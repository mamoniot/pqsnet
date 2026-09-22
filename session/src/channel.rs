use std::{
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
};

use bytes::Bytes;
use smallvec::SmallVec;

use crate::{
    application_layer::Route,
    protocol::*,
    session::{DocNo, OpenChannel, RecvDocState, ReplyState, SendDoc, Session},
};

const FLAG_IS_CLOSED: u64 = 1u64.reverse_bits();
const FLAG_HAS_SPECIAL_PARENT: u64 = 2u64.reverse_bits();
const DOC_NO_MASK: u64 = u64::MAX >> 2;

pub struct Channel<R: Route> {
    pub(crate) session: Session<R>,
    doc_no_tagged: u64,
}

pub struct ChannelStatus {
    pub ref_count: usize,
    pub parent_is_flushed: bool,
    pub ready_recv_docs: usize,
}

pub enum RecvDocData<R: Route> {
    Doc(Box<[u8]>, Channel<R>),
    Datagram(Box<[u8]>),
}

pub enum Error {
    Closed,
    Abandoned,
}

pub enum SendError {
    Closed,
    Abandoned,
    TooLarge,
}

pub enum TrySendError {
    Full,
    Closed,
    Abandoned,
    TooLarge,
}

impl<R: Route> Channel<R> {
    /// This function assumes that the the channels internal state will be updated by the caller,
    /// especially `ref_count`.
    pub(crate) fn new(session: &Session<R>, doc_no: DocNo, has_special_parent: bool, is_closed: bool) -> Self {
        Self {
            session: session.clone(),
            doc_no_tagged: doc_no
                | (has_special_parent as u64 * FLAG_HAS_SPECIAL_PARENT)
                | (is_closed as u64 * FLAG_IS_CLOSED),
        }
    }
    /// We do not bother updating the channel in memory if the session is abandoned. The keep
    /// alive system is responsible for cleaning up the memory of abandoned sessions.
    fn check_basic(&self) -> Result<(), Error> {
        if self.session.send_bytes_max.load(Ordering::Relaxed) > 0 {
            if self.doc_no_tagged & FLAG_IS_CLOSED > 0 {
                Err(Error::Closed)
            } else {
                Ok(())
            }
        } else {
            Err(Error::Abandoned)
        }
    }

    pub fn parent_was_local(&self) -> bool {
        (self.doc_no_tagged & 1 > 0) == self.session.is_initiator
    }

    pub fn has_special_parent(&self) -> bool {
        self.doc_no_tagged & FLAG_HAS_SPECIAL_PARENT > 0
    }

    pub fn doc_no(&self) -> DocNo {
        self.doc_no_tagged & DOC_NO_MASK
    }

    pub async fn recv(&self) -> Result<RecvDocData<R>, Error> {
        RecvFuture { channel: self }.await
    }

    pub fn try_recv(&self) -> Result<Option<RecvDocData<R>>, Error> {
        self.check_basic()?;

        let mut ret = Err(Error::Closed);
        let doc_no = self.doc_no();
        self.session.update_channel(doc_no, |channel| {
            ret = Ok(None);
            if let Some(ready_doc) = channel.ready_docs.pop() {
                // This store must always be ordered before any new docs are received.
                // Otherwise the sender may see and act on the decremented `recv_bytes_total` before
                // the receiver has propagated the decremented `recv_bytes_total` to all cores.
                self.session
                    .recv_bytes_total
                    .fetch_sub(ready_doc.buf.len(), Ordering::SeqCst);
                self.session
                    .schedule_send_control(VARIANT_CONTROL_FIN, ready_doc.doc_no);

                ret = Ok(Some(RecvDocData::Doc(
                    ready_doc.buf,
                    Channel::new(
                        &self.session,
                        ready_doc.doc_no,
                        ready_doc.has_special_parent,
                        ready_doc.is_closed,
                    ),
                )));
            }
            // TODO: update `session.send_bytes_total`
        });
        ret
    }

    pub async fn send(&self, doc: Bytes) -> Result<Channel<R>, (SendError, Bytes)> {
        SendFuture { channel: self, doc: Some(doc), has_waited: false }.await
    }

    fn try_send_any(&self, doc: Bytes, f: impl FnOnce() -> ReplyState) -> Result<Channel<R>, (TrySendError, Bytes)> {
        let session = &self.session;
        // Verify and update sending limits.
        let send_total = session.send_total.fetch_add(1, Ordering::Relaxed);
        if send_total + 1 >= session.send_table.len() {
            // Since this decrement is not atomic, a race condition is created where documents can
            // be spurious blocked when they could be sent.
            // This is acceptable since such a situation is self-resolving. The caller will try
            // again if sending this document was necessary.
            session.send_total.fetch_sub(1, Ordering::Relaxed);
            return Err((TrySendError::Full, doc));
        }

        let send_bytes_max = session.send_bytes_max.load(Ordering::Relaxed);
        if send_bytes_max == 0 {
            return Err((TrySendError::Abandoned, doc));
        } else if doc.len() as u64 >= send_bytes_max {
            return Err((TrySendError::TooLarge, doc));
        }

        let send_bytes_total = session.send_bytes_total.fetch_add(doc.len() as u64, Ordering::Relaxed);
        if send_bytes_total + doc.len() as u64 >= send_bytes_max {
            // Same as before, these decrements create an inconsequencial race condition.
            session.send_bytes_total.fetch_sub(doc.len() as u64, Ordering::Relaxed);
            session.send_total.fetch_sub(1, Ordering::Relaxed);
            return Err((TrySendError::Full, doc));
        }

        let reply_buffer = f();

        // Find an unused `doc_no`.
        // This loop is naive and will hardlock without preceeding limit checks.
        loop {
            let doc_no = session.send_doc_no.fetch_add(2, Ordering::Relaxed);
            let send_idx = ((doc_no >> 1) % session.send_table.len() as u64) as usize;
            let mut entry = session.send_table[send_idx].lock.lock().unwrap();

            if entry.channel.is_some() || entry.doc.is_some() {
                continue;
            }

            // This is the only place that populates a send slot.
            entry.doc_no = doc_no;
            entry.doc = Some(SendDoc {
                parent_no: doc_no,
                data: doc,
                flush_wakers: SmallVec::new(),
                has_special_parent: self.has_special_parent(),
                has_been_acked: false,
                next_seg_off: 0,
            });
            entry.channel = Some(OpenChannel {
                ref_count: 1,
                ready_wakers: SmallVec::new(),
                ready_docs: SmallVec::new(),
                reply_buffer,
            });
            entry.needs_send_close = false;
            // A channel with a special parent cannot be created here.
            return Ok(Channel { session: session.clone(), doc_no_tagged: doc_no });
        }
    }
    pub fn try_send(&self, doc: Bytes) -> Result<Channel<R>, (TrySendError, Bytes)> {
        self.try_send_any(doc, Default::default)
    }

    pub async fn send_with_reply_buffer(
        &self,
        doc: Bytes,
        buffer: Pin<&mut [u8]>,
    ) -> Result<(usize, Channel<R>), SendError> {
        SendReplyFuture {
            channel: self,
            buffer,
            state: SendReplyState::Sending(Some(doc), false),
        }
        .await
    }

    /// Document number is sending.
    /// When flushing a sending doc, we only wake when we are sure the peer has received
    /// the full document.
    /// Document number is receiving.
    /// When flushing a send doc, we only wake when we are sure the peer knows
    /// we have received the full document, or the peer has rejected the doc.
    pub async fn flush_parent(&self) {
        FlushFuture { channel: self, has_waited: false }.await
    }

    /// Returns true when `flush_parent` would block.
    pub fn status(&self) -> Result<bool, Error> {
        self.check_basic()?;

        let doc_no = self.doc_no();
        if self.parent_was_local() {
            // Document number is sending.
            // When flushing a sending doc, we only wake when we are sure the peer has received
            // the full document, aka we receive a fin.
            let send_idx = ((doc_no >> 1) % self.session.send_table.len() as u64) as usize;
            let entry = self.session.send_table[send_idx].lock.lock().unwrap();

            if entry.doc_no == doc_no && entry.channel.is_some() {
                Ok(entry.doc.is_some())
            } else {
                Err(Error::Closed)
            }
        } else {
            // Document number is receiving.
            // When flushing a recv doc, we only wake when we are sure the peer knows
            // we have received the full document, aka we have received a fin-ack.
            let recv_idx = ((doc_no >> 1) % self.session.recv_table.len() as u64) as usize;
            let entry = self.session.recv_table[recv_idx].lock.lock().unwrap();
            if entry.doc_no == doc_no && entry.channel.is_some() {
                Ok(matches!(&entry.doc, RecvDocState::Finishing(_)))
            } else {
                Err(Error::Closed)
            }
        }
    }

    /// This function is the only place currently that closes a channel such that an explicit
    /// close must be sent.
    fn close_if_inner(&self, f: impl FnOnce(&mut OpenChannel) -> bool) -> Result<(), Error> {
        let doc_no = self.doc_no();
        let session = &self.session;

        let mut closed_channel = None;

        if (doc_no & 1 > 0) == session.is_initiator {
            // Document number is sending.
            let send_idx = ((doc_no >> 1) % session.send_table.len() as u64) as usize;
            let mut entry = session.send_table[send_idx].lock.lock().unwrap();
            if entry.doc_no == doc_no
                && let Some(channel) = &mut entry.channel
                && f(channel)
            {
                closed_channel = entry.channel.take();
                entry.needs_send_close = true;
            }
        } else {
            // Document number is receiving.
            let recv_idx = ((doc_no >> 1) % session.recv_table.len() as u64) as usize;
            let mut entry = session.recv_table[recv_idx].lock.lock().unwrap();
            if entry.doc_no == doc_no
                && let Some(channel) = &mut entry.channel
                && f(channel)
            {
                closed_channel = entry.channel.take();
                entry.needs_send_control = true;
            }
        }

        let ret = if closed_channel.is_some() {
            // TODO: This could be made more efficient and context aware.
            session.schedule_send_control(VARIANT_CONTROL_CLOSE, doc_no);
            Ok(())
        } else {
            Err(Error::Closed)
        };

        session.drop_closed_channel(closed_channel);

        ret
    }

    pub fn close(&self) -> Result<(), Error> {
        self.check_basic()?;

        self.close_if_inner(|_| true)
    }

    pub fn close_if(&self, f: impl FnOnce() -> bool) -> Result<(), Error> {
        self.check_basic()?;

        self.close_if_inner(|_| f())
    }
}

impl<R: Route> Clone for Channel<R> {
    fn clone(&self) -> Self {
        // Channel cloning is infallible even if the channel is closed.
        // Closed channels clone to more closed channels.
        // TODO: check if closed and set flag.
        self.session
            .update_channel(self.doc_no(), |channel| channel.ref_count += 1);
        Self {
            session: self.session.clone(),
            doc_no_tagged: self.doc_no_tagged,
        }
    }
}

impl<R: Route> Drop for Channel<R> {
    fn drop(&mut self) {
        // TODO: Make channels wait until all pending child docs are sent before closing.
        // So the channel should only close after we receive a fin or reject for every child doc.
        // Channels without pending child docs can be closed immediate, since recv docs cannot be
        // received without a channel for the application to await on. All recv docs would be
        // rejected in that case. There is an issue where recv docs do not check the status of
        // their parent until the doc is finished, so recv child docs that will be rejected can still
        // waste bandwidth. Can this be fixed?

        // Solution: The receiver may close a channel at any time, when the sender receives the
        // close control frame it implicitly also rejects all of that channel's immediate children.
        // The sender should behave as though a reject was received on all immediate children and
        // stop transmitting them.
        let _ = self.close_if_inner(|channel| {
            channel.ref_count -= 1;
            channel.ref_count == 0
        });
    }
}

pub(crate) struct SendFuture<'a, R: Route> {
    channel: &'a Channel<R>,
    doc: Option<Bytes>,
    has_waited: bool,
}

impl<'a, R: Route> Future for SendFuture<'a, R> {
    type Output = Result<Channel<R>, (SendError, Bytes)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.channel.try_send(self.doc.take().unwrap()) {
            Ok(channel) => {
                // Waiting sends are awoken one at a time, with each send being responsible for
                // waking up the next if there may be space for it.
                if self.has_waited {
                    let waker = self.channel.session.send_wakers.lock().unwrap().pop_front();
                    if let Some(w) = waker {
                        w.wake();
                    }
                }
                Poll::Ready(Ok(channel))
            }
            Err((TrySendError::Full, doc)) => {
                self.has_waited = true;
                self.doc = Some(doc);
                let waker = cx.waker().clone();
                self.channel.session.send_wakers.lock().unwrap().push_back(waker);
                Poll::Pending
            }
            Err((TrySendError::Closed, doc)) => Poll::Ready(Err((SendError::Closed, doc))),
            Err((TrySendError::Abandoned, doc)) => Poll::Ready(Err((SendError::Abandoned, doc))),
            Err((TrySendError::TooLarge, doc)) => Poll::Ready(Err((SendError::TooLarge, doc))),
        }
    }
}

pub(crate) struct FlushFuture<'a, R: Route> {
    channel: &'a Channel<R>,
    has_waited: bool,
}

impl<'a, R: Route> Future for FlushFuture<'a, R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.has_waited {
            self.has_waited = true;

            let session = &self.channel.session;
            let doc_no = self.channel.doc_no();
            if self.channel.parent_was_local() {
                // Document number is sending.
                // When flushing a send doc, we only wake when we are sure the peer has received
                // the full document.
                let send_idx = ((doc_no >> 1) % session.send_table.len() as u64) as usize;
                let mut entry = session.send_table[send_idx].lock.lock().unwrap();

                if entry.doc_no == doc_no
                    && entry.channel.is_some()
                    && let Some(doc) = &mut entry.doc
                {
                    doc.flush_wakers.push(cx.waker().clone());
                    return Poll::Pending;
                }
            } else {
                // Document number is receiving.
                // When flushing a recv doc, we only wake when we are sure the peer knows
                // we have received the full document, aka we have received a fin-ack.
                let recv_idx = ((doc_no >> 1) % session.recv_table.len() as u64) as usize;
                let mut entry = session.recv_table[recv_idx].lock.lock().unwrap();
                if entry.doc_no == doc_no
                    && entry.channel.is_some()
                    && let RecvDocState::Finishing(flush_wakers) = &mut entry.doc
                {
                    flush_wakers.0.push(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(())
    }
}

pub(crate) struct RecvFuture<'a, R: Route> {
    channel: &'a Channel<R>,
}

impl<'a, R: Route> Future for RecvFuture<'a, R> {
    type Output = Result<RecvDocData<R>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: There is a race condition where a document is finished, but it gets
        // closed before this future can wake up and take the finised document.
        self.channel.check_basic()?;

        let mut ret = Poll::Ready(Err(Error::Closed));
        self.channel.session.update_channel(self.channel.doc_no(), |channel| {
            if let Some(ready_doc) = channel.ready_docs.pop() {
                // TODO: Deduplicate this code.
                let session = &self.channel.session;
                session
                    .recv_bytes_total
                    .fetch_sub(ready_doc.buf.len(), Ordering::SeqCst);
                session.schedule_send_control(VARIANT_CONTROL_FIN, ready_doc.doc_no);

                ret = Poll::Ready(Ok(RecvDocData::Doc(
                    ready_doc.buf,
                    Channel::new(
                        session,
                        ready_doc.doc_no,
                        ready_doc.has_special_parent,
                        ready_doc.is_closed,
                    ),
                )));
            } else {
                channel.ready_wakers.push(cx.waker().clone());
                ret = Poll::Pending;
            }
        });
        ret
    }
}

pub(crate) struct SendReplyFuture<'a, R: Route> {
    channel: &'a Channel<R>,
    buffer: Pin<&'a mut [u8]>,
    state: SendReplyState<R>,
}

enum SendReplyState<R: Route> {
    Sending(Option<Bytes>, bool),
    /// This channel has special invariants so it must not be exposed to the application.
    ///
    /// Right now we allow this channel to be naturally dropped, but this is inefficient.
    Sent(Channel<R>),
}

impl<'a, R: Route> Future for SendReplyFuture<'a, R> {
    type Output = Result<(usize, Channel<R>), SendError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // NOTE: This code is rather sensitive to invariants related to data representation and handling.
        // It will need to be overhauled anyways when a more thorough application buffering API is implemented.
        // TODO: There is a race condition where a document is finished, but it gets
        // closed before this future can wake up and take the finised document.
        match &mut *self {
            Self {
                channel,
                buffer,
                state: SendReplyState::Sending(doc, has_waited),
            } => {
                match channel.try_send_any(doc.take().unwrap(), || {
                    ReplyState::Awaiting(Some(buffer.as_mut_ptr_range()), cx.waker().clone())
                }) {
                    Ok(reply_channel) => {
                        if *has_waited {
                            let waker = channel.session.send_wakers.lock().unwrap().pop_front();
                            if let Some(w) = waker {
                                w.wake();
                            }
                        }
                        self.state = SendReplyState::Sent(reply_channel);
                        Poll::Pending
                    }
                    Err((TrySendError::Full, res_doc)) => {
                        *has_waited = true;
                        *doc = Some(res_doc);
                        let waker = cx.waker().clone();
                        channel.session.send_wakers.lock().unwrap().push_back(waker);
                        Poll::Pending
                    }
                    Err((TrySendError::Closed, _)) => Poll::Ready(Err(SendError::Closed)),
                    Err((TrySendError::Abandoned, _)) => Poll::Ready(Err(SendError::Abandoned)),
                    Err((TrySendError::TooLarge, _)) => Poll::Ready(Err(SendError::TooLarge)),
                }
            }
            Self {
                state: SendReplyState::Sent(reply_channel),
                channel: parent_channel,
                ..
            } => {
                let mut ret = Poll::Ready(Err(SendError::Closed));
                reply_channel.session.update_channel(reply_channel.doc_no(), |channel| {
                    // TODO: Analyze this section for errors.
                    match std::mem::take(&mut channel.reply_buffer) {
                        ReplyState::Awaiting(buffer, _) => {
                            // This can only occur due to a spurious wake up.
                            channel.reply_buffer = ReplyState::Awaiting(buffer, cx.waker().clone());
                            ret = Poll::Pending;
                        }
                        ReplyState::Recv(len, channel) => {
                            ret = Poll::Ready(Ok((
                                len,
                                Channel::new(
                                    &parent_channel.session,
                                    channel.doc_no,
                                    channel.has_special_parent,
                                    channel.is_closed,
                                ),
                            )));
                        }
                        ReplyState::None => {}
                    }
                });
                ret
            }
        }
    }
}
