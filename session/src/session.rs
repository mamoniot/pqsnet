use std::{
    collections::VecDeque, mem::MaybeUninit, ops::Range, ptr::copy_nonoverlapping, sync::{
        Arc, Condvar, Mutex, RwLock, atomic::{AtomicU64, AtomicUsize, Ordering},
    }, task::Waker,
};

use arrayvec::ArrayVec;
use bytes::{Bytes, buf::UninitSlice};
use smallvec::SmallVec;

use crate::{
    channel::{Channel, RecvDocData},
    congestion::CongestionControl,
    packet_builder::PacketBuilder,
    protocol::*,
    send::TransmissionQueue,
    stats::Stats,
    varint::*,
};

pub type DocNo = u64;
pub type SocketId = u32;

pub struct Session<R: Route>(pub Arc<SessionInner<R>>);

impl<R: Route> std::ops::Deref for Session<R> {
    type Target = Arc<SessionInner<R>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R: Route> Clone for Session<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct SessionInner<R: Route> {
    pub(crate) is_initiator: bool,
    pub(crate) last_recv_time: AtomicU64,
    pub(crate) mtu: u32,
    /// Document numbers may not be reused, otherwise severely delayed document segments could
    /// corrupt new documents.
    /// There is no way around this, segments which share a document number are indistinguishable.
    pub(crate) recv_total: AtomicUsize,
    pub(crate) recv_max: AtomicUsize,
    /// It is the sender's responsibility to correctly memory manage the receiver's `recv_table`.
    /// When a new document comes in, if the slot its doc no maps to is occupied by a doc with a
    /// lower doc no, the receiver will only replace it with the incoming doc if it is in a `Fin` or
    /// `FinAck` state. The previous doc will be finished and closed if it was not already, but new
    /// fin or close control packets will not be sent to the sender.
    pub(crate) recv_table: Vec<RecvDocEntry<R>>,

    pub(crate) send_bytes_total: AtomicU64,
    /// This is set to 0 if this session was abandoned.
    pub(crate) send_bytes_max: AtomicU64,
    pub(crate) send_total: AtomicUsize,
    pub(crate) send_doc_no: AtomicU64,
    pub(crate) send_wakers: Mutex<VecDeque<Waker>>,
    pub(crate) send_table: Vec<SendDocEntry<R>>,

    pub(crate) send_queue: Mutex<VecDeque<DocNo>>,
    pub(crate) transmissions: TransmissionQueue,

    pub(crate) open_sockets: RwLock<OpenSockets>,

    pub(crate) congestion_control: CongestionControl,
    pub(crate) stats: Stats,
    pub(crate) route: R,
}

pub(crate) struct OpenSockets {
    pub(crate) cur_idx: bool,
    pub(crate) sockets: ArrayVec<SocketData, 2>,
}

pub(crate) struct SocketData {
    /// Ack numbers must be added in sorted order from smallest to largest.
    pub(crate) acks: Mutex<Vec<u32>>,
    pub(crate) socket: Sock,
}

/// TODO: remove this.
pub struct Sock {
    pub local_id: u32,
    pub uid: u32,
}

impl Sock {
    pub fn encrypt_in_place(&self, buf: &mut [u8]) -> u32 {
        todo!()
    }
}

pub(crate) struct RecvDocEntry<R: Route> {
    pub(crate) lock: Mutex<RecvDocInner<R>>,
    pub(crate) condvar: Condvar,
}

pub(crate) struct RecvDocInner<R: Route> {
    pub(crate) doc_no: DocNo,
    pub(crate) doc: RecvDocState,
    pub(crate) channel: Option<ChannelState<R>>,
    // This may only be set to true once at the same time `channel` is set to `None` or when `doc`
    // is set to `Fin`.
    pub(crate) needs_send_control: bool,
}

#[derive(Default)]
pub(crate) enum RecvDocState {
    /// This state is reached when a new document is being received but the receiving thread has not
    /// yet fully initialized a `RecvDoc`. That thread will notify this slot's condvar when it is done.
    /// Threads which need to access a RecvDoc should wait on the condvar if they encounter this state.
    ///
    /// A reserved `RecvDocState` must only be overwritten by the thread which set it to reserved.
    RecvReserved,
    Recv(RecvDoc),
    /// These are awoken when we receive an ack for our doc fin frame or
    /// if the remote peer uses a document number that would use this slot.
    /// The remote peer will only reuse this document slot if it received
    /// our fin frame. We don't want a delayed ack to prevent receiving a
    /// valid document.
    Fin(SmallVec<[Waker; 1]>),
    #[default]
    FinAck,
}

pub(crate) struct RecvDoc {
    pub(crate) mem: DocMem,
    pub(crate) total_recv: usize,
    pub(crate) set_segs: Vec<usize>,
}

pub(crate) enum DocMem {
    Simple(Box<[MaybeUninit<u8>]>),
    ReplyBuf(Range<*mut u8>),
}

impl DocMem {
    pub fn len(&self) -> usize {
        match self {
            Self::Simple(m) => m.len(),
            Self::ReplyBuf(m) => m.end as usize - m.start as usize,
        }
    }

    pub fn write(&mut self, seg_off: usize, seg: &[u8]) {
        match self {
            Self::Simple(m) => {
                UninitSlice::uninit(&mut m[seg_off..seg_off + seg.len()]).copy_from_slice(seg);
            }
            Self::ReplyBuf(m) => {
                assert!(seg.len() < m.end as usize - m.start as usize, "document buffer overflow");
                unsafe {
                    copy_nonoverlapping(seg.as_ptr(), m.start, seg.len());
                }
            }
        }
    }
}

pub(crate) struct SendDocEntry<R: Route> {
    pub(crate) lock: Mutex<SendDocInner<R>>,
}

pub(crate) struct SendDocInner<R: Route> {
    pub(crate) doc_no: DocNo,
    pub(crate) doc: Option<SendDoc>,
    pub(crate) channel: Option<ChannelState<R>>,
    /// This slot in `send_table` cannot be reused for a different document until this document is
    /// finished and the request to close this document is acked.
    pub(crate) close_acked: bool,
    /// This may only be set to true once at the same time `channel` is set to `None`.
    pub(crate) needs_send_close: bool,
}

pub(crate) struct SendDoc {
    pub(crate) parent_no: DocNo,
    pub(crate) has_special_parent: bool,
    pub(crate) has_been_acked: bool,
    pub(crate) next_seg_off: usize,
    pub(crate) data: Bytes,
    /// These are awoken when we receive a doc fin frame.
    pub(crate) flush_wakers: SmallVec<[Waker; 1]>,
}

pub(crate) struct ChannelState<R: Route> {
    pub(crate) ref_count: usize,
    pub(crate) ready_wakers: SmallVec<[Waker; 1]>,
    pub(crate) ready_docs: SmallVec<[RecvDocData<R>; 1]>,
    /// TODO: Give this more capabilities. At least ensure that the protocol can handle extended
    /// capabilities.
    pub(crate) reply_buffer: ReplyState<R>,
}

#[derive(Default)]
pub enum ReplyState<R: Route> {
    Awaiting(Option<Range<*mut u8>>, Waker),
    Recv(usize, Channel<R>),
    #[default]
    None,
}

impl<R: Route> ReplyState<R> {
    /// If there is a reply buffer awaiting data, this function removes it and returns it.
    /// The reply state will still be awaiting data, but the reply buffer will be gone.
    pub fn try_incoming(&mut self) -> Option<Range<*mut u8>> {
        if let Self::Awaiting(ret, _) = self {
            ret.take()
        } else {
            None
        }
    }

    pub fn wake(self) {
        if let Self::Awaiting(_, w) = self {
            w.wake();
        }
    }
}

pub enum RecvError {
    Inauthentic,
    Invalid,
}

pub enum RouteError {
    RouteClosed,
    RouteBusy,
    RouteMtuExceeded,
    Other,
}

pub struct Work(pub(crate) WorkInner);

pub enum WorkInner {
    Send(PacketBuilder),
    SendOn(PacketBuilder, bool, u32),
}

/// TODO: change the name of this.
pub trait Route {
    fn send(&self, packet: &[u8]) -> Result<(), RouteError>;
}

impl<R: Route> Session<R> {
    pub fn get_last_recv_time(&self) -> f64 {
        bytemuck::cast(self.last_recv_time.load(Ordering::Relaxed))
    }

    pub fn send_lossy(&self) {
        todo!()
    }

    pub fn add_route(&self, route: R) -> bool {
        todo!()
    }

    fn recv_doc(&self, doc: &mut RecvDoc, seg_off: usize, seg: &[u8]) -> Result<bool, RecvError> {
        // TODO: check `first_incomplete_doc`, and also allow completed docs in the `recv_doc_table`.
        fn check_overlap(set_seg: &mut usize, set_bits: usize) -> usize {
            let pre_bits = *set_seg;
            *set_seg |= set_bits;

            let bits_set = !pre_bits & set_bits;
            bits_set.count_ones() as usize
        }

        let doc_len = doc.mem.len();

        if seg.is_empty() {
            return Ok(doc_len == 0);
        }
        let seg_end = seg_off + seg.len() - 1;
        if seg_end >= doc_len {
            return Err(RecvError::Invalid);
        }
        let seg_off_idx = seg_off / usize::BITS as usize;
        let seg_off_rem = seg_off % usize::BITS as usize;
        let seg_end_idx = seg_end / usize::BITS as usize;
        let seg_end_rem = seg_end % usize::BITS as usize;

        let seg_off_set = usize::MAX >> seg_off_rem;
        let seg_end_set = usize::MAX << (usize::BITS as usize - seg_end_rem - 1);

        let mut total_new_bytes = 0;
        if seg_off_idx == seg_end_idx {
            total_new_bytes += check_overlap(&mut doc.set_segs[seg_off_idx], seg_off_set & seg_end_set);
        } else {
            total_new_bytes += check_overlap(&mut doc.set_segs[seg_off_idx], seg_off_set);
            for i in seg_off_idx + 1..seg_end_idx - 1 {
                total_new_bytes += check_overlap(&mut doc.set_segs[i], usize::MAX);
            }
            total_new_bytes += check_overlap(&mut doc.set_segs[seg_end_idx], seg_end_set);
        }

        doc.total_recv += total_new_bytes;
        doc.mem.write(seg_off, seg);
        Ok(doc.total_recv == doc_len)
    }

    pub(crate) fn update_channel(&self, doc_no: DocNo, f: impl FnOnce(&mut ChannelState<R>)) {
        if (doc_no & 1 > 0) == self.is_initiator {
            // Document number is sending.
            let send_idx = ((doc_no >> 1) % self.send_table.len() as u64) as usize;
            let mut entry = self.send_table[send_idx].lock.lock().unwrap();
            if entry.doc_no == doc_no
                && let Some(channel) = &mut entry.channel
            {
                f(channel);
            }
        } else {
            // Document number is receiving.
            let recv_idx = ((doc_no >> 1) % self.recv_table.len() as u64) as usize;
            let mut entry = self.recv_table[recv_idx].lock.lock().unwrap();
            if entry.doc_no == doc_no
                && let Some(channel) = &mut entry.channel
            {
                f(channel);
            }
        }
    }

    pub(crate) fn recv(&self, packet: &mut [u8], route: R) -> Result<(), RecvError> {
        // TODO: Decrypt packet.

        let mut ack_eliciting = false;
        let mut i = 0;
        while i < packet.len() {
            let variant = packet[i];
            i += 1;
            match variant {
                VARIANT_NULL_TERMINATOR => break,
                VARIANT_SEG_MIN..=VARIANT_SEG_MAX => {
                    ack_eliciting = true;

                    let has_special_parent = variant & VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT > 0;
                    let has_doc_len = variant & VARIANT_SEG_FLAG_HAS_DOC_LEN > 0;
                    let is_single_seg = variant & VARIANT_SEG_FLAG_IS_SINGLE_SEG > 0;
                    let is_first_segment = variant & VARIANT_SEG_FLAG_IS_FIRST > 0;
                    // TODO: handle closing on segments.
                    let is_closed = variant & VARIANT_SEG_FLAG_IS_CLOSED > 0;
                    let variant_len = variant & VARIANT_SEG_LEN_MASK;
                    let mut doc_len = None;
                    let mut parent_no = None;
                    let mut seg_off = 0;

                    let doc_no = varu64_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    if has_doc_len {
                        doc_len = Some(varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?);
                    }
                    if has_special_parent || is_first_segment {
                        parent_no = Some(varu64_try_read(packet, &mut i).ok_or(RecvError::Invalid)?);
                    }
                    if !is_first_segment {
                        seg_off = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    }

                    let seg = if variant_len == VARIANT_SEG_IS_TERMINATOR {
                        let ret = &packet[i..];
                        i = packet.len();
                        ret
                    } else if variant_len == VARIANT_SEG_HAS_LEN {
                        let seg_len = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                        let seg_start = i;
                        i = i.saturating_add(seg_len);
                        packet.get(seg_start..i).ok_or(RecvError::Invalid)?
                    } else {
                        debug_assert_eq!(variant_len, VARIANT_SEG_HAS_TERMINATOR);
                        let seg_start = i;
                        i = packet.len();
                        let mut seg_end = packet.len() - 1;
                        loop {
                            if seg_start > seg_end {
                                return Err(RecvError::Invalid);
                            }
                            if packet[seg_end] == VARIANT_NULL_TERMINATOR {
                                break;
                            }
                            seg_end -= 1;
                        }
                        &packet[seg_start..seg_end]
                    };

                    if is_single_seg {
                        doc_len.get_or_insert(seg.len());
                    }


                    if (doc_no & 1 > 0) == self.is_initiator {
                        // Document number is sending. Segments cannot be received on sending docs.
                        return Err(RecvError::Invalid)
                    }
                    // Document number is receiving.
                    let recv_idx = ((doc_no >> 1) % self.recv_table.len() as u64) as usize;
                    let slot = &self.recv_table[recv_idx];
                    let mut entry = slot.lock.lock().unwrap();

                    if entry.doc_no == doc_no {
                        // The common case: adding to a pre-existing doc.
                        while let RecvDocState::RecvReserved = &entry.doc {
                            entry = slot.condvar.wait(entry).unwrap();
                        }
                        if let RecvDocState::Recv(doc) = &mut entry.doc {
                            // NOTE: we do not validate `doc_len` or `parent_no`. The values on
                            // the first recv segment are considered authoritative.
                            if self.recv_doc(doc, seg_off, seg)? {
                                // TODO: remove the doc, set it to `Fin` and schedule a `Fin`
                                // packet to be sent.
                            }
                        }
                        // Segments are ignored if the doc is in the `Fin` or `FinAck` state.
                    } else if entry.doc_no < doc_no {
                        // TODO: lockless single-segment document handling.
                        let Some(doc_len) = doc_len else {
                            // If first recv seg of a doc does not specify the document length then
                            // it is ignored. This can happen if this doc was reset, in which case
                            // the sender will be able to deduce that this segment was ignore
                            // despite being acked.
                            continue;
                        };

                        // Close and fin-ack any pre-existing document in this slot in preparation
                        // for the new doc.
                        if matches!(&entry.doc, RecvDocState::Recv(..)) {
                            // The sender must not use the recv slot of a document that is not
                            // finished. They must wait for us to send a fin control frame first.
                            return Err(RecvError::Invalid);
                        }

                        entry.doc_no = doc_no;
                        // Mark the doc as `FinAck`, kick out all wakers
                        if let RecvDocState::Fin(wakers) = std::mem::replace(&mut entry.doc, RecvDocState::RecvReserved) {
                            for waker in wakers {
                                waker.wake();
                            }
                        }
                        // TODO: channels are janky right now and should be fixed, ref_count set to
                        // 0 is cursed and could cause problems.
                        let closed_channel = entry.channel.replace(ChannelState {
                            ref_count: 0,
                            ready_wakers: SmallVec::new(),
                            ready_docs: SmallVec::new(),
                            reply_buffer: Default::default(),
                        });
                        // By specifying this slot, the sender is implicitly closing and fin-acking
                        // any pre-existing doc in this slot, so no control frame needs to be sent.
                        entry.needs_send_control = false;

                        // This doc slot is fully initialized and can be safely replaced with the
                        // new doc.

                        let mut mem = None;
                        let mut notify_unreserved = false;
                        if has_special_parent && let Some(parent_no) = parent_no {
                            // If this doc has a special parent we must look up that parent before allocating the doc.
                            // We must drop the lock to prevent deadlock when looking up a document's parent.
                            if parent_no >= doc_no {
                                // Parent docs must be older than child docs.
                                return Err(RecvError::Invalid);
                            }
                            notify_unreserved = true;
                            drop(entry);

                            // We cannot hold two locks into the send/recv tables at the same time.
                            // This is why we set the `RecvDocState` to reserved, so we can unlock.
                            self.update_channel(parent_no, |channel| {
                                mem = channel.reply_buffer.try_incoming().map(DocMem::ReplyBuf)
                            });

                            entry = slot.lock.lock().unwrap();
                        }
                        debug_assert!(matches!(&entry.doc, RecvDocState::RecvReserved));

                        let mut doc = RecvDoc {
                            mem: mem.unwrap_or_else(|| DocMem::Simple(Box::new_uninit_slice(doc_len))),
                            total_recv: 0,
                            set_segs: vec![0; doc_len.div_ceil(usize::BITS as usize)]
                        };
                        self.recv_doc(&mut doc, seg_off, seg);

                        entry.doc = RecvDocState::Recv(doc);
                        drop(entry);

                        // Now that the lock is dropped we can send notifications to any waiting threads/tasks.
                        if notify_unreserved {
                            slot.condvar.notify_all();
                        }
                        // TODO: eliminate this repeated waking pattern.
                        if let Some(channel) = closed_channel {
                            for waker in channel.ready_wakers {
                                waker.wake();
                            }
                            channel.reply_buffer.wake();
                        }
                    }
                }
                VARIANT_ACK_SINGLE | VARIANT_ACK_RUN => {}
                VARIANT_PADDING => {}
                _ => return Err(RecvError::Invalid),
            }
        }
        Ok(())
    }
}
