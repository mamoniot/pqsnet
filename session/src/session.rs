use std::{
    collections::VecDeque,
    mem::MaybeUninit,
    ops::Range,
    ptr::copy_nonoverlapping,
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::Waker,
};

use arrayvec::ArrayVec;
use bytes::{Bytes, buf::UninitSlice};
use smallvec::SmallVec;

use crate::{
    application_layer::Route, congestion::CongestionControl, packet_builder::PacketBuilder, protocol::*,
    send::TransmissionQueue, stats::Stats,
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
    /// We explicitly track the total number of bytes we are receiving. The number of docs being
    /// received is tracked implicitly by the length of `recv_table`.
    ///
    pub(crate) recv_bytes_total: AtomicUsize,
    /// This number can only increase. To "decrease" the recv bytes max, a doc is finished with a
    /// fin-drain, and `recv_bytes_total` is not decreased by the full length of the doc.
    pub(crate) recv_bytes_max: AtomicUsize,
    /// It is the sender's responsibility to correctly memory manage the receiver's `recv_table`.
    /// When a new document comes in, if the slot its doc no maps to is occupied by a doc with a
    /// lower doc no, the receiver will only replace it with the incoming doc if it is in a `Fin` or
    /// `FinAck` state. The previous doc will be finished and closed if it was not already, but new
    /// fin or close control packets will not be sent to the sender.
    pub(crate) recv_table: Vec<RecvDocEntry>,

    pub(crate) send_bytes_total: AtomicU64,
    /// This is set to 0 if this session was abandoned.
    pub(crate) send_bytes_max: AtomicU64,
    pub(crate) send_total: AtomicUsize,
    pub(crate) send_doc_no: AtomicU64,
    pub(crate) send_wakers: Mutex<VecDeque<Waker>>,
    pub(crate) send_table: Vec<SendDocEntry>,

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

pub(crate) struct RecvDocEntry {
    pub(crate) lock: Mutex<RecvDocInner>,
    pub(crate) condvar: Condvar,
}

pub(crate) struct UnreleasedChannel {
    pub(crate) doc_no: DocNo,
    pub(crate) has_special_parent: bool,
    pub(crate) is_closed: bool,
}

pub(crate) struct UnfinishedRecvDoc {
    pub(crate) buf: Box<[u8]>,
    pub(crate) doc_no: DocNo,
    pub(crate) has_special_parent: bool,
    pub(crate) is_closed: bool,
}

#[derive(Default)]
pub(crate) enum ReplyState {
    /// This waker is waiting for this channel to recv a new doc into this given pointer range or
    /// it is waiting for this channel to close.
    Awaiting(Option<Range<*mut u8>>, Waker),
    Recv(usize, UnreleasedChannel),
    #[default]
    None,
}

impl ReplyState {
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

/// Since this struct can own a `Channel`, it must not be dropped while a lock is held.
pub(crate) struct OpenChannel {
    /// If this is a channel for a recv doc, it will be initialized to `0`. This means that the app
    /// layer has not yet been passed a channel object because the recv doc is not completed or has
    /// not yet been received by its parent channel.
    pub(crate) ref_count: usize,
    /// These wakers are waiting for this channel to recv a new doc in `ready_docs` or
    /// they are waiting for this channel to close.
    pub(crate) ready_wakers: SmallVec<[Waker; 1]>,
    pub(crate) ready_docs: SmallVec<[UnfinishedRecvDoc; 1]>,
    /// TODO: Give this more capabilities. At least ensure that the protocol can handle extended
    /// capabilities.
    pub(crate) reply_buffer: ReplyState,
}

pub(crate) struct RecvDocInner {
    pub(crate) doc_no: DocNo,
    pub(crate) doc: RecvDocState,
    /// The channel of a recv slot can be in one of two states: open or closed. When a channel is
    /// open, it can be closed locally or remotely at any time. If it is closed remotely, the local
    /// channel will be open for a short time until an explicit or implicit close is received.
    /// Implicit closes are when a new, valid doc is received and claims this recv slot. The remote
    /// peer may only do this if it has closed the previous channel in this recv slot.
    ///
    /// We choose to represent the open state as `Some(..)` and the closed state as `None`.
    pub(crate) channel: Option<OpenChannel>,
    /// Each orphan "owns" a slot in the recv table. If this orphan is dropped because an open
    /// parent was not received, that slot must be freed and a fin-parent-closed for the orphan doc
    /// no must be sent.
    ///
    /// TODO: We need a rule to handle peers who incorrectly send us permanently orphaned documents.
    pub(crate) adoptable_orphans: SmallVec<[UnfinishedRecvDoc; 1]>,
    pub(crate) orphans_expected_parent_no: Option<DocNo>,
    /// This may only be set to true once at the same time `channel` is set to `None` or when `doc`
    /// is set to `Fin`.
    pub(crate) needs_send_control: bool,
}

#[derive(Default)]
pub struct Flushers(pub(crate) SmallVec<[Waker; 1]>);

impl Drop for Flushers {
    fn drop(&mut self) {
        while let Some(waker) = self.0.pop() {
            waker.wake();
        }
    }
}

#[derive(Default)]
pub(crate) enum RecvDocState {
    /// This state is reached when a new document is being received but the receiving thread has not
    /// yet fully initialized a `RecvDoc`. That thread will notify this slot's condvar when it is
    /// done. Threads which need to access the RecvDoc should wait on the condvar if they encounter
    /// this state. This state must be considered an "active" state.
    ///
    /// A reserved `RecvDocState` must only be overwritten by the thread which set it to reserved.
    ActiveReserved,
    Active(RecvDoc),
    /// This document has been completed and a fin will eventually be sent, though
    /// that may take a while if this doc has an unknown parent (aka is an orphan).
    /// This state will transition to `FinAck` when our fin is acked.
    ///
    /// A misbehaving peer may successfully insert a new recv doc in this slot while the current
    /// doc is not yet finished. This requires that this doc's channel is closed.
    /// This implementation is structured to tolerate such misbehavior.
    ///
    /// While in this state a channel may be created and passed to the app layer, this channel
    /// may then attempt to "flush" this doc by adding a waker to this state.
    /// These wakers are awoken when our fin is acked, or if the remote peer uses a
    /// document number that would use this slot (this is considered an implicit ack).
    /// We don't want a delayed ack to prevent receiving a valid document.
    /// The remote peer must only reuse this document slot after it receives our fin.
    Finishing(Flushers),
    FinAck,
    #[default]
    FinParentClose,
}

impl RecvDocState {
    pub fn slot_is_fin(&self) -> bool {
        matches!(self, RecvDocState::Finishing(..) | RecvDocState::FinAck)
    }
}

pub(crate) struct RecvDoc {
    pub(crate) has_special_parent: bool,
    pub(crate) parent_no: Option<DocNo>,
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
                assert!(
                    seg.len() < m.end as usize - m.start as usize,
                    "document buffer overflow"
                );
                unsafe {
                    copy_nonoverlapping(seg.as_ptr(), m.start, seg.len());
                }
            }
        }
    }
}

pub(crate) struct SendDocEntry {
    pub(crate) lock: Mutex<SendDocInner>,
}

pub(crate) struct SendDocInner {
    pub(crate) doc_no: DocNo,
    /// This may only be set to true once at the same time `channel` is set to `Close`.
    pub(crate) needs_send_close: bool,
    /// Sending docs can only have two states, active and free, so `Some(..)` is the active state
    /// and `None` is the free state.
    pub(crate) doc: Option<SendDoc>,
    /// The channel of a recv slot can be in one of two states: open or closed. When a channel is
    /// open, it can be closed locally or remotely at any time. If it is closed remotely, the local
    /// channel will be open for a short time until an explicit close is received. There is no way
    /// for the remote peer to send an implicit close. The app layer determines if and when a local
    /// close occurs. Local closes start as explicit but can become implicit if a sending doc claims
    /// this send slot.
    ///
    /// We choose to represent the open state as `Some(..)` and the closed state as `None`.
    pub(crate) channel: Option<OpenChannel>,
}

/// It is recommended to not drop this while holding a lock to reduce contention from wakers.
pub(crate) struct SendDoc {
    pub(crate) parent_no: DocNo,
    pub(crate) has_special_parent: bool,
    pub(crate) has_been_acked: bool,
    pub(crate) next_seg_off: usize,
    pub(crate) data: Bytes,
    /// These wakers are waiting for a fin on this doc, which will also drop this `SendDoc`.
    /// Right now they are only awoken on drop.
    pub(crate) flush_wakers: SmallVec<[Waker; 1]>,
}

impl Drop for SendDoc {
    fn drop(&mut self) {
        while let Some(waker) = self.flush_wakers.pop() {
            waker.wake();
        }
    }
}

pub enum RecvError {
    Inauthentic,
    Invalid,
}

pub struct Work(pub(crate) WorkInner);

pub enum WorkInner {
    Send(PacketBuilder),
    SendOn(PacketBuilder, bool, u32),
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

    pub(crate) fn update_channel(&self, doc_no: DocNo, f: impl FnOnce(&mut OpenChannel)) {
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

    pub(crate) fn drop_unfinished_recv_doc(&self, doc_no: DocNo, doc_len: usize) {
        let mut stack: SmallVec<[(DocNo, usize); 4]> = SmallVec::new();
        stack.push((doc_no, doc_len));

        while let Some((doc_no, doc_len)) = stack.pop() {
            // This store must always be ordered before any new docs are received.
            // Otherwise the sender may see and act on the decremented `recv_bytes_total` before
            // the receiver has propagated the decremented `recv_bytes_total` to all cores.
            self.recv_bytes_total.fetch_sub(doc_len, Ordering::SeqCst);
            // TODO: detect when a close can be implicit so that the explicit close can be canceled.
            self.schedule_send_control(VARIANT_CONTROL_FIN_PARENT_CLOSED, doc_no);

            let mut closed_channel = None;

            // Document number is receiving.
            let recv_idx = ((doc_no >> 1) % self.recv_table.len() as u64) as usize;
            let mut entry = self.recv_table[recv_idx].lock.lock().unwrap();
            if entry.doc_no == doc_no {
                debug_assert!(entry.doc.slot_is_fin());
                entry.doc = RecvDocState::FinParentClose;
                closed_channel = entry.channel.take();
                entry.needs_send_control = true;
            }
            drop(entry);

            if let Some(mut channel) = closed_channel {
                while let Some(unfinished_recv_doc) = channel.ready_docs.pop() {
                    stack.push((unfinished_recv_doc.doc_no, unfinished_recv_doc.buf.len()));
                }
                drop(channel);
            }
        }
    }

    pub(crate) fn drop_closed_channel(&self, channel: Option<OpenChannel>) {
        if let Some(mut channel) = channel {
            while let Some(unfinished_docs) = channel.ready_docs.pop() {
                self.drop_unfinished_recv_doc(unfinished_docs.doc_no, unfinished_docs.buf.len());
            }
            while let Some(waker) = channel.ready_wakers.pop() {
                waker.wake();
            }
            if let ReplyState::Awaiting(_, waker) = std::mem::take(&mut channel.reply_buffer) {
                waker.wake();
            }
        }
    }

    pub(crate) fn abandon(&self) {
        self.send_bytes_max.store(0, Ordering::Relaxed);
        todo!();
    }

    pub(crate) fn schedule_send_control(&self, variant: u8, doc_no: DocNo) {
        // NOTE: This will need a separate path for open docs and fin-close docs.
        todo!()
    }
}
