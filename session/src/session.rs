use std::{
    cell::UnsafeCell, collections::{BTreeMap, BTreeSet, HashMap}, ptr::NonNull, sync::{
        Arc, Mutex, RwLock, atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
    }, time::Instant,
};

use bytes::{Bytes, BytesMut};
use dashmap::{DashMap, Entry, OccupiedEntry};
use tinyvec::TinyVec;

use crate::{protocol::*, send_lossless::TransmissionQueue, varint::*};

pub type DocNo = usize;
pub type SocketId = u32;

pub struct Payload {
    ref_count: AtomicUsize,
    mem: [u8],
}


#[derive(Default)]
pub struct RecvDoc {
    parent_no: usize,
    /// This `Vec` may only increase in length.
    data: UnsafeCell<Vec<u8>>,
    /// TODO: This field is redundant, remove it.
    total_len: usize,
    variant: u8,
    total_recv: AtomicUsize,
    first_unacked_seg_no: AtomicUsize,
    /// This `Vec` may only increase in length.
    set_segs: Vec<AtomicUsize>,
}

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
    last_recv_time: AtomicU64,
    pub(crate) plpmtu: u32,
    pub(crate) doc_counter: AtomicUsize,

    pub(crate) nagle_payload: Mutex<Vec<u8>>,
    /// Document numbers may not be reused, otherwise severely delayed document segments could
    /// corrupt new documents.
    /// There is no way around this, segments which share a document number are indistinguishable.
    pub(crate) recv_doc_table: DashMap<DocNo, RecvDocState>,
    pub(crate) transmissions: TransmissionQueue,
    pub(crate) congestion_control: (),
    pub(crate) stats: (),
    pub(crate) route: R,
}

pub struct DocSender<R: Route> {
    pub(crate) session: Session<R>,
    pub(crate) parent_no: usize,
}

pub struct DocReceiver<R: Route> {
    pub(crate) session: Session<R>,
    pub(crate) parent_no: usize,
}

pub enum RecvDocState {
    Active(RecvDoc),
    Finished,
    Closed { last_message_id: u64 },
}

pub enum RecvData<R: Route> {
    LossyDoc(Vec<u8>),
    SyncDoc(Vec<u8>),
    SyncDocRecv(Vec<u8>, DocReceiver<R>),
    SyncDocSend(Vec<u8>, DocSender<R>),
}
impl<R: Route> Default for RecvData<R> {
    fn default() -> Self {
        Self::LossyDoc(Vec::new())
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

pub struct Work(WorkInner);

pub enum WorkInner {
    TrySendDoc(DocNo),
    TryRetransmit(RetransmitWork),
}

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

    pub fn add_route(&self, route: R) -> Result<(), Error> {
        todo!()
    }

    fn recv_doc(&self, doc_no: usize, seg_no: usize, seg: &[u8]) -> Result<Option<RecvData<R>>, RecvError> {
        // TODO: check `first_incomplete_doc`, and also allow completed docs in the `recv_doc_table`.
        fn check_overlap(set_seg: &AtomicUsize, set_bits: usize) -> usize {
            let pre_bits = set_seg.fetch_or(set_bits, Ordering::SeqCst);

            let bits_set = !pre_bits & set_bits;
            bits_set.count_ones() as usize
        }

        if seg.is_empty() {
            if let Some(state) = self.recv_doc_table.get(&doc_no) {
                if let RecvDocState::Active(doc) = state.value() {
                    doc.first_unacked_seg_no.fetch_min(seg_no, Ordering::SeqCst);
                }
            }
            return Ok(None);
        }

        let seg_end = seg_no + seg.len() - 1;
        let seg_no_idx = seg_no / usize::BITS as usize;
        let seg_end_idx = seg_end / usize::BITS as usize;
        let seg_no_rem = seg_no % usize::BITS as usize;
        let seg_end_rem = seg_end % usize::BITS as usize;

        let seg_no_set = usize::MAX >> seg_no_rem;
        let seg_end_set = usize::MAX << (usize::BITS as usize - seg_end_rem - 1);

        loop {
            let entry = self.recv_doc_table.get(&doc_no);
            if let Some(RecvDocState::Active(doc)) = entry.map(|s| s.value()) {
                // It is safe to read the length of `data` since it is only written to when the
                // write lock is held.
                let data_len = unsafe { doc.data.get().as_ref_unchecked().len() };

                if seg_end < data_len {
                    let mut total_new_bytes = 0;
                    if seg_no_idx == seg_end_idx {
                        total_new_bytes += check_overlap(&doc.set_segs[seg_no_idx], seg_no_set & seg_end_set);
                    } else {
                        total_new_bytes += check_overlap(&doc.set_segs[seg_no_idx], seg_no_set);
                        for i in seg_no_idx + 1..seg_end_idx - 1 {
                            total_new_bytes += check_overlap(&doc.set_segs[i], usize::MAX);
                        }
                        total_new_bytes += check_overlap(&doc.set_segs[seg_end_idx], seg_end_set);
                    }
                    doc.first_unacked_seg_no.fetch_min(seg_no, Ordering::SeqCst);

                    if total_new_bytes == seg.len() {
                        unsafe {
                            let data = doc.data.get().as_mut_unchecked();
                            data[seg_no..=seg_end].copy_from_slice(seg);
                        }
                        let total_recv = doc.total_recv.fetch_add(total_new_bytes, Ordering::SeqCst);
                        if doc.total_len > 0 && total_recv == doc.total_len {
                            drop(entry);
                            if let Some((_, doc)) = self.recv_doc_table.remove(&doc_no) {
                                return Some(doc.data.into_inner());
                            }
                        }
                    } else if total_new_bytes > 0 {
                        drop(doc);
                        // Anything could change since the lock was dropped, recheck everything.
                        // This is especially important if our peer mistakenly reuses a doc number.
                        if let Entry::Occupied(mut entry) = self.recv_doc_table.entry(doc_no) {
                            let doc = entry.get_mut();
                            if let Some(segment) = doc.data.get_mut().get_mut(seg_no..=seg_end) {
                                segment.copy_from_slice(seg);
                                let total_recv = doc.total_recv.fetch_add(total_new_bytes, Ordering::SeqCst);
                                return if doc.total_len > 0 && total_recv == doc.total_len {
                                    Some(entry.remove().data.into_inner())
                                } else {
                                    None
                                };
                            }
                        }
                        /*
                        This line is only reachable if the remote peer reuses a document number
                        or sends some other corrupt data. This would likely cause this entire
                        document to be leaked, which is why the remote peer must not reuse a
                        document number.
                        */
                    }
                    return None;
                }
            }
            drop(entry);

            let mut doc = self.recv_doc_table.entry(doc_no).or_default();
            if doc.total_len > 0 && seg_end >= doc.total_len {
                // The remote peer has sent us corrupt data that would overflow the expected
                // document length.
                return None;
            }

            doc.set_segs.resize_with(seg_end_idx + 1, Default::default);
            let data = doc.data.get_mut();
            // TODO: resize with uninitialized memory.
            data.resize(seg_end + 1, 0);
        }
    }

    fn extract_doc(
        &self,
        doc_no: usize,
        parent_no: usize,
        variant: u8,
        data: Vec<u8>,
    ) -> Result<Option<RecvData<R>>, RecvError> {
        // TODO: Better delineate flags.
        let ret = if variant == VARIANT_DOC_HEAD_RECV {
            let receiver = DocReceiver { session: self.clone(), parent_no: doc_no };
            RecvData::SyncDocRecv(data, receiver)
        } else if variant == VARIANT_DOC_HEAD_SEND {
            let sender = DocSender { session: self.clone(), parent_no: doc_no };
            RecvData::SyncDocSend(data, sender)
        } else {
            RecvData::SyncDoc(data)
        };

        // TODO: check parent doc.

        Ok(Some(ret))
    }

    fn finish_recv_doc(
        &self,
        doc_no: usize,
        mut entry: OccupiedEntry<usize, RecvDocState>,
    ) -> Result<Option<RecvData<R>>, RecvError> {
        let mut new_state = RecvDocState::Finished;
        std::mem::swap(&mut new_state, entry.get_mut());
        drop(entry);
        if let RecvDocState::Active(doc) = new_state {
            self.extract_doc(doc_no, doc.parent_no, doc.variant, doc.data.into_inner())
        } else {
            debug_assert!(false, "unreachable");
            Err(RecvError::Invalid)
        }
    }

    fn recv_doc_header(
        &self,
        doc_no: usize,
        parent_no: usize,
        doc_len: usize,
        variant: u8,
    ) -> Result<Option<RecvData<R>>, RecvError> {
        let doc_seg_len = doc_len.div_ceil(usize::BITS as usize);

        match self.recv_doc_table.entry(doc_no) {
            Entry::Occupied(mut entry) => {
                if let RecvDocState::Active(doc) = entry.get_mut() {
                    if doc.total_len == 0 {
                        doc.set_segs.resize_with(doc_seg_len, Default::default);
                        let data = doc.data.get_mut();
                        // TODO: resize with uninitialized memory.
                        data.resize(doc_len, 0);
                        doc.total_len = doc_len;
                        doc.variant = variant;
                        if doc.total_recv.load(Ordering::SeqCst) >= doc.total_len {
                            return self.finish_recv_doc(doc_no, entry);
                        }
                    }
                }
                Ok(None)
            }
            Entry::Vacant(entry) => {
                if doc_len > 0 {
                    let data = UnsafeCell::new(vec![0; doc_len]);
                    let mut set_segs = Vec::with_capacity(doc_seg_len);
                    set_segs.resize_with(doc_seg_len, Default::default);
                    entry.insert(RecvDocState::Active(RecvDoc {
                        total_len: doc_len,
                        data,
                        set_segs,
                        variant,
                        parent_no,
                        ..Default::default()
                    }));

                    Ok(None)
                } else {
                    entry.insert(RecvDocState::Finished);
                    self.extract_doc(doc_no, parent_no, variant, Vec::new())
                }
            }
        }
    }

    pub async fn recv(&self, packet: &mut [u8], route: R) -> Result<TinyVec<[RecvData<R>; 1]>, RecvError> {
        // TODO: Decrypt packet.
        let mut ret = TinyVec::new();

        let mut i = 0;
        while i < packet.len() {
            let variant = packet[i];
            i += 1;
            match variant {
                VARIANT_PADDING => {}
                VARIANT_NULL_TERMINATOR => break,
                // VARIANT_DOC_HEAD | VARIANT_DOC_HEAD_RECV | VARIANT_DOC_HEAD_SEND => {
                //     let doc_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                //     let parent_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                //     let doc_len = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                //     let res = self.recv_doc_header(doc_no, parent_no, doc_len, variant)?;
                //     if let Some(res) = res {
                //         ret.push(res);
                //     }
                // }
                VARIANT_SEGMENT..VARIANT_SEGMENT_MAX => {
                    let close_send = variant & VARIANT_SEGMENT_FLAG_CLOSE_SEND > 0;
                    let close_recv = variant & VARIANT_SEGMENT_FLAG_CLOSE_RECV > 0;
                    let base_variant = variant & VARIANT_SEGMENT_BASE_MASK;

                    let doc_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let seg_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let seg_len = if variant == VARIANT_DOC_SEG_TERMINATOR {
                        packet.len() - i
                    } else {
                        varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?
                    };
                    let start = i;
                    i += seg_len;
                    if i > packet.len() {
                        return Err(RecvError::Invalid);
                    }
                    let res = self.recv_doc(doc_no, seg_no, &packet[start..i])?;
                    if let Some(res) = res {
                        ret.push(res);
                    }
                }
                _ => return Err(RecvError::Invalid),
            }
        }
        Ok(ret)
    }

    fn send_all(&self, now: f64) {

    }

    fn drive_transmission(&self, now: f64) -> Option<f64> {
        let plpmtu = self.plpmtu as usize;
        // let mut nagle_payload = self.nagle_payload.lock().unwrap();
        // nagle_payload.reserve(plpmtu);

        // TODO: don't bother running this code if there is not data to send
        if let Some(next_wake) = self.congestion_control.may_transmit(now, plpmtu) {
            return Some(next_wake);
        }
        let rto = self.get_last_recv_time() - self.stats.retransmission_time();

        for sent_payload in self.payload_table.iter() {
            if sent_payload.sent_at >= rto {
                continue;
            }

            let mut idx_mem = 0;
            let mut payload_mem = Vec::new();
            let payload = if plpmtu.wrapping_sub(sent_payload.payload_len) <= MIN_DATA_APPEND_LEN {
                payload_mem.reserve(plpmtu);
                &mut payload_mem
            } else {
                &mut nagle_payload
            };

            for frame in &sent_payload.frames {
                let mut not_overflown = true;
                match frame {
                    SentFrame::METADATA { variant, doc_no, parent_no, data_len } => {
                        let frame_start = payload.len();
                        payload.push(*variant);
                        self.varusize_write_or_send(payload, plpmtu, *doc_no);
                        not_overflown &= varusize_write(payload, plpmtu, *parent_no);
                        not_overflown &= varusize_write(payload, plpmtu, *data_len);
                        if !not_overflown {
                            self.pad_and_send_packet(payload, frame_start)
                        }
                    }
                    SentFrame::SEGMENT { doc_no, seg_no, data } => {
                        payload.push(VARIANT_SEGMENT);
                        not_overflown &= varusize_write(payload, plpmtu, *doc_no);
                        not_overflown &= varusize_write(payload, plpmtu, *seg_no);
                            varusize_write_segment(payload, plpmtu, &data[..]);
                    }
                }
            }
        }

        macro_rules! pad_and_send {
            ($vi: expr) => {
                if let Some(seg) = packet.get_mut($vi..) {
                    seg.fill(VARIANT_NULL_TERMINATOR);
                }
                // TODO: Encryption.
                self.route.send(&packet);
                i = 0;
            };
        }

        // TODO: Eliminate this iteration, only some documents need to be visited.
        for doc in self.recv_doc_table.iter() {
            let first_unacked_seg_no = doc.first_unacked_seg_no.load(Ordering::SeqCst);
            let mut has_header = first_unacked_seg_no & 1 > 0;
            let mut j = first_unacked_seg_no >> 1;

            while has_header {
                // NOTE: This will hardlock if the plpmtu is too small.
                debug_assert!(packet.len() >= 8 * 3);
                packet[i] = doc.variant;
                let vi = i;
                i += 1;

                if !varusize_write(&mut packet, &mut i, *doc.key()) {
                    pad_and_send!(vi);
                }
                if !varusize_write(&mut packet, &mut i, doc.parent_no) {
                    pad_and_send!(vi);
                }
                if !varusize_write(&mut packet, &mut i, doc.data.len()) {
                    pad_and_send!(vi);
                }
                has_header = false;
            }

            while j < doc.data.len() {
                if i + MIN_FRAME_APPEND_LEN > plpmtu {
                    pad_and_send!(i);
                }

                packet[i] = VARIANT_DOC_SEG;
                let vi = i;
                i += 1;

                if !varusize_write(&mut packet, &mut i, *doc.key()) {
                    pad_and_send!(vi);
                }
                if !varusize_write(&mut packet, &mut i, j) {
                    pad_and_send!(vi);
                }
                // TODO: Support long segments.
                if !varusize_write_segment(&mut packet, &mut i, &doc.data, &mut j) {
                    pad_and_send!(vi);
                }
            }
        }
    }
}

pub enum Error {
    Abandoned,
    Closed,
}

pub enum TryError {
    Abandoned,
    Closed,
    NoData,
}

pub enum RecvIntoOk<R: Route> {
    LossyDoc,
    SyncDoc,
    SyncDocRecv(DocReceiver<R>),
    SyncDocSend(DocSender<R>),
}

impl<R: Route> DocReceiver<R> {
    pub async fn recv(&self) -> Result<RecvData<R>, Error> {
        todo!()
    }

    pub fn try_recv(&self) -> Result<RecvData<R>, TryError> {
        todo!()
    }

    pub async fn recv_into(&self, dest: &mut [u8]) -> Result<RecvIntoOk<R>, Error> {
        todo!()
    }

    pub fn try_recv_into(&self, dest: &mut [u8]) -> Result<RecvIntoOk<R>, TryError> {
        todo!()
    }
}

impl<R: Route> DocSender<R> {
    pub async fn flush(&self) -> Result<(), Error> {
        todo!()
    }

    pub fn send_bytes(&self, bytes: Bytes) -> Result<(), Error> {
        // TODO: Reuse document numbers.
        let doc_no = self.session.doc_counter.fetch_add(2, Ordering::Relaxed);

        let mut set_segs = Vec::new();
        set_segs.resize_with(bytes.len(), Default::default);
        let doc = SendDoc {
            data: bytes,
            variant: VARIANT_DOC_HEAD,
            set_segs,
            total_acked: Default::default(),
            first_unacked_seg_no: Default::default(),
        };

        self.session.send_doc_table.insert(doc_no, doc);

        Ok(())
    }

    pub fn send_bytes_with_receiver(&self, bytes: Bytes) -> Result<DocSender<R>, Error> {
        todo!()
    }

    pub fn send_bytes_with_sender(&self, bytes: Bytes) -> Result<DocReceiver<R>, Error> {
        todo!()
    }
}
