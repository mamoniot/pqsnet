use std::{cell::UnsafeCell, io, mem::MaybeUninit, sync::{Arc, Mutex, RwLock, atomic::{AtomicUsize, Ordering}}};

use bytes::{Buf, BufMut, Bytes};
use dashmap::{DashMap, Entry, OccupiedEntry};
use smallvec::SmallVec;

use crate::{protocol::*, varu64::*};

pub struct SendPacketData {
    /// TODO: improve efficiency by reusing buffers.
    pub(crate) packet: Box<[u8]>,
}

pub struct RecvPacketData {
    pub(crate) packet: Box<[u8]>,
}

pub struct SendDoc {
    /// This field may only be accessed while the session's `send_atom` is locked.
    pub(crate) last_packet_no: UnsafeCell<u64>,
}


#[derive(Default)]
pub struct RecvDoc {
    pub(crate) total_recv: AtomicUsize,
    pub(crate) parent_no: usize,
    pub(crate) total_len: usize,
    pub(crate) variant: u8,
    pub(crate) first_unacked_seg_no: AtomicUsize,
    /// This `Vec` may only increase in length.
    pub(crate) data: UnsafeCell<Vec<u8>>,
    /// This `Vec` may only increase in length.
    pub(crate) set_segs: Vec<AtomicUsize>,
}

// #[derive(Default)]
// pub struct RecvDoc(RwLock<Desegmenter>);

pub struct SessionParams<R: Route> {
    send_channel_limit: usize,
    recv_channel_limit: usize,
    total_channel_limit: usize,
    send_bytes_limit: usize,
    recv_bytes_limit: usize,
    total_bytes_limit: usize,
    plpmtu_limit: u32,
    channel_byte_usage: usize,
    route: R,
}

pub struct SendAtom {
    pub(crate) counter: u64,
    pub(crate) channel_counter: usize,
    pub(crate) nagle_packet: Vec<u8>,
}

pub enum RecvDocState {
    Active(RecvDoc),
    Finished,
    Closed {
        last_message_id: u64,
    }
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
    pub(crate) params: SessionParams<R>,
    pub(crate) send_atom: Mutex<SendAtom>,
    pub(crate) bytes_in_flight: AtomicUsize,
    // ctx:
    plpmtu: u32,
    send_doc_table: DashMap<usize, SendDoc>,
    /// Document numbers may not be reused, otherwise severely delayed document segments could
    /// corrupt new documents.
    /// There is no way around this, segments which share a document number are indistinguishable.
    recv_doc_table: DashMap<usize, RecvDocState>,
    send_packet_table: DashMap<u64, SendPacketData>,
    recv_packet_table: DashMap<u64, RecvPacketData>,
}

pub struct DocSender<R: Route> {
    pub(crate) session: Session<R>,
    pub(crate) parent_no: usize,
}

pub struct DocReceiver<R: Route> {
    pub(crate) session: Session<R>,
    pub(crate) parent_no: usize,
}

pub enum RecvData<R: Route> {
    LossyDoc(Vec<u8>),
    SyncDoc(Vec<u8>),
    SyncDocRecv(Vec<u8>, DocReceiver<R>),
    SyncDocSend(Vec<u8>, DocSender<R>),
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

pub trait Route {
    fn send(&self, packet: &[u8]) -> Result<(), RouteError>;
}

impl<R: Route> Session<R> {
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
                let data_len = unsafe {
                    doc.data.get().as_ref_unchecked().len()
                };

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

    fn extract_doc(&self, doc_no: usize, parent_no: usize, variant: u8, data: Vec<u8>) -> Result<Option<RecvData<R>>, RecvError> {
        // TODO: Better delineate flags.
        let ret = if variant == VARIANT_DOC_HEAD_RECV {
            let receiver = DocReceiver {
                session: self.clone(),
                parent_no: doc_no,
            };
            RecvData::SyncDocRecv(data, receiver)
        } else if variant == VARIANT_DOC_HEAD_SEND {
            let sender = DocSender {
                session: self.clone(),
                parent_no: doc_no,
            };
            RecvData::SyncDocSend(data, sender)
        } else {
            RecvData::SyncDoc(data)
        };

        // TODO: check parent doc.

        Ok(ret)
    }

    fn finish_recv_doc(&self, doc_no: usize, mut entry: OccupiedEntry<usize, RecvDocState>) -> Result<Option<RecvData<R>>, RecvError> {
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

    fn recv_doc_header(&self, doc_no: usize, parent_no: usize, doc_len: usize, variant: u8) -> Result<Option<RecvData<R>>, RecvError> {
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
                    entry.insert(RecvDocState::Active(RecvDoc { total_len: doc_len, data, set_segs, variant, parent_no, ..Default::default() }));

                    Ok(None)
                } else {
                    entry.insert(RecvDocState::Finished);
                    self.extract_doc(doc_no, parent_no, variant, Vec::new())
                }
            }
        }
    }

    pub async fn recv(&self, packet: &mut [u8], route: R) -> Result<SmallVec<[RecvData<R>; 1]>, RecvError> {
        // TODO: Decrypt packet.
        let mut ret = SmallVec::new();

        let mut i = 0;
        while i < packet.len() {
            let variant = packet[i];
            i += 1;
            match variant {
                VARIANT_NULL => {}
                VARIANT_PACKET_END => break,
                VARIANT_DOC_HEAD | VARIANT_DOC_HEAD_RECV | VARIANT_DOC_HEAD_SEND => {
                    let doc_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let parent_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let doc_len = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let res = self.recv_doc_header(doc_no, parent_no, doc_len, variant)?;
                    if let Some(res) = res {
                        ret.push(res);
                    }
                }
                VARIANT_DOC_DATA => {
                    let doc_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let seg_no = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    let seg_len = varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
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

pub enum IntoError {
    Abandoned,
    Closed,
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

    pub async fn recv_into(&self, dest: &mut [u8]) -> Result<RecvIntoOk<R>, IntoError> {
        todo!()
    }

    pub fn try_recv_into(&self, dest: &mut [u8]) -> Result<RecvIntoOk<R>, IntoError> {
        todo!()
    }
}

impl<R: Route> DocSender<R> {
    pub async fn flush(&self) -> Result<(), Error> {
        todo!()
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        todo!()
    }

    pub async fn send_with_receiver(&self, data: &[u8]) -> Result<DocSender<R>, Error> {
        todo!()
    }

    pub async fn send_with_sender(&self, data: &[u8]) -> Result<DocReceiver<R>, Error> {
        todo!()
    }

    pub async fn send_bytes(&self, bytes: Bytes) -> Result<(), Error> {
        todo!()
    }

    pub async fn send_bytes_with_receiver(&self, bytes: Bytes) -> Result<DocSender<R>, Error> {
        todo!()
    }

    pub async fn send_bytes_with_sender(&self, bytes: Bytes) -> Result<DocReceiver<R>, Error> {
        todo!()
    }

    pub async fn try_send_bytes(&self, bytes: Bytes) -> Result<(), TryError> {
        todo!()
    }

    pub async fn try_send_bytes_with_receiver(&self, bytes: Bytes) -> Result<DocSender<R>, TryError> {
        todo!()
    }

    pub async fn try_send_bytes_with_sender(&self, bytes: Bytes) -> Result<DocReceiver<R>, TryError> {
        todo!()
    }
}
