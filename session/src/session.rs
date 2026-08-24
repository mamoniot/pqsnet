use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    ops::{Deref, DerefMut, Range},
    ptr::NonNull,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::Waker,
};

use arrayvec::ArrayVec;
use bytes::{Bytes, BytesMut};
use dashmap::{DashMap, Entry, OccupiedEntry};
use smallvec::SmallVec;

use crate::{
    channel::{Channel, RecvDocData},
    packet_builder::PacketBuilder,
    protocol::*,
    send_lossless::TransmissionQueue,
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
    pub(crate) plpmtu: u32,
    /// Document numbers may not be reused, otherwise severely delayed document segments could
    /// corrupt new documents.
    /// There is no way around this, segments which share a document number are indistinguishable.
    pub(crate) recv_total: AtomicUsize,
    pub(crate) recv_max: AtomicUsize,
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

    pub(crate) socket_idx: bool,
    pub(crate) sockets: RwLock<ArrayVec<Socket, 2>>,

    pub(crate) congestion_control: (),
    pub(crate) stats: (),
    pub(crate) route: R,
}

pub(crate) struct Socket {
    pub(crate) acks: Mutex<VecDeque<u32>>,
    // pub(crate) socket: Sock
}

pub(crate) struct RecvDocEntry<R: Route> {
    pub(crate) lock: Mutex<RecvDocInner<R>>,
}

pub(crate) struct RecvDocInner<R: Route> {
    pub(crate) doc_no: DocNo,
    pub(crate) doc: RecvDocState,
    pub(crate) channel: Option<ChannelState<R>>,
    // This may only be set to true once at the same time `channel` is set to `None` or when `doc`
    // is set to `Fin`.
    pub(crate) needs_send_control: bool,
}

pub(crate) enum RecvDocState {
    Recv(RecvDoc),
    // These are awoken when we receive an ack for our doc fin frame.
    Fin(SmallVec<[Waker; 1]>),
    FinAck,
}

pub(crate) struct RecvDoc {
    pub(crate) mem: Box<[u8]>,
    pub(crate) total_recv: usize,
    pub(crate) set_segs: Vec<usize>,
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
    pub(crate) reply_buffer: Option<ReplyState<R>>,
}

pub enum ReplyState<R: Route> {
    Awaiting(Range<*mut u8>, Waker),
    Recv(Channel<R>),
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
}

#[derive(Clone, Copy, Debug)]
pub enum AllocData<'a> {
    Long(&'a [u8]),
    Short(u64),
    None,
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

    pub fn add_route(&self, route: R) -> Result<(), Error> {
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

        // It is safe to read the length of `data` since it is only written to when the
        // write lock is held.
        let doc_len = doc.mem.len();

        if seg.is_empty() {
            return Ok(doc_len == 0);
        }

        let seg_end = seg_off + seg.len() - 1;
        let seg_off_idx = seg_off / usize::BITS as usize;
        let seg_off_rem = seg_off % usize::BITS as usize;
        let seg_end_idx = seg_end / usize::BITS as usize;
        let seg_end_rem = seg_end % usize::BITS as usize;

        let seg_off_set = usize::MAX >> seg_off_rem;
        let seg_end_set = usize::MAX << (usize::BITS as usize - seg_end_rem - 1);

        if seg_end >= doc_len {
            return Err(RecvError::Invalid);
        }

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
        doc.mem[seg_off..=seg_end].copy_from_slice(seg);
        Ok(doc.total_recv == doc_len)
    }

    pub(crate) fn recv(&self, packet: &mut [u8], route: R) -> Result<(), RecvError> {
        // TODO: Decrypt packet.
        let mut ret = SmallVec::new();

        let mut ack_eliciting = false;
        let mut i = 0;
        while i < packet.len() {
            let variant = packet[i];
            i += 1;
            match variant {
                VARIANT_NULL_TERMINATOR => break,
                VARIANT_SEG_HAS_LEN..=VARIANT_SEG_MAX => {
                    ack_eliciting = true;

                    let has_special_parent = variant & VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT > 0;
                    let has_doc_len = variant & VARIANT_SEG_FLAG_HAS_DOC_LEN > 0;
                    let is_single_seg = variant & VARIANT_SEG_FLAG_IS_SINGLE_SEG > 0;
                    let is_first_segment = variant & VARIANT_SEG_FLAG_IS_FIRST > 0;
                    let variant_len = variant & VARIANT_SEG_LEN_MASK;
                    let doc_len = None;
                    let doc_parent_no = None;
                    let seg_off = 0;

                    let doc_no = varu64_try_read(packet, &mut i).ok_or(RecvError::Invalid)?;
                    if has_doc_len {
                        doc_len = Some(varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?);
                    }
                    if has_special_parent || is_first_segment {
                        doc_parent_no = Some(varusize_try_read(packet, &mut i).ok_or(RecvError::Invalid)?);
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

                    let mut largest_recv_doc_no = self.largest_recv_doc_no.lock().unwrap();
                    while *largest_recv_doc_no < doc_no {
                        *largest_recv_doc_no += 2;
                        // TODO: memory usage tracking
                        self.recv_doc_table.insert(*largest_recv_doc_no, None);
                        self.channel_table.insert(*largest_recv_doc_no, None);
                    }

                    match self.recv_doc_table.entry(doc_no) {
                        Entry::Occupied(mut entry) => match entry.get_mut() {
                            RecvDocState::Active(recv_doc) => {
                                if self.recv_doc(recv_doc, seg_off, seg)? {
                                    let (_, RecvDocState::Active(doc)) = entry.replace_entry(RecvDocState::Fin) else {
                                        unreachable!()
                                    };
                                    ret.push(RecvData::Recv {
                                        has_retransmission: doc.has_retransmission,
                                        doc: doc.mem,
                                        doc_no,
                                    });
                                }
                            }
                            RecvDocState::Fin => {}
                        },
                        Entry::Vacant(entry) => {
                            if variant_alloc > 0 {
                                // TODO: move this call out of the critical section.
                                if let Some(mem) = route.alloc(alloc_data, doc_len) {
                                    let set_segs_len = doc_len / usize::BITS as usize;
                                    let mut doc = RecvDoc {
                                        has_retransmission: variant & VARIANT_SEG_FLAG_HAS_RETRANSMISSION > 0,
                                        mem,
                                        total_recv: 0,
                                        set_segs: vec![0; set_segs_len],
                                    };
                                    if self.recv_doc(&mut doc, seg_off, seg)? {
                                        entry.insert(RecvDocState::Fin);
                                        ret.push(RecvData::Recv {
                                            has_retransmission: doc.has_retransmission,
                                            doc: doc.mem,
                                            doc_no,
                                        });
                                    } else {
                                        entry.insert(RecvDocState::Active(doc));
                                    }
                                } else {
                                    entry.insert(RecvDocState::Fin);
                                    self.send_control_frame(VARIANT_REJECT_DOC, doc_no);
                                }
                            }
                        }
                    }
                }
                VARIANT_ACK_SINGLE | VARIANT_ACK_RUN => {}
                VARIANT_RESET_DOC | VARIANT_FIN_DOC => {}
                VARIANT_PADDING => {}
                _ => return Err(RecvError::Invalid),
            }
        }
        Ok(ret)
    }
}
