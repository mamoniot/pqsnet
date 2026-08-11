use std::{collections::{BTreeSet, HashMap, VecDeque}, sync::{Mutex, RwLock}};

use bytes::Bytes;
use dashmap::DashMap;
use smallvec::SmallVec;

use crate::{protocol::VARIANT_ACK_RUN, session::{DocNo, RecvError, Route, Session, SocketId, Work}, varint::*};

pub struct SendDoc {
    parent_no: DocNo,
    data: Bytes,
    sent_total: usize,
}

pub struct SentPayload {
    packet_id: u64,
    sent_at: f64,
    resend_of: Option<u64>,
    eliciting_frames: SmallVec<[SentFrame; 2]>,
}

pub struct TransmitWork {
    resend_of: Option<u64>,
    eliciting_frames: SmallVec<[SentFrame; 2]>,
    packet: Vec<u8>,
}

pub enum SentFrame {
    METADATA {
        variant: u8,
        doc_no: DocNo,
        parent_no: usize,
        data_len: usize,
    },
    SEGMENT {
        doc_no: DocNo,
        seg_no: usize,
        data: Bytes,
    },
}

pub struct TransmissionQueue {
    send_doc_table: DashMap<DocNo, SendDoc>,
    // TODO: Change this datastructure to a hashtable indexing a ring buffer.
    payload_table: DashMap<u64, usize>,
    payload_queue: Mutex<VecDeque<SentPayload>>,
    lost_payloads: Mutex<BTreeSet<u64>>,
}


impl<R: Route> Session<R> {
    /// Returns the next time that `transmit_all` should be called.
    pub fn add_doc(&self, variant: u8, data: Bytes, parent_no: DocNo, now: f64) -> (DocNo, Option<f64>) {
        None
    }

    /// Returns the next time that this function should be called.
    pub fn transmit_all(&self, queue: impl FnMut(Work), now: f64) -> Option<f64> {
        let rto = self.get_last_recv_time() - self.stats.retransmission_time();

        // For now this function will do basically all of the work except for encryption.
        for payload in self.transmissions.payload_table.iter() {

        }

        for doc in self.transmissions.send_doc_table.iter() {
            doc.sent_total
        }
        None
    }

    pub fn transmit(&self, work: TransmitWork, now: f64) {
        let packet_id = self.ctx.encrypt(&mut work.packet[..]);
        let payload = SentPayload { packet_id, sent_at: now, resend_of: work.resend_of, eliciting_frames: work.eliciting_frames };

        let mut queue = self.transmissions.payload_queue.lock().unwrap();
        let queue_idx = queue.len();
        queue.push_back(payload);

        self.transmissions.payload_table.insert(packet_id, queue_idx);
        drop(queue);

        let _todo = self.route.send(&work.packet[..]);
    }

    /// Returns the next time that `transmit_all` should be called.
    pub fn acknowledged(&self, socket_id: SocketId, variant: u8, packet: &[u8], i: &mut usize, now: f64) -> Result<Option<f64>, RecvError> {
        // OPTIMIZATION: This can be made more efficient if we can acknowlegde packets in batches.
        let mut ack_packet = |packet_no: u32| {
            self.transmissions.payload_table.remove(&(packet_no as u64 | (socket_id as u64) << 32));
        };

        if *i + 4 > packet.len() {
            return Err(RecvError::Invalid);
        }
        let first_ack_no = u32::from_be_bytes(packet[*i..*i + 4].try_into().unwrap());
        *i += 4;

        ack_packet(first_ack_no);

        if variant == VARIANT_ACK_RUN {
            let total_len = varusize_try_read(packet, i).ok_or(RecvError::Invalid)?;
            // `total_len` is untrusted so we guard against overflows.
            if total_len > packet.len() - *i {
                return Err(RecvError::Invalid);
            }
            let ack_end = *i + total_len;

            let mut cur_ack_no = first_ack_no;
            while *i < ack_end {
                let cur_run = varu32_try_read(packet, i).ok_or(RecvError::Invalid)?;
                let cur_run_len = (cur_run >> 1) + 1;
                let cur_run_bit = cur_run & 1 > 0;

                let next_ack_no = cur_ack_no.checked_add(cur_run_len).ok_or(RecvError::Invalid)?;

                if cur_run_bit {
                    for n in cur_ack_no + 1..next_ack_no {
                        ack_packet(n);
                    }
                }

                ack_packet(next_ack_no);
                cur_ack_no = next_ack_no;
            }
        }

        Ok(())
    }
}
