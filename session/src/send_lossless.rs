use std::{collections::{BTreeSet, HashMap, VecDeque}, sync::{Mutex, RwLock, atomic::{AtomicU64, AtomicUsize, Ordering}}};

use bytes::Bytes;
use dashmap::{DashMap, DashSet, Entry};
use tinyvec::ArrayVec;

use crate::{lossless_builder::{LosslessBuilder, Segment}, protocol::*, session::{DocNo, RecvError, Route, Session, SocketId, Work}, varint::*};

pub struct SendDoc {
    parent_no: DocNo,
    header: ArrayVec<[u8; MAX_DOC_HEADER_LEN]>,
    data: Bytes,
    segmentation: AtomicUsize,
}

pub struct SentPayload {
    packet_id: u64,
    sent_at: f64,
    resend_of: Option<u64>,
    eliciting_frames: ArrayVec<[Segment; 2]>,
}

pub struct TransmitWork {
    rto: f64,
    plpmtu: usize,
}

impl From<TransmitWork> for Work {
    fn from(value: TransmitWork) -> Self {
        todo!()
    }
}

pub struct TransmissionQueue {
    next_time_to_send: AtomicU64,
    send_doc_table: DashMap<DocNo, SendDoc>,
    /// This table maps packet ids to a bool representing whether that particular packet id is in
    /// flight (true) or has been considered lost (false). It may not actually be lost, hence we
    /// track it for a short time to recover the congestion window if we eventually see the ack.
    payload_state_table: DashMap<u64, bool>,
    payload_queue: Mutex<VecDeque<SentPayload>>,
    ack_table: [Mutex<VecDeque<SentPayload>>; 2],
    lost_payloads: AtomicU64,
}

impl<R: Route> Session<R> {
    /// Returns the next time that `transmit_all` should be called.
    pub fn add_doc(&self, data: Bytes, parent_no: DocNo, now: f64) -> (DocNo, Option<f64>) {
        todo!()
    }

    /// Returns the next time that this function should be called.
    pub fn transmit_all(&self, queue: impl FnMut(Work), now: f64) -> Option<f64> {
        let plpmtu = self.plpmtu as usize;

        let next_time_to_send: f64 = bytemuck::cast(self.transmissions.next_time_to_send.load(Ordering::Relaxed));
        if next_time_to_send > now {
            return Some(next_time_to_send);
        }

        let work_to_spawn = match self.congestion_control.current_available_plpmtus(now, plpmtu) {
            Ok(n) => n,
            Err(next_time_to_send) => {
                self.transmissions.next_time_to_send.store(bytemuck::cast(next_time_to_send), Ordering::Relaxed);
                return Some(next_time_to_send)
            }
        };
        for i in 0..work_to_spawn {

        }

        None
    }

    pub fn transmit(&self, work: TransmitWork, now: f64) {
        let plpmtu = work.plpmtu;
        let mut packet = LosslessBuilder::new(plpmtu);

        let rto = self.get_last_recv_time() - self.stats.retransmission_time();
        loop {
            let resend_packet = None;
            // TODO: remove this lock as it is a large bottleneck.
            let mut queue = self.transmissions.payload_queue.lock().unwrap();
            while let Some(payload) = queue.pop_front_if(|p| p.sent_at < rto) {
                // If this payload's packet id is not in `payload_table` it means that
                // the payload's packet has been ack'd.
                self.transmissions.payload_state_table.alter(&payload.packet_id, |_, _is_in_flight| {
                    // This is the only place that may increment this counter.
                    self.transmissions.lost_payloads.fetch_add(1, Ordering::Relaxed);
                    debug_assert!(_is_in_flight, "lost packet in the payload_queue");
                    resend_packet = Some(payload);
                    false
                });
            }
            drop(queue);

            if let Some(resend_payload) = resend_packet {
                // TODO: Debounce congestion events.
                self.congestion_control.congestion_detected();
                for seg in resend_payload.eliciting_frames {
                    // Mark this segment as a resend before writing it.
                    // This is the only place that `resend_of_id` may be written to.
                    if let Some(resend_of_id) = seg.resend_of_id.replace(resend_payload.packet_id) {
                        // This segment was resent from an earlier packet, we assume that enough
                        // time has past that that earlier packet's ack will not arrive. If somehow
                        // it was severely delayed and arrives later anyways, who cares? If an ack
                        // gets that severely delayed we should not attempt to recover the
                        // congestion window because of it.
                        let state = self.transmissions.payload_state_table.remove(&resend_of_id);
                        let is_lost = state.is_some_and(|(_, _is_in_flight)| !_is_in_flight);
                        if is_lost {
                            let _lost_payloads = self.transmissions.lost_payloads.fetch_sub(1, Ordering::Relaxed);
                            debug_assert!(_lost_payloads != 0, "lost payloads underflow");
                        }
                        debug_assert!(is_lost, "in flight packet removed from state table");
                    }
                    while let Some(overflow_seg) = packet.try_append_segment(seg) {
                        // TODO: this method of handling overflowed segments is inefficient and inelegant.
                        self.send_now(&mut packet, now);
                        packet = LosslessBuilder::new(plpmtu);
                    }
                }
                if packet.is_full() {
                    return self.send_now(&mut packet, now);
                }
            } else {
                break;
            }
        }

        let shards_len = self.transmissions.send_doc_table.shards().len();
        let first_shard = rand::random_range(0..shards_len);
        let i = first_shard;

        for i in 0..shards_len {
            let shard = self.transmissions.send_doc_table.shards()[(first_shard + i) % shards_len].read();
            // The table is treated as read-only under a read lock, which makes it impossible to not
            // obey the required safety invariants.
            let iterator = unsafe {
                shard.iter()
            };
            for bucket in iterator {
                let doc_no;
                let doc;
                // Same as before, the table is read-only so this is safe.
                unsafe {
                    let entry = bucket.as_ref();
                    doc_no = entry.0;
                    doc = entry.1.get();
                };

                let total_doc_len = doc.data.len() + doc.header.len();
                let remaining_cap = packet.remaining_cap();
                debug_assert!(remaining_cap >= MIN_FRAME_APPEND_LEN);
                let mut seg_len = 0;
                // Claim a mutually exclusive segment of the document for this thread to send
                // or the document metadata if that has not been sent yet.
                let res = doc.segmentation.try_update(Ordering::Relaxed, Ordering::Relaxed, |seg_no| {
                    let remaining_data_len = total_doc_len - seg_no;
                    if remaining_data_len == 0 {
                        None
                    } else {
                        let seg_header_len = 1 + varusize_len(doc_no) + varusize_len(seg_no);
                        let data_cap = remaining_cap - seg_header_len;
                        seg_len = data_cap.min(remaining_data_len);
                        Some(seg_no + seg_len)
                    }
                });
                let seg_no = match res {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                debug_assert!(seg_len > 0);

                packet.append_doc(doc_no, seg_no, seg_len, &doc.header, &doc.data);

                if packet.is_full() {
                    return self.send_now(&mut packet, now);
                }
            }
        }

        self.send_now(&mut packet, now);
    }

    fn send_now(&self, packet: &mut LosslessBuilder, now: f64) {
        // TODO: This function needs to be retouched.
        // Make space for the footer (auth tag).
        packet.buf.extend_from_slice(&[0; FOOTER_LEN]);

        self.congestion_control.send_now(now, packet.buf.len());
        let packet_id = self.ctx.encrypt(&mut packet.buf[..]);
        let payload = SentPayload { packet_id, sent_at: now, resend_of: packet.resend_of_id, eliciting_frames: packet.eliciting_frames };

        let mut queue = self.transmissions.payload_queue.lock().unwrap();
        self.transmissions.payload_state_table.insert(packet_id, true);
        queue.push_back(payload);
        drop(queue);

        let _todo = self.route.send(&packet.buf[..]);
    }

    /// Returns the next time that `transmit_all` should be called.
    pub fn acknowledged(&self, socket_id: SocketId, variant: u8, packet: &[u8], i: &mut usize, now: f64) -> Result<Option<f64>, RecvError> {
        // OPTIMIZATION: This can be made more efficient if we can acknowlegde packets in batches.
        let ack_packet = |packet_no: u32| {
            let packet_id = packet_no as u64 | (socket_id as u64) << 32;
            if let Some((_, false)) = self.transmissions.payload_state_table.remove(&packet_id) {
                let lost_payloads = self.transmissions.lost_payloads.fetch_sub(1, Ordering::Relaxed);
                if lost_payloads <= 1 {
                    self.congestion_control.recover();
                }
                debug_assert!(lost_payloads != 0, "lost payloads underflow");
            }
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

        Ok(None)
    }
}
