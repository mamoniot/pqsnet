use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use dashmap::DashMap;
use smallvec::SmallVec;

use crate::{
    packet_builder::{PacketBuilder, Segment},
    protocol::*,
    session::{DocNo, RecvDocState, RecvError, Route, Session, SocketId, Work, WorkInner},
    varint::*,
};

pub struct SentPayload {
    packet_id: u64,
    sent_at: f64,
    has_resend_of: SmallVec<[u64; 2]>,
    eliciting_frames: SmallVec<[ElicitingFrame; 2]>,
}

pub enum ElicitingFrame {
    Seg(Segment),
    Fin(DocNo),
    Close(DocNo),
    Reject(DocNo),
    Reset(DocNo),
}

pub struct TransmitWork {
    rto: f64,
    plpmtu: usize,
}

pub struct TransmissionQueue {
    next_time_to_send: AtomicU64,
    /// This table maps packet ids to a bool representing whether that particular packet id is in
    /// flight (true) or has been considered lost (false). It may not actually be lost, hence we
    /// track it for a short time to recover the congestion window if we eventually see the ack.
    payload_state_table: DashMap<u64, bool>,
    orphans: Mutex<SmallVec<[ElicitingFrame; 1]>>,
    payload_queue: Mutex<VecDeque<SentPayload>>,
    ack_table: [Mutex<VecDeque<SentPayload>>; 2],
    lost_payloads: AtomicU64,
}

impl<R: Route> Session<R> {
    pub fn transmit(&self, queue: impl FnMut(Work), now: f64) {
        let plpmtu = self.plpmtu as usize;

        let packet_budget: usize = self.congestion_control.current_available_plpmtus(now, plpmtu);
        if packet_budget == 0 {
            return;
        }
        let mut packet = PacketBuilder::new(plpmtu);

        macro_rules! send_with_budget {
            () => {{
                queue(Work(WorkInner::Send(packet)));

                packet_budget -= 1;
                if packet_budget == 0 {
                    true
                } else {
                    packet = PacketBuilder::new(plpmtu);
                    false
                }
            }};
        }

        let rto = self.get_last_recv_time() - self.stats.retransmission_timeout();
        loop {
            let resend_packet = None;
            // TODO: remove this lock as it is a large bottleneck.
            let mut queue = self.transmissions.payload_queue.lock().unwrap();
            while let Some(payload) = queue.pop_front_if(|p| p.sent_at < rto) {
                // If this payload's packet id is not in `payload_table` it means that
                // the payload's packet has been acked.
                self.transmissions
                    .payload_state_table
                    .alter(&payload.packet_id, |_, _is_in_flight| {
                        // This is the only place that may increment this counter.
                        self.transmissions.lost_payloads.fetch_add(1, Ordering::Relaxed);
                        debug_assert!(_is_in_flight, "lost packet in the payload_queue");
                        resend_packet = Some(payload);
                        false
                    });
            }
            drop(queue);

            let Some(resend_payload) = resend_packet else {
                break;
            };

            // TODO: Debounce congestion events.
            self.congestion_control.congestion_detected();
            // Mark this segment as a resend before writing it.
            // This is the only place that `resend_of_id` may be written to.
            for resend_of in resend_payload.has_resend_of {
                // This segment was resent from an earlier packet, we assume that enough
                // time has past that that earlier packet's ack will not arrive. If somehow
                // it was severely delayed and arrives later anyways, who cares? If an ack
                // gets that severely delayed we should not attempt to recover the
                // congestion window because of it.
                let state = self.transmissions.payload_state_table.remove(&resend_of);
                let is_lost = state.is_some_and(|(_, _is_in_flight)| !_is_in_flight);
                if is_lost {
                    let _lost_payloads = self.transmissions.lost_payloads.fetch_sub(1, Ordering::Relaxed);
                    debug_assert!(_lost_payloads != 0, "lost payloads underflow");
                }
                debug_assert!(is_lost, "in flight packet removed from state table");
            }

            for frame in resend_payload.eliciting_frames {
                match frame {
                    ElicitingFrame::Seg(mut seg) => {
                        while let Some(overflow_seg) = packet.try_append_segment(seg, Some(resend_payload.packet_id)) {
                            if send_with_budget!() {
                                self.transmissions
                                    .orphans
                                    .lock()
                                    .unwrap()
                                    .push(ElicitingFrame::Seg(seg));
                                return;
                            }
                            seg = overflow_seg;
                        }
                    }
                    ElicitingFrame::Fin(doc_no) | ElicitingFrame::Close(doc_no) => {}
                    ElicitingFrame::Reject(doc_no) => {}
                    ElicitingFrame::Reset(doc_no) => {}
                }
            }
        }

        loop {
            let Some(doc_no) = self.send_queue.lock().unwrap().pop_front() else {
                break;
            };

            let remaining_cap = packet.remaining_cap();

            if (doc_no & 1 > 0) == self.is_initiator {
                // Document number is sending.
                let send_idx = ((doc_no >> 1) % self.send_table.len() as u64) as usize;
                let mut entry = self.send_table[send_idx].lock.lock().unwrap();
                if entry.doc_no != doc_no {
                    continue;
                }
                if let Some(doc) = &mut entry.doc {
                    match Segment::try_new(doc_no, doc, entry.channel.is_none(), packet.remaining_cap()) {
                        Ok(seg) => {
                            // This segment contains a close signal so none others need to be sent.
                            entry.needs_send_close = false;
                            drop(entry);

                            if packet.append_seg(seg) {
                                if send_with_budget!() {
                                    return;
                                }
                            }
                        }
                        Err(false) => {}
                        Err(true) => {
                            drop(entry);

                            if send_with_budget!() {
                                self.send_queue.lock().unwrap().push_front(doc_no);
                                return;
                            }

                            let mut entry = self.send_table[send_idx].lock.lock().unwrap();
                            let Ok(seg) =
                                Segment::try_new(doc_no, doc, entry.channel.is_none(), packet.remaining_cap())
                            else {
                                // If the document had no data, continue. It should not be
                                // possible for the document to overflow a fresh packet.
                                continue;
                            };
                            entry.needs_send_close = false;
                            drop(entry);

                            if packet.append_seg(seg) {
                                if send_with_budget!() {
                                    return;
                                }
                            }
                        }
                    }
                } else if entry.needs_send_close {
                    entry.needs_send_close = false;
                    let variant = VARIANT_CONTROL_CLOSE;
                    variant |= entry.doc.is_none() as u8 * VARIANT_CONTROL_FIN;
                    drop(entry);

                    if packet.append_control(variant, doc_no) {
                        if send_with_budget!() {
                            return;
                        }
                    }
                }
            } else {
                // Document number is receiving.
                let recv_idx = ((doc_no >> 1) % self.recv_table.len() as u64) as usize;
                let mut entry = self.recv_table[recv_idx].lock.lock().unwrap();
                if entry.doc_no != doc_no || !entry.needs_send_control {
                    continue;
                }
                entry.needs_send_control = false;
                let variant = entry.channel.is_none() as u8 * VARIANT_CONTROL_CLOSE;
                variant |= (!matches!(entry.doc, RecvDocState::Recv(..))) as u8 * VARIANT_CONTROL_FIN;
                drop(entry);

                if packet.append_control(variant, doc_no) {
                    if send_with_budget!() {
                        return;
                    }
                }
            }
        }

        if !packet.is_empty() {
            self.send_now(packet);
        }
    }

    fn send_now(&self, packet: PacketBuilder) {
        // TODO: This function needs to be retouched.
        // Make space for the footer (auth tag).
        packet.buf.extend_from_slice(&[0; FOOTER_LEN]);

        self.congestion_control.send_now(now, packet.buf.len());
        let packet_id = self.ctx.encrypt(&mut packet.buf[..]);
        let payload = SentPayload {
            packet_id,
            sent_at: now,
            resend_of: packet.resend_of_id,
            eliciting_frames: packet.eliciting_frames,
        };

        let mut queue = self.transmissions.payload_queue.lock().unwrap();
        self.transmissions.payload_state_table.insert(packet_id, true);
        queue.push_back(payload);
        drop(queue);

        let _todo = self.route.send(&packet.buf[..]);
    }

    /// Returns the next time that `transmit_all` should be called.
    pub fn acknowledged(
        &self,
        socket_id: SocketId,
        variant: u8,
        packet: &[u8],
        i: &mut usize,
        now: f64,
    ) -> Result<Option<f64>, RecvError> {
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
