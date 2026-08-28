use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::AtomicU64,
    },
};

use dashmap::DashSet;
use smallvec::SmallVec;

use crate::{
    ack_runs::decode, packet_builder::{ElicitingFrame, PacketBuilder, Segment}, protocol::*, session::{RecvDocState, RecvError, Route, SendDocInner, Session, Work, WorkInner},
};

pub struct SentPayload {
    pub(crate) packet_uid: u64,
    pub(crate) sent_at: f64,
    pub(crate) resend_len: u32,
    pub(crate) eliciting_frames: SmallVec<[ElicitingFrame; 2]>,
}

pub struct TransmissionQueue {
    next_time_to_send: AtomicU64,
    orphans: Mutex<SmallVec<[ElicitingFrame; 1]>>,
    pub(crate) packet_queue: Mutex<VecDeque<SentPayload>>,
    // It is possible but rare for this to have random numbers in it.
    pub(crate) unacked_packets: DashSet<u64>,
}

impl<R: Route> Session<R> {
    pub fn transmit(&self, mut queue: impl FnMut(Work), now: f64) {
        // TODO: This function is inelegant, we definitely want to improve that, but it does not
        // make sense to do so until we do some benchmarking and optimization.
        let mtu = self.mtu;

        let mut packet_budget = self.congestion_control.current_available_plpmtus(mtu, now);
        if packet_budget == 0 {
            return;
        }
        let mut packet = PacketBuilder::new(mtu);
        let mut _dec_budget = || {
            packet_budget -= 1;
            packet_budget == 0
        };

        let open_sockets = self.open_sockets.read().unwrap();
        for (i, socket_data) in open_sockets.sockets.iter().enumerate() {
            let mut acks = socket_data.acks.lock().unwrap();
            if packet.append_sorted_acks(&mut acks, i > 0, socket_data.socket.local_id) {
                queue(Work(WorkInner::Send(packet)));
                packet_budget -= 1;
                if packet_budget == 0 {
                    return;
                }
                packet = PacketBuilder::new(mtu);
            }
        }

        let rto = self.get_last_recv_time() - self.stats.retransmission_timeout();
        loop {
            let mut resend_packet = None;
            let mut packet_queue = self.transmissions.packet_queue.lock().unwrap();
            while let Some(packet) = packet_queue.pop_front_if(|p| p.sent_at < rto) {
                if self.transmissions.unacked_packets.remove(&packet.packet_uid).is_some() {
                    resend_packet = Some(packet);
                }
            }
            drop(packet_queue);

            let Some(resend_packet) = resend_packet else {
                break;
            };

            // TODO: Debounce congestion events.
            self.congestion_control.congestion_detected(now);

            let mut temp_packet = None;
            if resend_packet.resend_len as usize > packet.remaining_cap()
                && resend_ratio(mtu) < resend_packet.resend_len
                && resend_packet.resend_len <= mtu
                && packet_budget > 1
            {
                // This packet does not fit in the current packet builder but does fit nicely in its own packet.
                temp_packet = Some(packet);
                packet = PacketBuilder::new(mtu);
            }

            let mut frame_iter = resend_packet.eliciting_frames.into_iter();
            for frame in &mut frame_iter {
                match frame {
                    ElicitingFrame::Seg(mut seg) => {
                        loop {
                            let (send_now, overflow_seg) = packet.try_append_seg(seg);
                            if send_now {
                                queue(Work(WorkInner::Send(packet)));
                                packet_budget -= 1;
                                if packet_budget == 0 {
                                    if let Some(overflow_seg) = overflow_seg {
                                        let mut orphans = self.transmissions.orphans.lock().unwrap();
                                        orphans.push(ElicitingFrame::Seg(overflow_seg));
                                        for frame in frame_iter {
                                            orphans.push(frame);
                                        }
                                    } else if let Some(frame) = frame_iter.next() {
                                        let mut orphans = self.transmissions.orphans.lock().unwrap();
                                        orphans.push(frame);
                                        for frame in frame_iter {
                                            orphans.push(frame);
                                        }
                                    }
                                    if let Some(temp_packet) = temp_packet {
                                        debug_assert!(false, "unreachable");
                                        // Just in case, `temp_packet` is queued to be sent.
                                        queue(Work(WorkInner::Send(temp_packet)));
                                    }
                                    return;
                                }
                                packet = PacketBuilder::new(mtu);
                            }
                            if let Some(overflow_seg) = overflow_seg {
                                seg = overflow_seg;
                            } else {
                                break;
                            }
                        }
                    }
                    ElicitingFrame::Control(variant, doc_no) => {
                        if packet.append_control(variant, doc_no) {
                            queue(Work(WorkInner::Send(packet)));
                            packet_budget -= 1;
                            if packet_budget == 0 {
                                if let Some(frame) = frame_iter.next() {
                                    let mut orphans = self.transmissions.orphans.lock().unwrap();
                                    orphans.push(frame);
                                    for frame in frame_iter {
                                        orphans.push(frame);
                                    }
                                }
                                if let Some(temp_packet) = temp_packet {
                                    debug_assert!(false, "unreachable");
                                    // Just in case, `temp_packet` is queued to be sent.
                                    queue(Work(WorkInner::Send(temp_packet)));
                                }
                                return;
                            }
                            packet = PacketBuilder::new(mtu);
                        }
                    }
                }
            }

            if let Some(temp_packet) = temp_packet {
                queue(Work(WorkInner::Send(packet)));
                packet_budget -= 1;
                if packet_budget == 0 {
                    debug_assert!(false, "unreachable");
                    queue(Work(WorkInner::Send(temp_packet)));
                    return;
                }
                packet = temp_packet;
            }
        }

        loop {
            let Some(doc_no) = self.send_queue.lock().unwrap().pop_front() else {
                break;
            };

            if (doc_no & 1 > 0) == self.is_initiator {
                // Document number is sending.
                let send_idx = ((doc_no >> 1) % self.send_table.len() as u64) as usize;
                let mut entry = self.send_table[send_idx].lock.lock().unwrap();
                if entry.doc_no != doc_no {
                    continue;
                }

                if let SendDocInner { doc: Some(doc), channel, ..} = &mut *entry {
                    match Segment::try_new(doc_no, doc, channel.is_none(), packet.remaining_cap()) {
                        Ok(seg) => {
                            // This segment contains a close signal so none others need to be sent.
                            entry.needs_send_close = false;
                            drop(entry);

                            if packet.append_seg(seg) {
                                queue(Work(WorkInner::Send(packet)));
                                packet_budget -= 1;
                                if packet_budget == 0 {
                                    return;
                                }
                                packet = PacketBuilder::new(mtu);
                            }
                        }
                        Err(false) => {
                            if entry.needs_send_close {
                                entry.needs_send_close = false;
                                drop(entry);

                                if packet.append_control(VARIANT_CONTROL_CLOSE, doc_no) {
                                    queue(Work(WorkInner::Send(packet)));
                                    packet_budget -= 1;
                                    if packet_budget == 0 {
                                        return;
                                    }
                                    packet = PacketBuilder::new(mtu);
                                }
                            }
                        }
                        Err(true) => {
                            drop(entry);

                            queue(Work(WorkInner::Send(packet)));
                            packet_budget -= 1;
                            if packet_budget == 0 {
                                self.send_queue.lock().unwrap().push_front(doc_no);
                                return;
                            }
                            packet = PacketBuilder::new(mtu);

                            let mut entry = self.send_table[send_idx].lock.lock().unwrap();
                            if let SendDocInner { doc: Some(doc), channel, ..} = &mut *entry {
                                let Ok(seg) =
                                    Segment::try_new(doc_no, doc, channel.is_none(), packet.remaining_cap())
                                else {
                                    // If the document had no data, continue. It should not be
                                    // possible for the document to overflow a fresh packet.
                                    continue;
                                };
                                entry.needs_send_close = false;
                                drop(entry);

                                if packet.append_seg(seg) {
                                    queue(Work(WorkInner::Send(packet)));
                                    packet_budget -= 1;
                                    if packet_budget == 0 {
                                        return;
                                    }
                                    packet = PacketBuilder::new(mtu);
                                }
                            } else if entry.needs_send_close {
                                entry.needs_send_close = false;
                                drop(entry);

                                if packet.append_control(VARIANT_CONTROL_CLOSE | VARIANT_CONTROL_FIN, doc_no) {
                                    queue(Work(WorkInner::Send(packet)));
                                    packet_budget -= 1;
                                    if packet_budget == 0 {
                                        return;
                                    }
                                    packet = PacketBuilder::new(mtu);
                                }
                            }
                        }
                    }
                } else if entry.needs_send_close {
                    entry.needs_send_close = false;
                    drop(entry);

                    if packet.append_control(VARIANT_CONTROL_CLOSE | VARIANT_CONTROL_FIN, doc_no) {
                        queue(Work(WorkInner::Send(packet)));
                        packet_budget -= 1;
                        if packet_budget == 0 {
                            return;
                        }
                        packet = PacketBuilder::new(mtu);
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
                let mut variant = entry.channel.is_none() as u8 * VARIANT_CONTROL_CLOSE;
                variant |= (!matches!(entry.doc, RecvDocState::Active(..))) as u8 * VARIANT_CONTROL_FIN;
                drop(entry);

                if packet.append_control(variant, doc_no) {
                    queue(Work(WorkInner::Send(packet)));
                    packet_budget -= 1;
                    if packet_budget == 0 {
                        return;
                    }
                    packet = PacketBuilder::new(mtu);
                }
            }
        }

        if !packet.is_empty() {
            self.send_now(packet, todo!());
        }
    }

    /// Returns the next time that `transmit_all` should be called.
    pub fn acknowledged(
        &self,
        socket_uid: u32,
        variant: u8,
        packet: &[u8],
        i: &mut usize,
        now: f64,
    ) -> Result<Option<f64>, RecvError> {
        decode(packet, variant == VARIANT_ACK_RUN, i, |packet_no: u32| {
            let packet_uid = packet_no as u64 | (socket_uid as u64) << 32;
            // TODO: handle frames which require immediate attention after an ack.
            self.transmissions.unacked_packets.remove(&packet_uid);
        });

        Ok(None)
    }
}
