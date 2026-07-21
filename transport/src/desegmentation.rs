use crate::messages::shared::*;

#[derive(Default)]
pub struct Desegmenter {
    message_opt: Option<Box<[u8]>>,
    seg_completed: [u32; 8],
    seg_total: u32,
    seg_rem: u32,
    seg_len: usize,
    seg_recv_count: u32,
}

pub enum FirstRecvResult {
    Segmented(Desegmenter),
    NotSegmented,
    Invalid,
}

pub enum RecvResult {
    /// The packet received is a complete, unsegmented message.
    NotSegmented,
    /// The packet received was invalidly encoded.
    Invalid,
    /// The packet received was valid but was dropped for being a duplicate of a previous packet.
    Duplicate,
    /// The packet received was valid and desegmented, but the full message has not been received yet.
    Incomplete,
    /// The packet received was valid and desegmented into the full message.
    Complete(Box<[u8]>),
}

impl Desegmenter {
    pub fn recv(&mut self, packet: &[u8], header_len: usize, maximum_len: usize) -> RecvResult {
        if packet.len() <= header_len {
            return RecvResult::Invalid;
        }
        let seg_no = packet[SEGMENT_NO_IDX] as u32;
        let seg_total = packet[SEGMENT_TOTAL_IDX] as u32;
        let seg_rem = packet[SEGMENT_REMAINDER_IDX] as u32;
        let seg_len = packet.len() - header_len - (seg_no < seg_rem) as usize;

        if seg_no >= seg_total {
            return RecvResult::Invalid;
        }

        let message = if let Some(message) = &mut self.message_opt {
            if seg_total != self.seg_total || seg_rem != self.seg_rem || seg_len != self.seg_len {
                return RecvResult::Invalid;
            }

            message
        } else if self.seg_total == 0 {
            if seg_total == 0 || seg_rem >= seg_total {
                return RecvResult::Invalid;
            }
            if seg_total == 1 {
                return RecvResult::NotSegmented;
            }

            let message_len = seg_len * seg_total as usize + seg_rem as usize + header_len;
            if message_len > maximum_len {
                return RecvResult::Invalid;
            }

            self.seg_total = seg_total;
            self.seg_rem = seg_rem;
            self.seg_len = seg_len;

            let mut message = Vec::with_capacity(message_len);
            message.extend_from_slice(&packet[..header_len]);
            message[SEGMENT_NO_IDX] = 0;
            message.resize(message_len, 0);

            // This is the only place `message_opt` is populated.
            self.message_opt.insert(message.into())
        } else {
            // This is only reachable after a message is completed from a previous call to this function.
            return RecvResult::Duplicate;
        };

        let seg_bit = 1 << (seg_no % 32);
        let seg_mark = &mut self.seg_completed[(seg_no / 32) as usize];
        if (*seg_mark & seg_bit) > 0 {
            return RecvResult::Duplicate;
        }
        *seg_mark |= seg_bit;
        self.seg_recv_count += 1;

        let i = self.seg_len * seg_no as usize + self.seg_rem.min(seg_no) as usize + header_len;
        let j = i + packet.len() - header_len;

        message[i..j].copy_from_slice(&packet[header_len..]);

        if self.seg_recv_count >= self.seg_total {
            RecvResult::Complete(self.message_opt.take().unwrap())
        } else {
            RecvResult::Incomplete
        }
    }

    /// Returns `true` if the message this was desegmenting has already been completed.
    /// Once the message is completed this will reject all new packets.
    pub fn is_complete(&self) -> bool {
        self.seg_recv_count >= self.seg_total
    }
}

pub fn precalc_segments(header_length: usize, message_len: usize, mtu: usize) -> (u8, u8) {
    let inner_mtu = mtu - header_length;
    let inner_message = message_len - header_length;
    let seg_total = inner_message.div_ceil(inner_mtu);
    let seg_rem = inner_message % seg_total;

    (seg_total as u8, seg_rem as u8)
}
