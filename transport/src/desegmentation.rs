use crate::messages::shared::*;

pub struct Desegmentation<const H_LEN: usize> {
    message: Box<[u8]>,
    seg_completed: [u32; 8],
    seg_count: u32,
    seg_total: u32,
    seg_rem: u32,
    seg_len: usize,
}

pub enum FirstRecvResult<const H_LEN: usize> {
    Segmented(Desegmentation<H_LEN>),
    NotSegmented,
    Invalid,
}

pub enum RecvResult {
    Invalid,
    Duplicate,
    Incomplete,
    Complete,
}

impl<const H_LEN: usize> Desegmentation<H_LEN> {
    pub fn is_single_segment(packet: &[u8]) -> bool {
        if packet.len() <= H_LEN {
            return false;
        }
        let seg_no = packet[SEGMENT_NO_IDX] as u32;
        let seg_total = packet[SEGMENT_TOTAL_IDX] as u32;
        let seg_rem = packet[SEGMENT_REMAINDER_IDX] as u32;

        if seg_no >= seg_total || seg_rem >= seg_total {
            return false;
        }

        seg_total <= 1
    }
    pub fn first_recv(packet: &[u8], maximum_len: usize) -> FirstRecvResult<H_LEN> {
        use FirstRecvResult::*;

        if packet.len() <= H_LEN {
            return Invalid;
        }
        let seg_no = packet[SEGMENT_NO_IDX] as u32;
        let seg_total = packet[SEGMENT_TOTAL_IDX] as u32;
        let seg_rem = packet[SEGMENT_REMAINDER_IDX] as u32;

        if seg_no >= seg_total || seg_rem >= seg_total {
            return Invalid;
        }

        if seg_total <= 1 {
            return NotSegmented;
        }
        let seg_len = packet.len() - H_LEN - (seg_no < seg_rem) as usize;

        let message_len = seg_len * seg_total as usize + seg_rem as usize + H_LEN;
        if message_len > maximum_len {
            return Invalid;
        }

        let mut message = Vec::with_capacity(message_len);
        message.extend_from_slice(&packet[..H_LEN]);
        message[SEGMENT_NO_IDX] = 0;
        message.resize(message_len, 0);

        let mut seg_completed = [0; 8];
        seg_completed[(seg_no / 32) as usize] |= 1 << (seg_no % 32);

        let mut ret = Desegmentation {
            message: message.into_boxed_slice(),
            seg_completed,
            seg_count: 1,
            seg_total,
            seg_rem,
            seg_len,
        };

        ret.write_to(seg_no, packet);

        FirstRecvResult::Segmented(ret)
    }

    pub fn recv(&mut self, packet: &[u8]) -> RecvResult {
        use RecvResult::*;

        if packet.len() <= H_LEN {
            return Invalid;
        }
        let seg_no = packet[SEGMENT_NO_IDX] as u32;
        let seg_total = packet[SEGMENT_TOTAL_IDX] as u32;
        let seg_rem = packet[SEGMENT_REMAINDER_IDX] as u32;
        let seg_len = packet.len() - H_LEN - (seg_no < seg_rem) as usize;

        if seg_total != self.seg_total || seg_rem != self.seg_rem || seg_len != self.seg_len || seg_no >= seg_total {
            return Invalid;
        }

        let seg_bit = 1 << (seg_no % 32);
        let seg_mark = &mut self.seg_completed[(seg_no / 32) as usize];
        if (*seg_mark & seg_bit) > 0 {
            return Duplicate;
        }
        *seg_mark |= seg_bit;
        self.seg_count += 1;

        self.write_to(seg_no, packet);

        if self.seg_count < seg_total {
            Incomplete
        } else {
            Complete
        }
    }

    fn write_to(&mut self, seg_no: u32, packet: &[u8]) {
        let i = self.seg_len * seg_no as usize + self.seg_rem.min(seg_no) as usize + H_LEN;
        let j = i + packet.len() - H_LEN;

        self.message[i..j].copy_from_slice(&packet[H_LEN..]);
    }

    pub fn complete(self) -> Box<[u8]> {
        self.message
    }
}
