use crate::messages::*;

pub struct Desegmentation {
    message: Box<[u8]>,
    seg_total: usize,
    seg_rem: usize,
}

pub enum FirstRecvResult {
    Segmented(Desegmentation),
    NotSegmented,
    Invalid,
}

pub enum RecvResult {
    Invalid,
    Duplicate,
    Incomplete,
    Complete,
}


impl Desegmentation {
    pub fn first_recv(packet: &[u8]) -> FirstRecvResult {
        use FirstRecvResult::*;

        if packet.len() <= MESSAGE_CRYPTO_START {
            return Invalid;
        }
        let seg_no = packet[SEGMENT_NO_IDX] as usize;
        let seg_total = packet[SEGMENT_TOTAL_IDX] as usize;
        let seg_rem = packet[SEGMENT_REMAINDER_IDX] as usize;

        if seg_no >= seg_total || seg_rem >= seg_total {
            return Invalid;
        }

        if seg_total <= 1 {
            return NotSegmented;
        }

        let packet_common_len = packet.len() - MESSAGE_CRYPTO_START - (seg_no < seg_rem) as usize;
        let message_len = seg_total * packet_common_len + seg_rem + MESSAGE_CRYPTO_START;

        let mut message = Vec::with_capacity(message_len);
        message.extend_from_slice(&packet[..MESSAGE_CRYPTO_START]);
        message[SEGMENT_NO_IDX] = 0;

        for i in 0..seg_total {
            if i == seg_no {
                message.extend_from_slice(&packet[MESSAGE_CRYPTO_START..]);
            } else if i < seg_no {
                message.extend((0..(packet_common_len + 1)).map(|_| 0u8));
            } else {
                message.extend((0..packet_common_len).map(|_| 0u8));
            }
        }

        FirstRecvResult::Segmented(Desegmentation { message: message.into_boxed_slice(), seg_total, seg_rem })
    }

    pub fn recv(&self, packet: &[u8]) -> RecvResult {
        use RecvResult::*;

        if packet.len() <= MESSAGE_CRYPTO_START {
            return Invalid;
        }
        let seg_no = packet[SEGMENT_NO_IDX] as usize;
        let seg_total = packet[SEGMENT_TOTAL_IDX] as usize;
        let seg_rem = packet[SEGMENT_REMAINDER_IDX] as usize;

        if seg_total != self.seg_total || seg_rem != self.seg_rem || seg_no >= seg_total {
            return Invalid;
        }


    }

    pub fn complete(self) -> Box<u8> {

    }
}
