use std::sync::Arc;

use crate::messages::{*, shared::*};

#[derive(Default)]
pub struct Desegmenter {
    message_opt: Option<Box<[u8]>>,
    seg_completed: [u32; 8],
    seg_total: u32,
    seg_rem_len: u32,
    seg_min_len: usize,
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
        let seg_rem_len = packet[SEGMENT_REMAINDER_IDX] as u32;
        let seg_min_len = packet.len() - header_len - (seg_no < seg_rem_len) as usize;

        if seg_no >= seg_total {
            return RecvResult::Invalid;
        }

        let message = if let Some(message) = &mut self.message_opt {
            if seg_total != self.seg_total || seg_rem_len != self.seg_rem_len || seg_min_len != self.seg_min_len {
                return RecvResult::Invalid;
            }

            message
        } else if self.seg_total == 0 {
            if seg_total == 0 || seg_rem_len >= seg_total {
                return RecvResult::Invalid;
            }
            if seg_total == 1 {
                return RecvResult::NotSegmented;
            }

            let message_len = seg_min_len * seg_total as usize + seg_rem_len as usize + header_len;
            if message_len > maximum_len {
                return RecvResult::Invalid;
            }

            self.seg_total = seg_total;
            self.seg_rem_len = seg_rem_len;
            self.seg_min_len = seg_min_len;

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

        let i = self.seg_min_len * seg_no as usize + self.seg_rem_len.min(seg_no) as usize + header_len;
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

#[derive(Clone, Debug)]
pub struct Segmenter {
    message: Arc<[u8]>,
    packet_min_len: usize,
}


#[derive(Clone, Debug)]
pub struct SegmentIter<'a> {
    message: &'a [u8],
    packet_min_len: usize,
}

impl Segmenter {
    /// Computes the segment total, the segment remainder length and the final length of the message
    /// when it is segmented into packets.
    ///
    /// It is assumed that `message_len` includes the length of a header conforming to the
    /// "SEGMENTATION HEADER DEFINITION" defined in module `shared`.
    ///
    /// This function will return `None` in the event that it is not possible to segment this message
    /// into packets that fit within the given `mtu`.
    /// This function will return `None` if `message.len() < header_len`.
    ///
    /// # Panics
    /// This function will panic if `header_len < shared::SEGMENT_HEADER_END`,
    /// or if `message.len() < header_len`.
    pub fn precalc(message_len: usize, header_len: usize, mtu: Mtu) -> (u8, u8, usize) {
        assert!(header_len >= SEGMENT_HEADER_END, "nonconforming header length");

        let mtu = mtu.get() as usize;

        // `inner_mtu` cannot be 0 or less.
        let inner_mtu = mtu - header_len;
        let inner_message_len = message_len.strict_sub(header_len);

        let seg_total = inner_message_len.div_ceil(inner_mtu).max(1);
        debug_assert!(seg_total <= u8::MAX as usize);

        let seg_rem_len = inner_message_len % seg_total;

        let message_final_len = inner_message_len + header_len * seg_total;
        (seg_rem_len as u8, seg_total as u8, message_final_len)
    }

    /// Creates a `Segmenter` that iterates over the given `message` broken up into packets that at most
    /// `mtu` in length. Each of these packets contains a header of `header_len`, and a segment of
    /// `message`. This segmentation scheme is deterministic and allows a `Desegmenter` to
    /// reconstruct the original message after receiving all packets from the return value `Segmenter`
    ///
    /// It is assumed that `message` begins with a header conforming to the
    /// "SEGMENTATION HEADER DEFINITION" defined in module `shared`. This header
    /// will be the template for each packet's header.
    ///
    /// # Panics
    /// This function will panic if `header_len < shared::SEGMENT_HEADER_END`,
    /// or if `message.len() < header_len`.
    pub(crate) fn new(mut message: Vec<u8>, header_len: usize, mtu: Mtu) -> Segmenter {
        use shared::*;
        assert!(header_len >= SEGMENT_HEADER_END, "nonconforming header length");

        let message_len = message.len();
        let mtu = mtu.get() as usize;
        // `inner_mtu` cannot be 0 or less.
        let inner_mtu = mtu - header_len;
        let inner_message_len = message_len - header_len;

        let seg_total = inner_message_len.div_ceil(inner_mtu).max(1);
        debug_assert!(seg_total <= u8::MAX as usize);

        let seg_min_len = inner_message_len / seg_total;
        let seg_rem_len = inner_message_len % seg_total;

        let packet_min_len = seg_min_len + header_len;
        let message_final_len = inner_message_len + header_len * seg_total;
        debug_assert_eq!(message_final_len, packet_min_len * seg_total + seg_rem_len, "segmentation length incorrect");
        debug_assert!(packet_min_len <= mtu, "segmentation length incorrect");

        message.resize(message_final_len, 0);

        // Iterate over the message backwards so that a header can be prepended to each segment of the
        // message without destroying other segments of the message.
        let mut cur_packet_end = message_final_len;
        let mut cur_seg_end = message_len;
        let mut i = seg_total - 1;
        loop {
            let cur_seg_len = seg_min_len + (i < seg_rem_len) as usize;
            let cur_seg_start = cur_seg_end - cur_seg_len;
            let cur_packet_len = cur_seg_len + header_len;
            let cur_packet_start = cur_packet_end - cur_packet_len;

            // This message segment has been located, and now must move it forwards to fit its header.
            message.copy_within(cur_seg_start..cur_seg_end, cur_packet_start + header_len);

            /* START OF SEGMENT HEADER CONSTRUCTION */

            message[SEGMENT_NO_IDX] = i as u8;
            message[SEGMENT_REMAINDER_IDX] = seg_rem_len as u8;
            message[SEGMENT_TOTAL_IDX] = seg_total as u8;
            message.copy_within(..header_len, cur_packet_start);

            if i <= 0 {
                debug_assert_eq!(cur_packet_start, 0);
                debug_assert_eq!(cur_seg_start, header_len);
                return Segmenter { message: message.into(), packet_min_len };
            } else {
                debug_assert!(cur_packet_start >= cur_seg_start, "header overwrite");
                cur_packet_end = cur_packet_start;
                cur_seg_end = cur_seg_start;
                i -= 1;
            }
        }
    }
}

impl<'a> IntoIterator for &'a Segmenter {
    type Item = &'a [u8];

    type IntoIter = SegmentIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SegmentIter {
            message: &self.message,
            packet_min_len: self.packet_min_len,
        }
    }
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.message.is_empty() {
            return None;
        }

        let seg_rem_len = self.message[SEGMENT_REMAINDER_IDX] as usize;
        let seg_no = self.message[SEGMENT_NO_IDX] as usize;
        let len = self.packet_min_len + (seg_no < seg_rem_len) as usize;
        let ret;
        (ret, self.message) = self.message.split_at(len);
        Some(ret)
    }
}

impl<'a> ExactSizeIterator for SegmentIter<'a> {
    fn len(&self) -> usize {
        self.message.len() / self.packet_min_len
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Hash)]
pub struct Mtu(u32);

impl Mtu {
    // Right now the `reply` message is the longest, so the smallest allowable MTU must be exactly
    // enough to segment the `reply` message. If a different message becomes the longest,
    // this constant must be changed.
    /// This constant is the minimum MTU that can be supported by this protocol.
    /// This constant may increase in future versions of this protocol.
    pub const MIN_ALLOWED_MTU: u32 = ((reply::MESSAGE_LEN - reply::HEADER_LEN).div_ceil(u8::MAX as usize) + reply::HEADER_LEN) as u32;

    pub fn new(mtu: u32) -> Option<Self> {
        (mtu >= Self::MIN_ALLOWED_MTU).then_some(Self(mtu))
    }

    pub unsafe fn new_unchecked(mtu: u32) -> Self {
        Self(mtu)
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}
