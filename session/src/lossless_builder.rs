use bytes::Bytes;
use tinyvec::ArrayVec;

use crate::{protocol::*, session::DocNo, varint::*};

pub type Header = ArrayVec<[u8; MAX_DOC_HEADER_LEN]>;

pub struct LosslessBuilder {
    pub buf: Vec<u8>,
    pub segments: ArrayVec<[Segment; 2]>,
    pub plpmtu: usize,
}

#[derive(Default)]
pub struct Segment {
    pub resend_of_id: Option<u64>,
    pub doc_no: DocNo,
    pub seg_no: usize,
    pub header: Header,
    pub data: Bytes,
}

impl LosslessBuilder {
    pub fn new(plpmtu: usize) -> Self {
        Self {
            buf: Vec::with_capacity(plpmtu),
            segments: ArrayVec::new(),
            plpmtu,
        }
    }
    pub fn final_len(&self) -> usize {
        self.buf.len() + FOOTER_LEN
    }
    pub fn is_full(&self) -> bool {
        self.remaining_cap() <= MIN_FRAME_APPEND_LEN
    }
    pub fn remaining_cap(&self) -> usize {
        self.plpmtu - self.final_len()
    }

    pub fn append_doc(&mut self, doc_no: DocNo, seg_no: usize, seg_len: usize, header: &Header, data: &Bytes) {
        let seg_end = seg_no + seg_len;

        let seg_header;
        let seg_data;
        if let Some(i) = seg_no.checked_sub(header.len()) {
            seg_header = ArrayVec::new();
            seg_data = data.slice(i..seg_end - header.len());
        } else if let Some(i) = seg_end.checked_sub(header.len()) {
            seg_header = header.clone();
            seg_data = data.slice(..i);
        } else {
            seg_header = header.clone();
            seg_data = Bytes::new();
        }
        let segment = Segment {
            doc_no,
            seg_no,
            header: seg_header,
            data: seg_data,
            resend_of_id: None,
        };

        self.append_segment(segment);
    }

    pub fn append_segment(&mut self, seg: Segment) {
        let seg_len = seg.data.len() + seg.header.len();
        let data_cap = self.remaining_cap();
        debug_assert!(seg_len <= data_cap);

        // We need to add `seg_len` bytes to this frame.
        if seg_len == data_cap {
            // This segment is exactly the length of the remaining space in this packet,
            // so mark this frame as a packet terminator and append the entire segment.
            self.buf.push(VARIANT_SEGMENT_IS_TERMINATOR);
            self.buf.extend_from_slice(&seg.header);
            self.buf.extend_from_slice(&seg.data);
        } else if varusize_len(seg_len) + seg_len <= data_cap {
            // This segment will fit in this packet as a normal segment frame,
            // so append the segment length and then the segment.
            self.buf.push(VARIANT_SEGMENT);
            varusize_write(&mut self.buf, seg_len);
            self.buf.extend_from_slice(&seg.header);
            self.buf.extend_from_slice(&seg.data);
        } else {
            // This segment has an awkward size. It will not fill the entire packet,
            // but we cannot append it as a normal segment since then the packet
            // would overflow the plpmtu. So we mark this frame as a packet
            // terminator and place byte padding at the end of the segment.
            self.buf.push(VARIANT_SEGMENT_HAS_TERMINATOR);
            self.buf.extend_from_slice(&seg.header);
            self.buf.extend_from_slice(&seg.data);
            debug_assert!(self.remaining_cap() > 0);
            self.buf.push(VARIANT_NULL_TERMINATOR);
            for _ in 0..self.remaining_cap() {
                self.buf.push(VARIANT_PADDING);
            }
        }
        self.segments.push(seg);
    }

    pub fn try_append_segment(&mut self, mut seg: Segment) -> Option<Segment> {
        let seg_len = seg.data.len() + seg.header.len();
        let data_cap = self.remaining_cap();
        let mut ret = None;

        if let Some(seg_overflow) = seg_len.checked_sub(data_cap) {
            if let Some(header_overflow) = seg.header.len().checked_sub(seg_overflow) {
                ret = Some(Segment {
                    doc_no: seg.doc_no,
                    seg_no: seg.seg_no + seg_overflow,
                    header: seg.header.split_off(header_overflow),
                    data: seg.data.split_off(0),
                    // It is important that `resend_of_id` is unique and not duplicated due to how
                    // lost packet detection and congestion window recovery logic are structured.
                    resend_of_id: None,
                });
            } else {
                ret = Some(Segment {
                    doc_no: seg.doc_no,
                    seg_no: seg.seg_no + seg_overflow,
                    header: ArrayVec::new(),
                    data: seg.data.split_off(seg_overflow - seg.header.len()),
                    resend_of_id: None,
                });
            }
        }

        self.append_segment(seg);
        ret
    }
}
