use bytes::Bytes;
use smallvec::SmallVec;

use crate::{
    protocol::*,
    session::{DocNo, SendDoc},
    varint::*,
};

pub struct PacketBuilder {
    pub buf: Vec<u8>,
    pub segments: SmallVec<[Segment; 2]>,
    pub plpmtu: usize,
    has_resend_of: SmallVec<[u64; 2]>,
}

#[derive(Default)]
pub struct Segment {
    variant_and_header_len: usize,
    doc_no: DocNo,
    doc_len: usize,
    doc_parent_no: u64,
    seg_off: usize,
    data: Bytes,
}

impl Segment {
    pub fn try_new(doc_no: DocNo, doc: &mut SendDoc, is_closed: bool, remaining_cap: usize) -> Result<Self, bool> {
        if doc.next_seg_off >= doc.data.len() {
            return Err(false);
        }

        let seg_off = doc.next_seg_off;
        let total_left = doc.data.len() - seg_off;

        let mut variant = is_closed as u8 * VARIANT_SEG_FLAG_IS_CLOSED;
        let mut header_len = 1 + varu64_len(doc_no);

        if seg_off == 0 {
            variant |= VARIANT_SEG_FLAG_IS_FIRST;
            variant |= doc.has_special_parent as u8 * VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT;
            header_len += varu64_len(doc.parent_no);

            if header_len.saturating_add(doc.data.len()) <= remaining_cap {
                variant |= VARIANT_SEG_FLAG_IS_SINGLE_SEG;
                doc.next_seg_off = doc.data.len();
                return Ok(Segment {
                    variant_and_header_len: variant as usize | header_len << 8,
                    doc_no,
                    doc_len: doc.data.len(),
                    doc_parent_no: doc.parent_no,
                    seg_off,
                    data: doc.data.clone(),
                });
            }
        } else {
            if !doc.has_been_acked && doc.has_special_parent {
                variant |= VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT;
                header_len += varu64_len(doc.parent_no);
            }
            header_len += varusize_len(seg_off);
        }
        if !doc.has_been_acked {
            variant |= VARIANT_SEG_FLAG_HAS_DOC_LEN;
            header_len += varusize_len(doc.data.len());
        }

        if header_len + MIN_SEG_DATA_LEN > remaining_cap {
            return Err(true);
        }
        let seg_len = total_left.min(remaining_cap - header_len);
        doc.next_seg_off += seg_len;
        Ok(Segment {
            variant_and_header_len: variant as usize | header_len << 8,
            doc_no,
            doc_len: doc.data.len(),
            doc_parent_no: doc.parent_no,
            seg_off,
            data: doc.data.slice(seg_off..doc.next_seg_off),
        })
    }
}

impl PacketBuilder {
    pub fn new(plpmtu: usize) -> Self {
        Self {
            buf: Vec::with_capacity(plpmtu),
            segments: SmallVec::new(),
            plpmtu,
            has_resend_of: SmallVec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn remaining_cap(&self) -> usize {
        self.plpmtu - self.buf.len()
    }

    pub fn append_seg(&mut self, seg: Segment) -> bool {
        let seg_len = seg.data.len();
        let frame_min_len = seg.data.len() + (seg.variant_and_header_len >> 8);
        let variant = seg.variant_and_header_len as u8;
        let data_cap = self.remaining_cap();
        debug_assert!(seg_len <= data_cap);

        let variant_idx = self.buf.len();
        self.buf.push(variant);

        let has_special_parent = variant & VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT > 0;
        let has_doc_len = variant & VARIANT_SEG_FLAG_HAS_DOC_LEN > 0;
        let is_first_segment = variant & VARIANT_SEG_FLAG_IS_FIRST > 0;

        varu64_write(&mut self.buf, seg.doc_no);
        if has_doc_len {
            varusize_write(&mut self.buf, seg.doc_len);
        }
        if has_special_parent || is_first_segment {
            varu64_write(&mut self.buf, seg.doc_parent_no);
        }
        if !is_first_segment {
            varusize_write(&mut self.buf, seg.seg_off);
        }

        // We need to add `seg_len` bytes to this frame.
        if frame_min_len == data_cap {
            // This segment is exactly the length of the remaining space in this packet,
            // so mark this frame as a packet terminator and append the entire segment.
            self.buf[variant_idx] |= VARIANT_SEG_IS_TERMINATOR;
            self.buf.extend_from_slice(&seg.data);
        } else if frame_min_len + varusize_len(seg_len) <= data_cap {
            // This segment will fit in this packet as a normal segment frame,
            // so append the segment length and then the segment.
            self.buf[variant_idx] |= VARIANT_SEG_HAS_LEN;
            varusize_write(&mut self.buf, seg_len);
            self.buf.extend_from_slice(&seg.data);
        } else {
            // This segment has an awkward size. It will not fill the entire packet,
            // but we cannot append it as a normal segment since then the packet
            // would overflow the plpmtu. So we mark this frame as a packet
            // terminator and place byte padding at the end of the segment.
            self.buf[variant_idx] |= VARIANT_SEG_HAS_TERMINATOR;
            self.buf.extend_from_slice(&seg.data);
            debug_assert!(self.remaining_cap() > 0);
            self.buf.push(VARIANT_NULL_TERMINATOR);
            for _ in 0..self.remaining_cap() {
                self.buf.push(VARIANT_PADDING);
            }
        }
        self.segments.push(seg);
        self.remaining_cap() < MIN_FRAME_APPEND_LEN
    }

    pub fn append_control(&mut self, variant: u8, doc_no: DocNo) -> bool {
        self.buf.push(variant);
        varu64_write(&mut self.buf, doc_no);
        self.remaining_cap() < MIN_FRAME_APPEND_LEN
    }
}
