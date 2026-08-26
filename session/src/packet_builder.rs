use bytes::Bytes;
use smallvec::SmallVec;

use crate::{
    ack_runs::encode, protocol::*, send::SentPayload, session::{DocNo, Route, SendDoc, Session}, varint::*,
};

pub struct Segment {
    /// The variant is the bottom 8 bits and the header length is the rest.
    /// This saves a bit of space compared to storing them separately (TODO: test this optimization).
    variant_and_header_len: usize,
    doc_no: DocNo,
    doc_len: usize,
    doc_parent_no: u64,
    off: usize,
    data: Bytes,
}

pub enum ElicitingFrame {
    Seg(Segment),
    Control(u8, DocNo),
}

pub struct PacketBuilder {
    mtu: u32,
    socket_binding: Option<(bool, u32)>,
    buf: Vec<u8>,
    resend_len: u32,
    eliciting_frames: SmallVec<[ElicitingFrame; 2]>,
}

impl Segment {
    pub(crate) fn try_new(doc_no: DocNo, doc: &mut SendDoc, is_closed: bool, remaining_cap: usize) -> Result<Self, bool> {
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
                    off: seg_off,
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
            off: seg_off,
            data: doc.data.slice(seg_off..doc.next_seg_off),
        })
    }
}

impl PacketBuilder {
    pub fn new(mtu: u32) -> Self {
        let mut buf = Vec::with_capacity(mtu as usize);
        buf.resize(HEADER_LEN, 0);
        Self {
            socket_binding: None,
            buf,
            mtu,
            resend_len: 0,
            eliciting_frames: SmallVec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.remaining_cap() < MIN_FRAME_APPEND_LEN
    }

    pub fn remaining_cap(&self) -> usize {
        self.mtu as usize - self.buf.len()
    }

    /// This function trusts that `seg` will fit in the packet.
    pub fn append_seg(&mut self, seg: Segment) -> bool {
        let variant = seg.variant_and_header_len as u8;

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
            varusize_write(&mut self.buf, seg.off);
        }
        debug_assert_eq!(seg.variant_and_header_len >> 8, self.buf.len() - variant_idx);

        let seg_len = seg.data.len();
        let data_cap = self.remaining_cap();
        // We need to add `seg_len` bytes to this frame.
        if seg_len == data_cap {
            // This segment is exactly the length of the remaining space in this packet,
            // so mark this frame as a packet terminator and append the entire segment.
            self.buf[variant_idx] |= VARIANT_SEG_IS_TERMINATOR;
            self.buf.extend_from_slice(&seg.data);
        } else if seg_len + varusize_len(seg_len) <= data_cap {
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
        self.resend_len += (self.buf.len() - variant_idx) as u32;
        self.eliciting_frames.push(ElicitingFrame::Seg(seg));
        self.is_full()
    }

    pub fn try_append_seg(&mut self, mut seg: Segment) -> (bool, Option<Segment>) {
        let mut variant = seg.variant_and_header_len as u8;
        let mut header_len = seg.variant_and_header_len >> 8;
        let data_cap = self.remaining_cap();

        if header_len + MIN_SEG_DATA_LEN > data_cap {
            return (true, Some(seg));
        }

        let mut ret = None;

        if header_len + seg.data.len() > data_cap {
            // `seg` is too large so truncate it and return the remainder to be sent separately.
            if variant & VARIANT_SEG_FLAG_IS_SINGLE_SEG > 0 {
                variant &= !VARIANT_SEG_FLAG_IS_SINGLE_SEG;

                if variant & VARIANT_SEG_FLAG_HAS_DOC_LEN == 0 {
                    variant |= VARIANT_SEG_FLAG_HAS_DOC_LEN;
                    header_len += varusize_len(seg.doc_len);
                }
                if header_len + MIN_SEG_DATA_LEN > data_cap {
                    // No modifications have been committed to `seg` at this point.
                    return (true, Some(seg));
                }
            }

            let mut new_variant = variant;
            let mut new_header_len = header_len;
            let split_idx = data_cap - header_len;
            let new_off = seg.off + split_idx;

            if variant & VARIANT_SEG_FLAG_IS_FIRST > 0 {
                new_variant &= !VARIANT_SEG_FLAG_IS_FIRST;
                new_header_len += varusize_len(new_off);
                if variant & VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT == 0 {
                    new_header_len -= varu64_len(seg.doc_parent_no);
                }
            }

            seg.variant_and_header_len = variant as usize | header_len << 8;
            ret = Some(Segment {
                variant_and_header_len: new_variant as usize | new_header_len << 8,
                doc_no: seg.doc_no,
                doc_len: seg.doc_len,
                doc_parent_no: seg.doc_parent_no,
                off: new_off,
                data: seg.data.split_off(split_idx),
            });
        }

        self.append_seg(seg);
        (self.is_full(), ret)
    }

    /// May panic if the packet has less than `MIN_FRAME_APPEND_LEN` remaining capacity.
    pub fn append_control(&mut self, variant: u8, doc_no: DocNo) -> bool {
        let i = self.buf.len();
        self.buf.push(variant);
        varu64_write(&mut self.buf, doc_no);

        self.resend_len += (self.buf.len() - i) as u32;
        self.eliciting_frames.push(ElicitingFrame::Control(variant, doc_no));
        self.is_full()
    }

    /// May panic if the packet has less than `MIN_FRAME_APPEND_LEN` remaining capacity.
    pub fn append_sorted_acks(&mut self, acks: &mut Vec<u32>, socket_idx: bool, socket_uid: u32) -> bool {
        let total_written = encode(&mut self.buf, &acks[..], self.mtu as usize);
        if total_written > 0 {
            acks.drain(..total_written);
            self.socket_binding = Some((socket_idx, socket_uid));
        }
        self.is_full()
    }
}

impl<R: Route> Session<R> {
    pub(crate) fn send_now(&self, mut packet: PacketBuilder, now: f64) {
    // TODO: This function needs to be retouched.
        // Make space for the footer (auth tag).
        packet.buf.extend_from_slice(&[0; FOOTER_LEN]);

        self.congestion_control.sending(packet.buf.len() as u32, now);

        let open_sockets = self.open_sockets.read().unwrap();
        let packet_uid = if let Some((socket_idx, socket_uid)) = packet.socket_binding {
            let socket = &open_sockets.sockets[socket_idx as usize].socket;
            // There could be a race condition here where the socket we were bound to was replaced
            // with a new socket. Checking the uid prevents this. The uid could overflow but
            // sessions will be dropped too fast for one to be reused.
            if socket.uid == socket_uid {
                let packet_no = socket.encrypt_in_place(&mut packet.buf);
                packet_no as u64 | (socket_uid as u64) << 32
            } else {
                // This case is extremely unlikely, since it requires a different thread to spawn
                // work to send this packet on a socket that was dropped. This may be possible
                // from repeatedly sending packets with acks bound to an old socket, which is why
                // there is an age limit for sending ack eliciting frames on a packet with ack frames
                // bound to an old socket (TODO: implement this age limit). An adversary could cause
                // this case to happen but there is nothing for them to gain by that.
                // All we need from this id is that it is unique,
                // a random number will almost certainly be.
                rand::random()
            }
        } else {
            let socket = &open_sockets.sockets[open_sockets.cur_idx as usize].socket;
            let packet_no = socket.encrypt_in_place(&mut packet.buf);
            packet_no as u64 | (socket.uid as u64) << 32
        };

        self.transmissions.unacked_packets.insert(packet_uid);

        let payload = SentPayload {
            packet_uid,
            sent_at: now,
            eliciting_frames: packet.eliciting_frames,
            resend_len: packet.resend_len,
        };
        self.transmissions.packet_queue.lock().unwrap().push_back(payload);


        let _todo = self.route.send(&packet.buf[..]);
    }
}
