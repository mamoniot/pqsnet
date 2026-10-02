use std::ops::Range;

use psqnet_transport::crypto::mem::Mem;

use crate::varint::*;

pub struct Desegmenter<M: Mem> {
    mem: M,
}

pub enum NewResult<M: Mem> {
    Segmented(Desegmenter<M>),
    SingleSeg(Range<usize>),
    MissingLen,
    AllocFailure,
    Invalid,
}

pub enum SegError {
    Segmented,
    Invalid,
}

/// Message Segment {
/// [Message length (i)],
/// [Segment offset (i)],
/// [Segment length (i)],
/// Segment data (..)
/// }
impl<M: Mem> Desegmenter<M> {
    #[inline]
    fn read_header(packet: &[u8], idx: &mut usize, has_len: bool, has_off: bool, is_terminator: bool) -> Option<(usize, usize, Option<usize>)> {
        let message_len = if has_len {
            Some(varusize_try_read(packet, idx)?)
        } else {
            None
        };

        let off = if has_off {
            varusize_try_read(packet, idx)?
        } else {
            0
        };

        let seg_len = if is_terminator {
            packet.len() - *idx
        } else {
            varusize_try_read(packet, idx)?
        };

        let seg_end = off.checked_add(seg_len)?;

        if let Some(message_len) = message_len && seg_end > message_len {
            return None
        }

        Some((off, seg_len, message_len))
    }

    pub fn try_single_seg(packet: &[u8], idx: &mut usize, has_len: bool, has_off: bool, is_terminator: bool) -> Result<Range<usize>, SegError> {
        let (_, seg_len, message_len) = Self::read_header(packet, idx, has_len, has_off, is_terminator).ok_or(SegError::Invalid)?;

        if let Some(message_len) = message_len && seg_len == message_len {
            let j = *idx + seg_len;
            let ret = *idx..j;
            *idx = j;
            Ok(ret)
        } else {
            Err(SegError::Segmented)
        }
    }

    fn recv_mut_inner(&mut self, packet: &[u8], idx: &mut usize, off: usize, seg_len: usize) -> Result<Vec<u8>, SegError> {
        todo!()
    }

    pub fn try_new(packet: &[u8], idx: &mut usize, has_len: bool, has_off: bool, is_terminator: bool, alloc: M::Alloc) -> NewResult<M> {
        let Some((off, seg_len, message_len)) = Self::read_header(packet, idx, has_len, has_off, is_terminator) else {
            return NewResult::Invalid;
        };

        if let Some(message_len) = message_len {
            if seg_len == message_len {
                let j = *idx + seg_len;
                let ret = *idx..j;
                *idx = j;
                NewResult::SingleSeg(ret)
            } else {
                let Some(mem) = M::malloc(alloc, message_len) else {
                    return NewResult::AllocFailure;
                };
                let mut ret = Self {
                    mem,
                };
                ret.recv_mut_inner(packet, idx, off, seg_len);
                NewResult::Segmented(ret)
            }
        } else {
            NewResult::MissingLen
        }
    }

    pub fn recv(&self, packet: &[u8], idx: &mut usize, has_len: bool, has_off: bool, is_terminator: bool) -> Result<Vec<u8>, SegError> {
        todo!()
    }

    pub fn recv_mut(&mut self, packet: &[u8], idx: &mut usize, has_len: bool, has_off: bool, is_terminator: bool) -> Result<Vec<u8>, SegError> {
        let (off, seg_len, message_len) = Self::read_header(packet, idx, has_len, has_off, is_terminator).ok_or(SegError::Invalid)?;

        if let Some(message_len) = message_len && message_len != self.mem.len() {
            return Err(SegError::Invalid);
        }

        self.recv_mut_inner(packet, idx, off, seg_len)
    }
}
