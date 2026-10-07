use std::{
    cell::UnsafeCell,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use psqnet_transport::crypto::mem::Mem;

use crate::varint::*;

const WIDTH: usize = usize::BITS as usize;

pub struct Desegmenter<M: Mem> {
    mem: UnsafeCell<Option<M>>,
    len: usize,
    total_set: AtomicUsize,
    /// A bit-set array which is written to in little endian order.
    set_segs: Vec<AtomicUsize>,
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

impl<M: Mem> Desegmenter<M> {
    /// This function only runs `f` on ranges of bytes that are contained in the current segment and
    /// are not yet set in `self.mem`. It will also atomically mark those bytes as set.
    /// This guarantees that between multiple threads, `f` will always be passed mutually-exclusive,
    /// non-overlapping ranges of bytes of the full message.
    ///
    /// If `start` is set to `Some`, the current range may overrun into the next index of `set_segs`,
    /// that range on index `idx` will be marked as set, but not have been passed to `f`.
    /// Subsequent calls to `check_and_set_bits` will correctly use argument `start` to aggregate
    /// ranges that span more than one index into one call to `f`.
    fn check_and_set_bits(
        &self,
        idx: usize,
        seg_bits: usize,
        start: &mut Option<usize>,
        f: &mut impl FnMut(Range<usize>),
    ) {
        // If `f` is only called on non-overlapping ranges,
        // writes to `self.mem` will never be overlapping.
        // If `f` is only called on non-overlapping ranges (and no range overflows `self.len`),
        // `self.total_set` can only atomically sum to `self.len` exactly once.
        // Since `self.total_set` is summed with `AcqRel` ordering, all writes to `self.mem` will
        // be visible to the one thread which summed `self.total_set` to `self.len`.
        // `Relaxed` ordering is sufficient to guarantee that `f` is only called on non-overlapping
        // ranges. Therefore this `fetch_or` can have `Relaxed` ordering.
        let pre_bits = self.set_segs[idx].fetch_or(seg_bits, Ordering::Relaxed);
        let base = idx * WIDTH;

        let mut set_bits = !pre_bits & seg_bits;

        while let Some(i) = set_bits.lowest_one().map(|i| i as usize) {
            // This utilizes carries to count set ranges.
            let carried_bits = set_bits.wrapping_add(1 << i);
            if let Some(j) = carried_bits.lowest_one().map(|i| i as usize) {
                set_bits &= usize::MAX << j;
                if i == 0 {
                    let cur_start = start.take().unwrap_or(base);
                    f(cur_start..base + j);
                } else {
                    if let Some(start) = start.take() {
                        f(start..base);
                    }
                    f(base + i..base + j);
                }
            } else {
                if i == 0 {
                    start.get_or_insert(base);
                } else {
                    if let Some(start) = start.take() {
                        f(start..base);
                    }
                    *start = Some(base + i);
                }
                break;
            }
        }
    }

    fn run_over_unset_ranges(&self, range: Range<usize>, mut f: impl FnMut(Range<usize>)) {
        debug_assert!(range.end <= self.len);

        let seg_off_idx = range.start / WIDTH;
        let seg_off_rem = range.start % WIDTH;
        let seg_end_idx = (range.end - 1) / WIDTH;
        let seg_end_rem = (range.end - 1) % WIDTH;

        let seg_off_set = usize::MAX << seg_off_rem;
        let seg_end_set = usize::MAX >> (WIDTH - seg_end_rem - 1);

        let mut start = None;
        if seg_off_idx == seg_end_idx {
            self.check_and_set_bits(seg_off_idx, seg_off_set & seg_end_set, &mut start, &mut f);
        } else {
            self.check_and_set_bits(seg_off_idx, seg_off_set, &mut start, &mut f);

            for k in seg_off_idx + 1..seg_end_idx - 1 {
                self.check_and_set_bits(k, usize::MAX, &mut start, &mut f);
            }

            self.check_and_set_bits(seg_end_idx, seg_end_set, &mut start, &mut f);
        }

        if let Some(start) = start {
            f(start..range.end)
        }
    }

    fn recv_inner(&self, packet: &[u8], idx: &mut usize, off: usize, seg_len: usize) -> Option<M> {
        let mut cur_total_set = 0;
        self.run_over_unset_ranges(off..off + seg_len, |r| {
            let mem = unsafe { (&mut *self.mem.get()).as_deref_mut().unwrap_unchecked() };
            mem[r.clone()].copy_from_slice(&packet[*idx + r.start - off..*idx + r.end - off]);

            cur_total_set += r.end - r.start;
        });

        *idx += seg_len;

        // `AcqRel` is the correct ordering, it guarantees that the lucky thread which finishes
        // desegmentation will see all writes to `self.mem` as those writes are always ordered
        // before this `fetch_add`.
        let pre_total_set = self.total_set.fetch_add(cur_total_set, Ordering::AcqRel);
        if cur_total_set > 0 && pre_total_set + cur_total_set == self.len {
            Some(unsafe { (&mut *self.mem.get()).take().unwrap_unchecked() })
        } else {
            None
        }
    }

    fn recv_mut_inner(&mut self, packet: &[u8], idx: &mut usize, off: usize, seg_len: usize) -> Option<M> {
        self.recv_inner(packet, idx, off, seg_len)
    }

    /// Message Segment {
    /// [Message length (i)],
    /// [Segment offset (i)],
    /// [Segment length (i)],
    /// Segment data (..)
    /// }
    /// If this function returns `Some` then `idx` will be set to the start of the data section of
    /// the current segment within this packet.
    /// If this function returns `None` then `idx` may have been incremented by any amount such that
    /// `*idx <= packet.len()`.
    ///
    /// This function guarantees that its return values cannot cause arithmetic or buffer overflow
    /// when used as intended.
    #[inline]
    fn read_header(
        packet: &[u8],
        idx: &mut usize,
        has_len: bool,
        has_off: bool,
        is_terminator: bool,
    ) -> Option<(usize, usize, Option<usize>)> {
        let message_len = if has_len {
            Some(varusize_try_read(packet, idx)?)
        } else {
            None
        };

        let off = if has_off { varusize_try_read(packet, idx)? } else { 0 };

        let rem_len = packet.len() - *idx;
        let seg_len;
        if is_terminator {
            seg_len = rem_len
        } else {
            seg_len = varusize_try_read(packet, idx)?;
            if seg_len > rem_len {
                return None;
            }
        }

        let seg_end = off.checked_add(seg_len)?;

        if let Some(message_len) = message_len
            && seg_end > message_len
        {
            return None;
        }

        Some((off, seg_len, message_len))
    }

    pub fn recv(
        &self,
        packet: &[u8],
        idx: &mut usize,
        has_len: bool,
        has_off: bool,
        is_terminator: bool,
    ) -> Result<M, SegError> {
        let (off, seg_len, message_len) =
            Self::read_header(packet, idx, has_len, has_off, is_terminator).ok_or(SegError::Invalid)?;

        if let Some(message_len) = message_len
            && message_len != self.len
        {
            return Err(SegError::Invalid);
        }

        self.recv_inner(packet, idx, off, seg_len).ok_or(SegError::Segmented)
    }

    pub fn recv_mut(
        &mut self,
        packet: &[u8],
        idx: &mut usize,
        has_len: bool,
        has_off: bool,
        is_terminator: bool,
    ) -> Result<M, SegError> {
        let (off, seg_len, message_len) =
            Self::read_header(packet, idx, has_len, has_off, is_terminator).ok_or(SegError::Invalid)?;

        if let Some(message_len) = message_len
            && message_len != self.len
        {
            return Err(SegError::Invalid);
        }

        self.recv_mut_inner(packet, idx, off, seg_len)
            .ok_or(SegError::Segmented)
    }

    pub fn try_new(
        packet: &[u8],
        idx: &mut usize,
        has_len: bool,
        has_off: bool,
        is_terminator: bool,
        alloc: M::Alloc,
    ) -> NewResult<M> {
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
                debug_assert_eq!(mem.len(), message_len, "incorrect allocation length");

                let mut set_segs = Vec::new();
                set_segs.resize_with(mem.len().div_ceil(WIDTH), || AtomicUsize::new(0));
                let mut ret = Self {
                    mem: UnsafeCell::new(Some(mem)),
                    len: message_len,
                    total_set: AtomicUsize::new(0),
                    set_segs,
                };

                let _a = ret.recv_mut_inner(packet, idx, off, seg_len);
                debug_assert!(_a.is_none());

                NewResult::Segmented(ret)
            }
        } else {
            NewResult::MissingLen
        }
    }

    pub fn try_single_seg(
        packet: &[u8],
        idx: &mut usize,
        has_len: bool,
        has_off: bool,
        is_terminator: bool,
    ) -> Result<Range<usize>, SegError> {
        let (_, seg_len, message_len) =
            Self::read_header(packet, idx, has_len, has_off, is_terminator).ok_or(SegError::Invalid)?;

        if let Some(message_len) = message_len
            && seg_len == message_len
        {
            let j = *idx + seg_len;
            let ret = *idx..j;
            *idx = j;
            Ok(ret)
        } else {
            Err(SegError::Segmented)
        }
    }
}
