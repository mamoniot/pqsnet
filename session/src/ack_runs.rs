use crate::{protocol::*, varint::*};

/// [3, 5, 6] -> [3, 2, 1] -> [3, 0b0110]   -> [3u32, 1u8, 0 || 0, 0 || 1]
/// [3, 4, 6] -> [3, 1, 2] -> [3, 0b1010]   -> [3u32, 1u8, 0 || 1, 0 || 1]
/// [3, 4, 9] -> [3, 1, 5] -> [3, 0b100001] -> [3u32, 1u8, 0 || 1, 2 || 0]
/// [3, 5, 9] -> [3, 2, 5] -> [3, 0b010001] -> [3u32, 1u8, 0 || 0, 2 || 0]
/// [3, 4, 5, 6] -> [3, 1, 1, 1] -> [3, 0b1110]  -> [3u32, 0u8, 2 || 1]
/// [3, 4, 6, 7] -> [3, 1, 2, 1] -> [3, 0b10110] -> [3u32, 1u8, 0 || 1, 1 || 1]
///
/// [3, 0x80000000] => [3u32], [0x80000000u32]
/// [0, 2, 4, ..., 508, 510, 512] => [0u32, 255u8, 0 || 0, 0 || 0, ...]
/// [0, 2, 4, ..., 510, 512, 514] => [0u32, 255u8, 0 || 0, 0 || 0, ...], [514u32]
/// [0, 2, 4, ..., 512, 514, 516] => [0u32, 255u8, 0 || 0, 0 || 0, ...], [514u32, 0u8, 0 || 0]
/// [0, 1, 3, ..., 511, 513, 515] => [0u32, 255u8, 0 || 1, 0 || 1, ...], [513u32, 0u8, 0 || 0] 2i-1
/// [0, 1, 3, ..., 511, 512, 514] => [0u32, 255u8, 0 || 1, 0 || 1, ..., 1 || 1], [514u32]
/// [0, 2, 4, ..., 512, 513, 514, ..., 0x8200] => [0u32, 254u8, 0 || 0, 0 || 0, ...], [512u32, 3u8, 0x8000 || 1]
/// [0, 1, 3, ..., 511, 512, 513, ..., 0x8200] => [0u32, 254u8, 0 || 1, 0 || 1, ...], [511u32, 3u8, 0x8000 || 1]
/// [0, 1, 3, ..., 511, 512, 513, ..., 0x8200, 0x8202] => [0u32, 254u8, 0 || 1, 0 || 1, ...], [511u32, 4u8, 0x8000 || 1, 0 || 1]
pub fn encode(buf: &mut Vec<u8>, sorted_acks: &[u32], capacity: usize) -> usize {
    // OPTIMIZATION: we could have the length of long set ack runs that overflow a single ack run
    // carry over to the next ack run so those acks are not double counted.
    let mut i = 0;
    while i < sorted_acks.len() {
        let variant_idx = buf.len();
        let len_idx = variant_idx + 5;
        if len_idx > capacity {
            return i;
        }
        buf.push(VARIANT_ACK_RUN);
        buf.extend_from_slice(&sorted_acks[i].to_be_bytes());
        i += 1;

        if len_idx + 1 > capacity {
            buf[variant_idx] = VARIANT_ACK_SINGLE;
            return i;
        }
        debug_assert_eq!(len_idx, buf.len());
        buf.push(0);
        let max_len = capacity.min(buf.len() + u8::MAX as usize + 1);

        let mut cur_set_run_len: u32 = 0;
        while i < sorted_acks.len() {
            let mut diff = sorted_acks[i] - sorted_acks[i - 1];
            i += 1;

            if diff <= 1 {
                cur_set_run_len += 1;
                // This is the only place where the loop can break with `cur_set_run_len > 0`.
                continue;
            }
            if cur_set_run_len > 0 {
                let n = ((cur_set_run_len - 1) << 1) | 1;
                let new_len = buf.len() + varu32_len(n);
                if new_len > max_len {
                    i -= cur_set_run_len as usize + 1;
                    cur_set_run_len = 0;
                    break;
                }
                varu32_write(buf, n);
                cur_set_run_len = 0;
                if new_len == max_len {
                    // The cur set run is being terminated but there is no room left to encode which
                    // number terminated it. Decrement so it is encoded in the next ack run.
                    i -= 1;
                    break;
                }

                // By decrementing diff and rechecking it, we are presuming a single zero follows
                // the run of ones we just wrote. This reduces information redundancy.
                diff -= 1;
                if diff <= 1 {
                    cur_set_run_len += 1;
                    continue;
                }
            }

            let cur_unset_run_len = diff - 2;
            if cur_unset_run_len > VARINT_U32_MAX >> 1 {
                // The run length is so long here that it would have to be encoded as a 64 bit varint.
                // It is more space efficient to start a new ack run encoding instead.
                i -= 1;
                break;
            }

            let n = cur_unset_run_len << 1;
            let new_len = buf.len() + varu32_len(n);
            if new_len > max_len {
                i -= 1;
                break;
            }
            varu32_write(buf, n);
            if new_len == max_len {
                break;
            }
        }
        if cur_set_run_len > 0 {
            let n = ((cur_set_run_len - 1) << 1) | 1;
            let new_len = buf.len() + varu32_len(n);
            if new_len > max_len {
                i -= cur_set_run_len as usize;
            } else {
                varu32_write(buf, n);
            }
        }

        let run_total_len = buf.len() - len_idx;
        if run_total_len <= 1 {
            // The run didn't end up containing anything so erase it and mark it as a single ack.
            buf.pop();
            buf[variant_idx] = VARIANT_ACK_SINGLE;
        } else {
            // Reduce the length so we can encode runs of length up to 256 bytes long.
            buf[len_idx] = (run_total_len - 2) as u8;
        }
    }
    i
}

/// [3u32, 1u8, 0 || 0, 0 || 1] => [3, 5, 6]
/// [3u32, 1u8, 0 || 1, 0 || 1] => [3, 4, 6]
/// [3u32, 1u8, 0 || 1, 2 || 0] => [3, 4, 9]
/// [3u32, 1u8, 0 || 0, 2 || 0] => [3, 5, 9]
/// [3u32, 0u8, 3 || 1]         => [3, 4, 5, 6]
/// [3u32, 1u8, 1 || 1, 1 || 1] => [3, 4, 6, 7]
#[must_use]
pub fn decode(buf: &[u8], is_run: bool, i: &mut usize, mut f: impl FnMut(u32)) -> bool {
    // OPTIMIZATION: This can be made more efficient if we can acknowlegde packets in batches.
    if *i + 4 + is_run as usize > buf.len() {
        return false;
    }
    let first_ack_no = u32::from_be_bytes(buf[*i..*i + 4].try_into().unwrap());
    *i += 4;
    f(first_ack_no);
    if !is_run {
        return true;
    }

    let total_len = buf[*i] as usize + 1;
    *i += 1;
    let Some(buf) = buf.get(..*i + total_len) else {
        return false;
    };

    // `total_len` is untrusted so we guard against overflows.
    let mut cur_ack_no = first_ack_no;
    while *i < buf.len() {
        let Some(cur_run) = varu32_try_read(buf, i) else {
            return false;
        };
        let cur_run_len = cur_run >> 1;

        if cur_run & 1 > 0 {
            for _ in 0..=cur_run_len {
                cur_ack_no += 1;
                f(cur_ack_no);
            }
            // The final ack in this run must be absent. Skip it.
            cur_ack_no += 1;
        } else {
            cur_ack_no += cur_run_len + 2;
            f(cur_ack_no);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_decode(acks: &[u32]) {
        let mut enc_buf = Vec::new();
        let mut dec_buf = Vec::with_capacity(acks.len());

        assert_eq!(encode(&mut enc_buf, acks, usize::MAX), acks.len());
        let mut i = 0;
        while i < enc_buf.len() {
            let is_run = enc_buf[i] == VARIANT_ACK_RUN;
            i += 1;
            assert!(decode(&enc_buf, is_run, &mut i, |ack| {
                dec_buf.push(ack);
            }));
        }

        assert_eq!(acks, &dec_buf[..]);
    }

    /// [3, 5, 6] -> [3, 2, 1] -> [3, 0b0110]   -> [3u32, 1u8, 0 || 0, 0 || 1]
    #[test]
    fn test_first_break() {
        encode_decode(&[3, 5, 6]);
    }
    /// [3, 4, 6] -> [3, 1, 2] -> [3, 0b1010]   -> [3u32, 1u8, 0 || 1, 0 || 1]
    #[test]
    fn test_second_break() {
        encode_decode(&[3, 4, 6]);
    }
    /// [3, 4, 9] -> [3, 1, 5] -> [3, 0b100001] -> [3u32, 1u8, 0 || 1, 2 || 0]
    #[test]
    fn test_long_break() {
        encode_decode(&[3, 4, 9]);
    }
    /// [3, 5, 9] -> [3, 2, 5] -> [3, 0b010001] -> [3u32, 1u8, 0 || 0, 2 || 0]
    #[test]
    fn test_double_break() {
        encode_decode(&[3, 5, 9]);
    }
    /// [3, 4, 5, 6] -> [3, 1, 1, 1] -> [3, 0b1110]  -> [3u32, 0u8, 2 || 1]
    #[test]
    fn test_continuous() {
        encode_decode(&[3, 4, 5, 6]);
    }
    /// [3, 4, 6, 7] -> [3, 1, 2, 1] -> [3, 0b10110] -> [3u32, 1u8, 0 || 1, 1 || 1]
    #[test]
    fn test_center_break() {
        encode_decode(&[3, 4, 6, 7]);
    }
    /// [3, 0x80000000] => [3u32], [0x80000000u32]
    #[test]
    fn test_32_max() {
        encode_decode(&[3, 0x80000000]);
    }
    /// [0, 2, 4, ..., 508, 510, 512] => [0u32, 255u8, 0 || 0, 0 || 0, ...]
    #[test]
    fn test_evens_512() {
        let mut acks = Vec::new();
        for i in 0..=256 {
            acks.push(2 * i);
        }
        encode_decode(&acks[..]);
    }
    /// [0, 2, 4, ..., 510, 512, 514] => [0u32, 255u8, 0 || 0, 0 || 0, ...], [514u32]
    #[test]
    fn test_evens_514() {
        let mut acks = Vec::new();
        for i in 0..=257 {
            acks.push(2 * i);
        }
        encode_decode(&acks[..]);
    }
    /// [0, 2, 4, ..., 512, 514, 516] => [0u32, 255u8, 0 || 0, 0 || 0, ...], [514u32, 0u8, 0 || 0]
    #[test]
    fn test_evens_516() {
        let mut acks = Vec::new();
        for i in 0..=258 {
            acks.push(2 * i);
        }
        encode_decode(&acks[..]);
    }
    /// [0, 1, 3, ..., 511, 513, 515] => [0u32, 255u8, 0 || 1, 0 || 1, ...], [513u32, 0u8, 0 || 0]
    #[test]
    fn test_odds_515() {
        let mut acks = Vec::new();
        acks.push(0);
        for i in 0..=257 {
            acks.push(2 * i + 1);
        }
        encode_decode(&acks[..]);
    }
    /// [0, 1, 3, ..., 511, 512, 514] => [0u32, 255u8, 0 || 1, 0 || 1, ..., 1 || 1], [514u32]
    #[test]
    fn test_odds_break() {
        let mut acks = Vec::new();
        acks.push(0);
        for i in 0..=255 {
            acks.push(2 * i + 1);
        }
        acks.push(512);
        acks.push(514);
        encode_decode(&acks[..]);
    }
    /// [0, 2, 4, ..., 510, 0x8200] => [0u32, 254u8, 0 || 0, 0 || 0, ...], [0x8200u32]
    #[test]
    fn test_evens_overflow() {
        let mut acks = Vec::new();
        for i in 0..=255 {
            acks.push(2 * i);
        }
        acks.push(0x8200);
        encode_decode(&acks[..]);
    }
    /// [0, 2, 4, ..., 510, 0x8200, 0x8202] => [0u32, 254u8, 0 || 0, 0 || 0, ...], [0x8200u32, 0u8, 0 || 0]
    #[test]
    fn test_evens_overflow_break() {
        let mut acks = Vec::new();
        for i in 0..=255 {
            acks.push(2 * i);
        }
        acks.push(0x8200);
        acks.push(0x8202);
        encode_decode(&acks[..]);
    }
    /// [0, 1, 3, ..., 509, 0x8200] => [0u32, 254u8, 0 || 1, 0 || 1, ...], [0x8200]
    #[test]
    fn test_odds_overflow() {
        let mut acks = Vec::new();
        acks.push(0);
        for i in 0..=254 {
            acks.push(2 * i + 1);
        }
        acks.push(0x8200);
        encode_decode(&acks[..]);
    }
    /// [0, 1, 3, ..., 509, 0x8200, 0x8202] => [0u32, 254u8, 0 || 1, 0 || 1, ...], [0x8200, 0u8, 0 || 0]
    #[test]
    fn test_odds_overflow_break() {
        let mut acks = Vec::new();
        acks.push(0);
        for i in 0..=254 {
            acks.push(2 * i + 1);
        }
        acks.push(0x8200);
        acks.push(0x8202);
        encode_decode(&acks[..]);
    }
    /// [0, 2, 4, ..., 510, 511, 512, ..., 0x8200] => [0u32, 254u8, 0 || 0, 0 || 0, ...], [511u32, 3u8, 0x8000 || 1]
    #[test]
    fn test_long_evens_overflow() {
        let mut acks = Vec::new();
        for i in 0..=254 {
            acks.push(2 * i);
        }
        for i in 510..=0x8200 {
            acks.push(i);
        }
        encode_decode(&acks[..]);
    }
    /// [0, 1, 3, ..., 511, 512, 513, ..., 0x8200] => [0u32, 254u8, 0 || 1, 0 || 1, ...], [511u32, 3u8, 0x8000 || 1]
    #[test]
    fn test_long_odds_overflow() {
        let mut acks = Vec::new();
        acks.push(0);
        for i in 0..=254 {
            acks.push(2 * i + 1);
        }
        for i in 511..=0x8200 {
            acks.push(i);
        }
        encode_decode(&acks[..]);
    }
}
