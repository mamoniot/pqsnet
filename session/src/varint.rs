use bytes::BufMut;

pub const VARINT_U8_MAX: u8 = u8::MAX >> 2;
pub const VARINT_U16_MAX: u16 = u16::MAX >> 2;
pub const VARINT_U32_MAX: u32 = u32::MAX >> 2;
pub const VARINT_MAX: u64 = u64::MAX >> 2;

pub fn varu64_len(value: u64) -> usize {
    if value <= VARINT_U16_MAX as u64 {
        if value <= VARINT_U8_MAX as u64 { 1 } else { 2 }
    } else {
        if value <= VARINT_U32_MAX as u64 { 4 } else { 8 }
    }
}
pub fn varusize_len(value: usize) -> usize {
    if value <= VARINT_U16_MAX as usize {
        if value <= VARINT_U8_MAX as usize { 1 } else { 2 }
    } else {
        if value <= VARINT_U32_MAX as usize { 4 } else { 8 }
    }
}
pub fn varu32_len(value: u32) -> usize {
    varusize_len(value as usize)
}

pub fn varu64_write(buf: &mut Vec<u8>, value: u64) {
    if value <= VARINT_U16_MAX as u64 {
        if value <= VARINT_U8_MAX as u64 {
            buf.push(value as u8);
        } else {
            buf.put_u16(value as u16 | 0b01 << 14);
        }
    } else {
        if value <= VARINT_U32_MAX as u64 {
            buf.put_u32(value as u32 | 0b10 << 30);
        } else {
            buf.put_u64(value | 0b11 << 62);
        }
    }
}
pub fn varusize_write(buf: &mut Vec<u8>, value: usize) {
    if value <= VARINT_U16_MAX as usize {
        if value <= VARINT_U8_MAX as usize {
            buf.push(value as u8);
        } else {
            buf.put_u16(value as u16 | 0b01 << 14);
        }
    } else {
        if value <= VARINT_U32_MAX as usize {
            buf.put_u32(value as u32 | 0b10 << 30);
        } else {
            buf.put_u64(value as u64 | 0b11 << 62);
        }
    }
}
pub fn varu32_write(buf: &mut Vec<u8>, value: u32) {
    varusize_write(buf, value as usize);
}

macro_rules! impl_try_read {
    ($n: ident, $t:ty) => {
        pub fn $n(buf: &[u8], idx: &mut usize) -> Option<$t> {
            let i = *idx;
            if i >= buf.len() {
                return None;
            }
            Some(match buf[i] >> 6 {
                0b00 => {
                    *idx += 1;
                    buf[i] as $t
                }
                0b01 => {
                    let j = *idx + 2;
                    if j > buf.len() {
                        return None;
                    }
                    *idx = j;
                    (u16::from_be_bytes(buf[i..j].try_into().unwrap()) & VARINT_U16_MAX) as $t
                }
                0b10 => {
                    let j = *idx + 4;
                    if j > buf.len() {
                        return None;
                    }
                    *idx = j;
                    (u32::from_be_bytes(buf[i..j].try_into().unwrap()) & VARINT_U32_MAX) as $t
                }
                0b11 => {
                    let j = *idx + 8;
                    if j > buf.len() {
                        return None;
                    }
                    *idx = j;
                    <$t>::try_from(u64::from_be_bytes(buf[i..j].try_into().unwrap())).ok()?
                }
                _ => unreachable!(),
            })
        }
    };
}

impl_try_read!(varu64_try_read, u64);
impl_try_read!(varusize_try_read, usize);
impl_try_read!(varu32_try_read, u32);
