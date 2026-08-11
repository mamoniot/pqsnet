pub fn varu64_len(value: u64) -> usize {
    todo!()
}

pub fn varu64_try_read(buf: &[u8], idx: &mut usize) -> Option<u64> {
    todo!()
}

pub fn varu32_try_read(buf: &[u8], idx: &mut usize) -> Option<u32> {
    todo!()
}

pub fn varusize_try_read(buf: &[u8], idx: &mut usize) -> Option<usize> {
    todo!()
}

pub fn varusize_len(value: usize) -> usize {
    todo!()
}

pub fn varusize_write(buf: &mut [u8], idx: &mut usize, value: usize) -> bool {
    todo!()
}

pub fn varusize_write_segment(buf: &mut [u8], idx: &mut usize, data: &[u8], jdx: &mut usize) -> bool {
    todo!()
}
