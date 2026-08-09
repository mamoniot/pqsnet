


pub fn varu64_len(value: u64) -> usize {
    todo!()
}

pub fn varu64_write<W: std::io::Write>(buf: &mut W, value: u64) -> usize {
    todo!()
}

pub fn varu64_try_read(buf: &[u8], start: &mut usize) -> Option<u64> {
    todo!()
}
pub fn varusize_try_read(buf: &[u8], start: &mut usize) -> Option<usize> {
    todo!()
}




pub fn varusize_len(value: usize) -> usize {
    todo!()
}

pub fn varusize_write<W: std::io::Write>(buf: &mut W, value: usize) -> usize {
    todo!()
}

/// TODO: Move this function.
pub fn copy_write<W: std::io::Write>(dest: &mut W, src: &[u8], len: usize) {

}
