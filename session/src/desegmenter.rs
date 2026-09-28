use std::ops::Range;

pub struct Desegmenter {}

pub enum NewResult {
    Segmented(Desegmenter),
    SingleSeg(Range<usize>),
    Invalid,
}

pub enum SegError {
    Segmented,
    Invalid,
}

impl Desegmenter {
    pub fn get_single_seg(packet: &[u8], idx: &mut usize) -> Result<Range<usize>, SegError> {
        todo!()
    }

    pub fn new(packet: &[u8], idx: &mut usize) -> NewResult {
        todo!()
    }

    pub fn recv(&self, packet: &[u8], idx: &mut usize) -> Result<Vec<u8>, SegError> {
        todo!()
    }

    pub fn recv_mut(&mut self, packet: &[u8], idx: &mut usize) -> Result<Vec<u8>, SegError> {
        todo!()
    }
}
