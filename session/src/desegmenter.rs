use std::ops::Range;

pub struct Desegmenter {}

pub enum NewResult {
    Success(Desegmenter),
    SingleSeg(Range<usize>),
    Failure,
}

impl Desegmenter {
    pub fn new(packet: &[u8], idx: &mut usize) -> NewResult {
        todo!()
    }

    pub fn recv(&self, packet: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
        todo!()
    }

    pub fn recv_mut(&mut self, packet: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
        todo!()
    }
}
