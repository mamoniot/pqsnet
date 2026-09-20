

pub struct Desegmenter {
}

pub enum NewResult<'a> {
    Success(Desegmenter),
    SingleSeg(&'a [u8]),
    Failure,
}

impl Desegmenter {
    pub fn new<'a>(packet: &'a [u8], idx: &mut usize) -> NewResult<'a> {
        todo!()
    }

    pub fn recv(&self, packet: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
        todo!()
    }

    pub fn recv_mut(&mut self, packet: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
        todo!()
    }
}
