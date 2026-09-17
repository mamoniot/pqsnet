

pub struct Desegmenter<T> {
    t: T,

}

pub enum NewResult<T> {
    Success(Desegmenter<T>),
    SingleSeg(Box<[u8]>, T),
    Failure,
}

impl<T> Desegmenter<T> {
    pub fn new(packet: &[u8], i: &mut usize, t: T) -> NewResult<T> {
        todo!()
    }

    pub fn recv(&self, packet: &[u8], i: &mut usize) -> Option<(Box<[u8]>, T)> {
        todo!()
    }

    pub fn recv_mut(&mut self, packet: &[u8], i: &mut usize) -> Option<(Box<[u8]>, T)> {
        todo!()
    }
}
