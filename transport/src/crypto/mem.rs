use core::ops::DerefMut;

pub trait Mem: DerefMut<Target = [u8]> {
    fn new(len: usize) -> Self;
}

#[cfg(feature = "std")]
impl Mem for Vec<u8> {
    fn new(len: usize) -> Self {
        vec![0; len]
    }
}

#[cfg(feature = "std")]
impl Mem for Box<[u8]> {
    fn new(len: usize) -> Self {
        vec![0; len].into()
    }
}
