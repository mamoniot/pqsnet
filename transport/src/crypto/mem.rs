use core::ops::DerefMut;

pub trait Mem: DerefMut<Target = [u8]> {
    fn new(len: usize) -> Self;
}
