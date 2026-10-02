use core::ops::DerefMut;

pub trait Mem: Sized + DerefMut<Target = [u8]> {
    type Alloc;
    fn malloc(alloc: Self::Alloc, len: usize) -> Option<Self>;
}

#[cfg(feature = "std")]
impl Mem for Vec<u8> {
    type Alloc = ();
    fn malloc(_: (), len: usize) -> Option<Self> {
        Some(vec![0; len])
    }
}

#[cfg(feature = "std")]
impl Mem for Box<[u8]> {
    type Alloc = ();
    fn malloc(_: (), len: usize) -> Option<Self> {
        Some(vec![0; len].into())
    }
}
