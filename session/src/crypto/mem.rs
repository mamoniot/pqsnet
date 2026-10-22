use std::{ops::{Deref, DerefMut}, ptr::NonNull};

use psqnet_transport::crypto::mem::Mem;


pub(crate) struct PrefixMem {
    mem: Vec<u8>,
    start: usize
}

pub(crate) struct DocMem {
    mem: *mut u8,
    len: usize,
}

impl Deref for PrefixMem {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mem[self.start..]
    }
}

impl DerefMut for PrefixMem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mem[self.start..]
    }
}

impl Mem for PrefixMem {
    type Alloc = Vec<u8>;

    fn malloc(mut mem: Self::Alloc, len: usize) -> Option<Self> {
        let start = mem.len();
        mem.resize(start + len, 0);
        Some(Self {
            mem,
            start
        })
    }
}

impl Deref for DocMem {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            std::slice::from_raw_parts(self.mem, self.len)
        }
    }
}

impl DerefMut for DocMem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            std::slice::from_raw_parts_mut(self.mem, self.len)
        }
    }
}

impl Mem for DocMem {
    type Alloc = fn(usize) -> Option<NonNull<u8>>;

    fn malloc(alloc: Self::Alloc, len: usize) -> Option<Self> {
        Some(Self {
            mem: alloc(len)?.as_ptr(),
            len,
        })
    }
}
