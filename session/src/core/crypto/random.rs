use std::convert::Infallible;

use rand::{TryCryptoRng, TryRng};


pub struct OpenSSLRand;

impl TryRng for OpenSSLRand {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        todo!()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        todo!()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        todo!()
    }
}

impl TryCryptoRng for OpenSSLRand {}
unsafe impl Sync for OpenSSLRand {}
unsafe impl Send for OpenSSLRand {}
