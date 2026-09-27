use psqnet_transport::crypto::shake256::*;

pub struct Shake256Hasher {}

impl Xof for Shake256Hasher {
    fn new() -> Self {
        todo!()
    }

    fn update(&mut self, data: &[u8]) {
        todo!()
    }

    fn finish(self, output: &mut [u8]) {
        todo!()
    }
}
