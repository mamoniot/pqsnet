pub const HASH384_LEN: usize = 48;

pub trait Shake256 {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finish(self, output: &mut [u8]);
}
