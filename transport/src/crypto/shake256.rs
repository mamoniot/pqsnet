pub trait Xof {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finish(self, output: &mut [u8]);
}
