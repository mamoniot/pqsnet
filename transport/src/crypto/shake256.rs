pub trait Shake256 {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finish_and_reset(&mut self, output: &mut [u8]);
}
