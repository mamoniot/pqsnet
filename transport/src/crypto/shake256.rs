pub const COLLISION_RESISITANCE_NIST2_LEN: usize = 32;
pub const COLLISION_RESISITANCE_NIST4_LEN: usize = 48;
pub const COLLISION_RESISITANCE_NIST5_LEN: usize = 64;

pub trait Xof {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finish(self, output: &mut [u8]);
}
