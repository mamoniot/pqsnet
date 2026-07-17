use rand_core::CryptoRng;

pub const PUBLIC_KEY_LEN: usize = 1952;
pub const SIGNATURE_LEN: usize = 3309;

pub trait MlDsa65 {
    fn sign<R: CryptoRng>(&self, rng: &mut R, data: &[u8]) -> [u8; SIGNATURE_LEN];

    #[must_use]
    fn verify(public_key: &[u8; PUBLIC_KEY_LEN], data: &[u8]) -> bool;
}
