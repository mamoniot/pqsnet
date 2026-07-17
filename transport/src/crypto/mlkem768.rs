use rand_core::CryptoRng;

pub const ENCAPSULATION_KEY_LEN: usize = 1088;
pub const CIPHERTEXT_LEN: usize = 1088;
pub const SHARED_SECRET_KEY_LEN: usize = 32;

pub trait MlKem768 {
    fn generate<R: CryptoRng>(rng: &mut R) -> ([u8; ENCAPSULATION_KEY_LEN], Self);

    #[must_use]
    fn encapsulate<R: CryptoRng>(
        rng: &mut R,
        encapsulation_key: &[u8; ENCAPSULATION_KEY_LEN],
    ) -> Option<([u8; SHARED_SECRET_KEY_LEN], [u8; CIPHERTEXT_LEN])>;

    #[must_use]
    fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_LEN]) -> Option<[u8; SHARED_SECRET_KEY_LEN]>;
}
