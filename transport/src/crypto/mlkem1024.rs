pub const ENCAPSULATION_KEY_LEN: usize = 1568;
pub const CIPHERTEXT_LEN: usize = 1568;
pub const SHARED_SECRET_KEY_LEN: usize = 32;

pub trait DecapsulationKey {
    fn generate() -> ([u8; ENCAPSULATION_KEY_LEN], Self);

    #[must_use]
    fn encapsulate(
        encapsulation_key: &[u8; ENCAPSULATION_KEY_LEN],
    ) -> Option<([u8; SHARED_SECRET_KEY_LEN], [u8; CIPHERTEXT_LEN])>;

    #[must_use]
    fn decapsulate(&mut self, ciphertext: &[u8; CIPHERTEXT_LEN]) -> Option<[u8; SHARED_SECRET_KEY_LEN]>;
}
