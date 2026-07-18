/// The size of an AES-256 key.
pub const KEY_LEN: usize = 32;
/// The size of an AES-GCM authentication tag.
pub const TAG_LEN: usize = 16;
/// The size of an AES-GCM nonce.
pub const NONCE_LEN: usize = 12;

pub trait HotPathDuplexCipher: Send + Sync {
    type EncContext<'a>
    where
        Self: 'a;

    type DecContext<'a>
    where
        Self: 'a;

    fn new(encrypt_key: &[u8; KEY_LEN], decrypt_key: &[u8; KEY_LEN]) -> Self;

    fn start_enc<'a>(&'a self, nonce: [u8; NONCE_LEN]) -> Self::EncContext<'a>;

    fn start_dec<'a>(&'a self, nonce: [u8; NONCE_LEN]) -> Self::DecContext<'a>;

    fn encrypt<'a>(&'a self, enc: &mut Self::EncContext<'a>, input: &[u8], output: &mut [u8]);

    fn decrypt_in_place<'a>(&'a self, dec: &mut Self::DecContext<'a>, data: &mut [u8]);

    fn finish_enc<'a>(&'a self, enc: Self::EncContext<'a>) -> [u8; TAG_LEN];

    #[must_use]
    fn finish_dec<'a>(&'a self, dec: Self::DecContext<'a>, tag: &[u8; TAG_LEN]) -> bool;
}

pub trait ColdPathCipher: Send + Sync {
    fn encrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8]) -> [u8; TAG_LEN];

    #[must_use]
    fn decrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8], tag: [u8; TAG_LEN]) -> bool;
}

pub(crate) fn counter_to_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
