/// The size in bytes of an AES-256 key.
pub const KEY_LEN: usize = 32;
/// The size in bytes of an AES-GCM authentication tag.
pub const TAG_LEN: usize = 16;
/// The size in bytes of an AES-GCM nonce.
pub const NONCE_LEN: usize = 12;

pub trait Cipher {
    fn encrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8]) -> [u8; TAG_LEN];

    #[must_use]
    fn decrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8], tag: [u8; TAG_LEN]) -> bool;
}
