use crate::messages::shared::{AES_GCM_FIXED_FIELD_DATA, AES_GCM_FIXED_FIELD_HANDSHAKE};

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

    fn encrypt_in_place(&self, nonce: [u8; NONCE_LEN], data: &mut [u8]) -> [u8; TAG_LEN];

    #[must_use]
    fn decrypt_in_place(&self, nonce: [u8; NONCE_LEN], data: &mut [u8], tag: [u8; TAG_LEN]) -> bool;
}

pub trait ColdPathCipher: Send + Sync {
    fn encrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8]) -> [u8; TAG_LEN];

    #[must_use]
    fn decrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8], tag: [u8; TAG_LEN]) -> bool;
}

pub(crate) fn to_handshake_nonce(counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = *AES_GCM_FIXED_FIELD_HANDSHAKE;
    nonce[NONCE_LEN - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub(crate) fn to_data_nonce(counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = *AES_GCM_FIXED_FIELD_DATA;
    nonce[NONCE_LEN - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
