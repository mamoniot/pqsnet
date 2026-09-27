use psqnet_transport::crypto::aes256::*;

pub struct ColdAesGcm {}

impl Cipher for ColdAesGcm {
    fn encrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8]) -> [u8; TAG_LEN] {
        todo!()
    }

    fn decrypt_in_place(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], data: &mut [u8], tag: [u8; TAG_LEN]) -> bool {
        todo!()
    }
}
