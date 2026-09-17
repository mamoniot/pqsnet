

pub struct HotAesGcmEncryptor {}

pub struct HotAesGcmDecryptor {}

impl HotAesGcmDecryptor {
    #[must_use]
    pub fn decrypt_in_place(&self, nonce_suffix: &[u8], ciphertext: &mut [u8]) -> bool {
        debug_assert!(nonce_suffix.len() >= 4);
        debug_assert!(nonce_suffix.len() <= 8);
        todo!()
    }
}

impl HotAesGcmEncryptor {

}
