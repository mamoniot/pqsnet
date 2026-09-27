use psqnet_transport::crypto::mlkem1024::*;

pub struct Mlkem1024Key {}

impl DecapsulationKey for Mlkem1024Key {
    fn generate() -> ([u8; ENCAPSULATION_KEY_LEN], Self) {
        todo!()
    }

    fn encapsulate(
        encapsulation_key: &[u8; ENCAPSULATION_KEY_LEN],
    ) -> Option<([u8; SHARED_SECRET_KEY_LEN], [u8; CIPHERTEXT_LEN])> {
        todo!()
    }

    fn decapsulate(&mut self, ciphertext: &[u8; CIPHERTEXT_LEN]) -> Option<[u8; SHARED_SECRET_KEY_LEN]> {
        todo!()
    }
}
