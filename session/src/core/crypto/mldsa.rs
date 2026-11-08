use psqnet_transport::crypto::mldsa87::*;

pub struct MlDsa87SecretKey {}

pub struct MlDsa87PublicKey {}

impl SecretKey for MlDsa87SecretKey {
    fn sign(&self, ctx: &[u8], data: &[u8]) -> [u8; SIGN_LEN] {
        todo!()
    }
}

impl PublicKey for MlDsa87PublicKey {
    fn decode(public_key: [u8; PUBLIC_KEY_LEN]) -> Option<Self> {
        todo!()
    }

    fn verify(&self, ctx: &[u8], data: &[u8], signature: &[u8; SIGN_LEN]) -> bool {
        todo!()
    }
}
