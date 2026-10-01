use super::*;

pub struct Crypto {}

impl psqnet_transport::crypto::CryptoAndMem for Crypto {
    type Cipher = aes::ColdAesGcm;

    type Xof = sha3::Shake256Hasher;

    type SecretKey = mldsa::MlDsa87SecretKey;

    type PublicKey = mldsa::MlDsa87PublicKey;

    type DecapsulationKey = mlkem::Mlkem1024Key;
}
