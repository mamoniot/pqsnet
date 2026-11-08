use psqnet_transport::crypto::CryptoAndMem;

use super::*;

pub struct Crypto {}

impl CryptoAndMem for Crypto {
    type Cipher = aes::ColdAesGcm;

    type Xof = sha3::Shake256Hasher;

    type SecretKey = mldsa::MlDsa87SecretKey;

    type PublicKey = mldsa::MlDsa87PublicKey;

    type DecapsulationKey = mlkem::Mlkem1024Key;

    type BundleMem = Box<[u8]>;

    type PayloadMem = Vec<u8>;

    type MessageMem = Vec<u8>;
}
