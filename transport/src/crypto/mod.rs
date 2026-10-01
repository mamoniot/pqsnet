pub mod aes256;

pub mod shake256;

pub mod mlkem1024;

pub mod mldsa87;

pub mod mem;

pub trait CryptoAndMem {
    type Cipher: aes256::Cipher;
    type Xof: shake256::Xof;
    type SecretKey: mldsa87::SecretKey;
    type PublicKey: mldsa87::PublicKey;
    type DecapsulationKey: mlkem1024::DecapsulationKey;

    type BundleMem: mem::Mem;
    type PayloadMem: mem::Mem;
    type MessageMem: mem::Mem;
}

pub mod prelude {
    use super::*;

    pub use aes256::Cipher;

    pub use shake256::Xof;

    pub use mlkem1024::DecapsulationKey;

    pub use mldsa87::PublicKey;

    pub use mldsa87::SecretKey;

    pub use mem::Mem;

    pub use super::CryptoAndMem;
}
