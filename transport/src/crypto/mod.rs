pub mod aes256;

pub mod shake256;

pub mod mlkem1024;

pub mod mldsa87;

pub trait Crypto {
    type Cipher: aes256::Cipher;
    type Xof: shake256::Xof;
    type SecretKey: mldsa87::SecretKey;
    type PublicKey: mldsa87::PublicKey;
    type DecapsulationKey: mlkem1024::DecapsulationKey;
}

pub mod prelude {
    use super::*;

    pub use aes256::Cipher;

    pub use shake256::Xof;

    pub use mlkem1024::DecapsulationKey;

    pub use mldsa87::PublicKey;

    pub use mldsa87::SecretKey;

    pub use super::Crypto;
}
