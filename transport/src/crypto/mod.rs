pub mod aes256;

pub mod shake256;

pub mod mlkem1024;

pub mod mldsa87;

pub trait Crypto {
    type Cipher: aes256::Cipher;
    type Hasher: shake256::Hasher;
    type SecretSigningKey: mldsa87::SecretSigningKey;
    type PublicSigningKey: mldsa87::PublicSigningKey;
    type DecapsulationKey: mlkem1024::DecapsulationKey;
}

pub mod prelude {
    use super::*;

    pub use aes256::Cipher;

    pub use shake256::Hasher;

    pub use mlkem1024::DecapsulationKey;

    pub use mldsa87::PublicSigningKey;

    pub use mldsa87::SecretSigningKey;

    pub use super::Crypto;
}
