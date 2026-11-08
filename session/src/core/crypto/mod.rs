use std::sync::Arc;

use psqnet_transport::key_bundle;

pub mod aes;

pub mod sha3;

pub mod mlkem;

pub mod mldsa;

pub mod mem;

pub mod transport;

pub mod random;

pub type SecretBundle = Arc<key_bundle::SecretBundle<transport::Crypto>>;

pub type RemoteBundle = Arc<key_bundle::AuthenticBundle<transport::Crypto>>;
