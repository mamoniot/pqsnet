#![cfg_attr(not(feature = "std"), no_std)]

pub mod crypto;

pub(crate) mod protocol;

pub(crate) mod symmetric_state;

pub(crate) mod api;

pub mod key_bundle;

pub mod initiator;

pub mod responder;

pub mod error;

pub use api::HandshakeComplete;
pub use api::SymmetricKeys;
pub use protocol::domain::to_data_nonce;

pub mod exports {
    pub use constant_time_eq;
    pub use zeroize;
}
