use std::sync::Arc;

use crate::crypto::*;
use crate::key_bundle::{AuthenticBundle, PrivateBundle};
use crate::protocol::*;

pub type ResumptionToken = [u8; initialize::RESUMPTION_TOKEN_LEN];
pub type ResumptionKey = [u8; initialize::RESUMPTION_KEY_LEN];
pub type SocketKey = [u8; aes256::KEY_LEN];

#[derive(Default)]
pub enum ResumptionAction<S: SessionLayer> {
    ResumeWithKey {
        key: ResumptionKey,
        allow_fallback: bool,
        online_public_key: S::PublicSigningKeyImpl,
    },
    #[default]
    ReplyUnknown,
    Reject,
}

pub trait SessionLayer: Sized {
    type HotPathDuplexCipherImpl: aes256::HotPathDuplexCipher;
    type ColdPathCipher: aes256::ColdPathCipher;
    type Shake256Impl: shake256::Shake256;
    type PrivateSigningKeyImpl: mldsa87::PrivateSigningKey;
    type PublicSigningKeyImpl: mldsa87::PublicSigningKey;
    type DecapsulationKeyImpl: mlkem1024::DecapsulationKey;
    type RngImpl: rand_core::CryptoRng;

    fn rng(&mut self) -> &mut Self::RngImpl;

    // TODO: add return values for identifying the remote party.
    fn lookup_resumption_key(
        &mut self,
        resumption_token: &ResumptionToken,
    ) -> Option<(ResumptionKey, AuthenticBundle<Self::PublicSigningKeyImpl>)>;

    fn private_key_bundle(&mut self) -> Arc<PrivateBundle<Self::PublicSigningKeyImpl, Self::PrivateSigningKeyImpl>>;
    // fn sign_with_online_key(&mut self, ctx: &[u8], data: &[u8]) -> [u8; mldsa87::SIGNATURE_LEN];
    // fn local_key_bundle_bytes(&mut self) -> &[u8];
    // fn bundle_uid(&mut self) -> u128;
    // / TODO: This function creates race conditions with `key_bundle`.
    // fn bundle_len(&mut self) -> usize;
    // fn handshake_flags(&mut self) -> u8;
}
