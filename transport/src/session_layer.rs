use zeroize::Zeroizing;

use crate::crypto::*;
use crate::protocol::*;

pub type ResumptionToken = [u8; initialize::RESUMPTION_TOKEN_LEN];
pub type ResumptionKey = Zeroizing<[u8; initialize::RESUMPTION_KEY_LEN]>;

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
    fn lookup_resumption_key(&mut self, resumption_token: &ResumptionToken) -> ResumptionAction<Self>;
}
