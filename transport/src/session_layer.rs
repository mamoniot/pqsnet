use zeroize::Zeroizing;

use crate::crypto::*;
use crate::messages::*;

pub type ResumptionToken = [u8; initialize::RESUMPTION_TOKEN_LEN];
pub type ResumptionKey = Zeroizing<[u8; initialize::RESUMPTION_KEY_LEN]>;

#[derive(Default)]
pub enum ResumptionAction {
    ResumeKnownWithKey {
        key: ResumptionKey,
    },
    AuthWithKey {
        key: ResumptionKey,
    },
    #[default]
    AuthUnknown,
    Reject,
}

pub trait SessionLayer {
    type HotPathDuplexCipherImpl: aes256::HotPathDuplexCipher;
    type ColdPathCipher: aes256::ColdPathCipher;
    type Shake256Impl: shake256::Shake256;
    type PublicKeyBundleImpl: mldsa87::PublicKeyBundle;
    type DecapsulationKeyImpl: mlkem1024::DecapsulationKey;
    type RngImpl: rand_core::CryptoRng;

    fn static_public_keys(&mut self) -> Self::PublicKeyBundleImpl;

    fn rng(&mut self) -> &mut Self::RngImpl;

    // TODO: add return values for identifying the remote party.
    fn lookup_resumption_key(&mut self, resumption_token: &ResumptionToken) -> ResumptionAction;
}
