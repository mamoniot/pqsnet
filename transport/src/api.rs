use zeroize::Zeroizing;

use crate::{
    crypto::{CryptoAndMem, aes256::KEY_LEN},
    key_bundle::AuthenticBundle,
    protocol::derivation::*,
};

pub type ResumptionToken = [u8; RESUMPTION_TOKEN_LEN];
pub type ResumptionKey = [u8; RESUMPTION_KEY_LEN];
pub type SocketKey = [u8; KEY_LEN];

#[derive(Clone)]
pub struct SymmetricKeys(pub(crate) Zeroizing<[u8; SHAKE256_SPLIT_OUTPUT_LEN]>);

pub struct Resumption<C: CryptoAndMem> {
    pub token: ResumptionToken,
    pub key: Zeroizing<ResumptionKey>,
    pub remote_key_bundle: AuthenticBundle<C>,
}

pub struct HandshakeComplete<'a, C: CryptoAndMem> {
    /// If this is `Some`, then this peer must send the contained message to the remote peer and not
    /// consider the socket fully opened until the remote peer sends this peer authentic encrypted
    /// data.
    ///
    /// If this is `None` then this socket is fully opened and this peer should immediately send
    /// some kind of encrypted data for the remote peer to also consider this socket open.
    pub message_to_send: Option<C::MessageMem>,
    pub keys: SymmetricKeys,
    pub remote_key_bundle: AuthenticBundle<C>,
    pub recv_payload: &'a mut [u8],
}

impl SymmetricKeys {
    pub fn resumption_key(&self) -> &ResumptionKey {
        (&self.0[RESUMPTION_KEY_RANGE]).try_into().unwrap()
    }
    pub fn initiator_resumption_token(&self) -> &ResumptionToken {
        (&self.0[INITIATOR_RESUMPTION_TOKEN_RANGE]).try_into().unwrap()
    }
    pub fn responder_resumption_token(&self) -> &ResumptionToken {
        (&self.0[RESPONDER_RESUMPTION_TOKEN_RANGE]).try_into().unwrap()
    }
    pub fn initiator_key(&self) -> &SocketKey {
        (&self.0[INITIATOR_KEY_RANGE]).try_into().unwrap()
    }
    pub fn responder_key(&self) -> &SocketKey {
        (&self.0[RESPONDER_KEY_RANGE]).try_into().unwrap()
    }
}
