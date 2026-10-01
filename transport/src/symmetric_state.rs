use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::{
    crypto::{
        aes256::{KEY_LEN, TAG_LEN},
        prelude::*,
    },
    error::Error,
    key_bundle::AuthenticBundle,
    protocol::{domain, symmetric_state::*},
};

pub type ResumptionToken = [u8; RESUMPTION_TOKEN_LEN];
pub type ResumptionKey = [u8; RESUMPTION_KEY_LEN];
pub type SocketKey = [u8; KEY_LEN];

pub struct SymmetricState<S: CryptoAndMem> {
    key_buffer: Zeroizing<[u8; SHAKE256_HANDSHAKE_OUTPUT_LEN]>,
    _s: PhantomData<S>,
}

#[derive(Clone)]
pub struct SymmetricKeys {
    key_buffer: Zeroizing<[u8; SHAKE256_SPLIT_OUTPUT_LEN]>,
}

pub struct Resumption<C: CryptoAndMem> {
    pub token: ResumptionToken,
    pub key: Zeroizing<ResumptionKey>,
    pub remote_key_bundle: AuthenticBundle<C>,
}

pub struct HandshakeComplete<'a, C: CryptoAndMem> {
    pub message_to_send: Option<C::MessageMem>,
    pub keys: SymmetricKeys,
    pub remote_key_bundle: AuthenticBundle<C>,
    pub recv_payload: &'a mut [u8],
}

impl<C: CryptoAndMem> Clone for SymmetricState<C> {
    fn clone(&self) -> Self {
        Self { key_buffer: self.key_buffer.clone(), _s: Default::default() }
    }
}

impl<C: CryptoAndMem> SymmetricState<C> {
    fn hash3(&self, step_no: u8, shared_data: &[u8]) -> C::Xof {
        let mut hasher = C::Xof::new();
        hasher.update(&self.key_buffer[CHAINING_KEY_RANGE]);
        hasher.update(&[step_no]);
        hasher.update(shared_data);
        hasher
    }

    pub fn mix(&mut self, step_no: u8, shared_data: &[u8]) {
        self.hash3(step_no, shared_data).finish(&mut self.key_buffer[..]);
    }

    pub fn new(aad: &[u8]) -> Self {
        let mut ret = Self { key_buffer: Zeroizing::new([0u8; _]), _s: Default::default() };

        ret.key_buffer[..domain::HANDSHAKE_SALT.len()].copy_from_slice(domain::HANDSHAKE_SALT);
        ret.mix(0, aad);

        ret
    }

    pub fn encrypt_and_mix(&mut self, step_no: u8, plaintext_and_pad: &mut [u8]) {
        let (plaintext, pad) = plaintext_and_pad.split_at_mut(plaintext_and_pad.len() - TAG_LEN);

        let tag = C::Cipher::encrypt_in_place(
            (&self.key_buffer[AES_KEY_RANGE]).try_into().unwrap(),
            domain::to_handshake_nonce(step_no),
            plaintext,
        );
        pad.copy_from_slice(&tag);

        self.mix(step_no, plaintext_and_pad);
    }

    pub fn decrypt_and_mix(&mut self, step_no: u8, ciphertext_and_tag: &mut [u8]) -> Result<(), Error> {
        let hasher = self.hash3(step_no, ciphertext_and_tag);

        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - TAG_LEN);

        let auth = C::Cipher::decrypt_in_place(
            (&self.key_buffer[AES_KEY_RANGE]).try_into().unwrap(),
            domain::to_handshake_nonce(step_no),
            ciphertext,
            tag.try_into().unwrap(),
        );

        hasher.finish(&mut self.key_buffer[..]);

        if auth { Ok(()) } else { Err(Error::Inauthentic) }
    }

    pub fn channel_binding(&self) -> [u8; CHANNEL_BINDING_LEN] {
        self.key_buffer[CHANNEL_BINDING_RANGE].try_into().unwrap()
    }

    pub fn split(self, step_no: u8) -> SymmetricKeys {
        let mut key_buffer = Zeroizing::new([0u8; _]);

        self.hash3(step_no, &[]).finish(&mut key_buffer[..]);

        SymmetricKeys { key_buffer }
    }
}

impl SymmetricKeys {
    pub fn resumption_key(&self) -> &ResumptionKey {
        (&self.key_buffer[RESUMPTION_KEY_RANGE]).try_into().unwrap()
    }
    pub fn initiator_resumption_token(&self) -> &ResumptionToken {
        (&self.key_buffer[INITIATOR_RESUMPTION_TOKEN_RANGE]).try_into().unwrap()
    }
    pub fn responder_resumption_token(&self) -> &ResumptionToken {
        (&self.key_buffer[RESPONDER_RESUMPTION_TOKEN_RANGE]).try_into().unwrap()
    }
    pub fn initiator_key(&self) -> &SocketKey {
        (&self.key_buffer[INITIATOR_KEY_RANGE]).try_into().unwrap()
    }
    pub fn responder_key(&self) -> &SocketKey {
        (&self.key_buffer[RESPONDER_KEY_RANGE]).try_into().unwrap()
    }
}
