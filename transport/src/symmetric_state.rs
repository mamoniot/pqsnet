use zeroize::Zeroizing;

use crate::{
    crypto::{aes256::TAG_LEN, prelude::*},
    error::Error,
    protocol::{domain, symmetric_state::*},
    session_layer::{ResumptionKey, ResumptionToken, SessionLayer, SocketKey},
};

pub struct SymmetricState<S: SessionLayer> {
    key_buffer: Zeroizing<[u8; SHAKE256_HANDSHAKE_OUTPUT_LEN]>,
    _s: std::marker::PhantomData<S>,
}

#[derive(Clone)]
pub struct SymmetricKeys {
    key_buffer: Zeroizing<[u8; SHAKE256_SPLIT_OUTPUT_LEN]>,
}

impl<S: SessionLayer> Clone for SymmetricState<S> {
    fn clone(&self) -> Self {
        Self {
            key_buffer: self.key_buffer.clone(),
            _s: Default::default(),
        }
    }
}

impl<S: SessionLayer> SymmetricState<S> {
    pub fn new(aad: &[u8]) -> Self {
        let mut hasher = S::Shake256Impl::new();
        hasher.update(domain::TRANSPORT_PROTOCOL_SALT);
        hasher.update(aad);

        let mut key_buffer = Zeroizing::new([0u8; SHAKE256_HANDSHAKE_OUTPUT_LEN]);
        hasher.finish(&mut key_buffer[..]);

        Self {
            key_buffer,
            _s: Default::default(),
        }
    }

    pub fn mix(&mut self, shared_data: &[u8]) {
        let mut hasher = S::Shake256Impl::new();
        hasher.update(&self.key_buffer[CHAINING_KEY_RANGE]);
        hasher.update(shared_data);

        hasher.finish(&mut self.key_buffer[..]);
    }

    pub fn encrypt_and_mix(&mut self, plaintext_and_pad: &mut [u8]) {
        let (plaintext, pad) = plaintext_and_pad.split_at_mut(plaintext_and_pad.len() - TAG_LEN);

        let tag = S::ColdPathCipher::encrypt_in_place(
            (&self.key_buffer[AES_KEY_RANGE]).try_into().unwrap(),
            domain::AES_GCM_FIXED_FIELD_HANDSHAKE,
            plaintext,
        );
        pad.copy_from_slice(&tag);

        let mut hasher = S::Shake256Impl::new();
        hasher.update(&self.key_buffer[CHAINING_KEY_RANGE]);
        hasher.update(plaintext_and_pad);

        hasher.finish(&mut self.key_buffer[..]);
    }

    pub fn decrypt_and_mix(&mut self, ciphertext_and_tag: &mut [u8]) -> Result<(), Error> {
        let mut hasher = S::Shake256Impl::new();

        hasher.update(&self.key_buffer[CHAINING_KEY_RANGE]);
        hasher.update(ciphertext_and_tag);

        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - TAG_LEN);

        let auth = S::ColdPathCipher::decrypt_in_place(
            (&self.key_buffer[AES_KEY_RANGE]).try_into().unwrap(),
            domain::AES_GCM_FIXED_FIELD_HANDSHAKE,
            ciphertext,
            tag.try_into().unwrap(),
        );

        hasher.finish(&mut self.key_buffer[..]);

        if auth { Ok(()) } else { Err(Error::Inauthentic) }
    }

    pub fn channel_binding(&self) -> [u8; CHANNEL_BINDING_LEN] {
        self.key_buffer[CHANNEL_BINDING_RANGE].try_into().unwrap()
    }

    pub fn split(self) -> SymmetricKeys {
        let mut key_buffer = Zeroizing::new([0u8; SHAKE256_SPLIT_OUTPUT_LEN]);
        let mut hasher = S::Shake256Impl::new();

        hasher.update(&self.key_buffer[CHAINING_KEY_RANGE]);
        hasher.finish(&mut key_buffer[..]);

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
