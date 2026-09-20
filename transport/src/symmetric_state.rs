use zeroize::Zeroizing;

use crate::{
    crypto::{aes256::TAG_LEN, prelude::*}, error::Error, protocol::{domain, resume::COUNTER_SKIP, shared::*}, session_layer::{ResumptionKey, ResumptionToken, SessionLayer, SocketKey},
};

pub struct SymmetricState<S: SessionLayer> {
    key_buffer: Zeroizing<[u8; SHAKE256_NORMAL_OUTPUT_LEN]>,
    counter: u32,
    _s: std::marker::PhantomData<S>,
}

// TODO: switch to single zeroizing buffer.
pub struct SymmetricKeys {
    pub initiator_key: SocketKey,
    pub responder_key: SocketKey,
    pub initiator_resumption_token: ResumptionToken,
    pub responder_resumption_token: ResumptionToken,
    pub resumption_key: ResumptionKey,
}

impl<S: SessionLayer> Clone for SymmetricState<S> {
    fn clone(&self) -> Self {
        Self {
            key_buffer: self.key_buffer.clone(),
            counter: self.counter,
            _s: Default::default(),
        }
    }
}

impl<S: SessionLayer> Default for SymmetricState<S> {
    fn default() -> Self {
        let mut key_buffer = Zeroizing::new([0u8; SHAKE256_NORMAL_OUTPUT_LEN]);
        key_buffer[CHAINING_KEY_START..CHAINING_KEY_END].copy_from_slice(&domain::TRANSPORT_PROTOCOL_SHAKE256);
        Self {
            key_buffer,
            counter: AES_GCM_INIT_COUNTER,
            _s: Default::default(),
        }
    }
}

impl<S: SessionLayer> SymmetricState<S> {
    pub fn start_resume(&mut self) {
        self.counter += COUNTER_SKIP;
    }

    pub fn mix(&mut self, shared_data: &[u8]) {
        let mut hasher = S::Shake256Impl::new();
        hasher.update(&self.key_buffer[CHAINING_KEY_START..CHAINING_KEY_END]);
        hasher.update(shared_data);

        hasher.finish(&mut self.key_buffer[..CHANNEL_BINDING_END]);
    }

    pub fn encrypt_and_mix(&mut self, plaintext_and_pad: &mut [u8]) {
        let (plaintext, pad) = plaintext_and_pad.split_at_mut(plaintext_and_pad.len() - TAG_LEN);

        let tag = S::ColdPathCipher::encrypt_in_place(
            (&self.key_buffer[AES_KEY_START..AES_KEY_END]).try_into().unwrap(),
            domain::to_handshake_nonce(self.counter),
            plaintext,
        );
        self.counter += 1;
        pad.copy_from_slice(&tag);

        let mut hasher = S::Shake256Impl::new();
        hasher.update(&self.key_buffer[CHAINING_KEY_START..CHAINING_KEY_END]);
        hasher.update(plaintext_and_pad);

        hasher.finish(&mut self.key_buffer[..]);
    }

    pub fn decrypt_and_mix(&mut self, ciphertext_and_tag: &mut [u8]) -> Result<(), Error> {
        let mut hasher = S::Shake256Impl::new();

        hasher.update(&self.key_buffer[CHAINING_KEY_START..CHAINING_KEY_END]);
        hasher.update(ciphertext_and_tag);

        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - TAG_LEN);

        let auth = S::ColdPathCipher::decrypt_in_place(
            (&self.key_buffer[AES_KEY_START..AES_KEY_END]).try_into().unwrap(),
            domain::to_handshake_nonce(self.counter),
            ciphertext,
            tag.try_into().unwrap(),
        );
        self.counter += 1;

        hasher.finish(&mut self.key_buffer[..]);

        if auth { Ok(()) } else { Err(Error::Inauthentic) }
    }

    pub fn channel_binding(&self) -> [u8; CHANNEL_BINDING_LEN] {
        self.key_buffer[CHANNEL_BINDING_RANGE].try_into().unwrap()
    }

    pub fn split(self) -> SymmetricKeys {
        let mut buffer = Zeroizing::new([0u8; SHAKE256_FINAL_OUTPUT_LEN]);
        let mut hasher = S::Shake256Impl::new();

        hasher.update(&self.key_buffer[CHAINING_KEY_START..CHAINING_KEY_END]);
        hasher.finish(&mut buffer[..]);

        let resumption_key = Zeroizing::new(buffer[RESUMPTION_KEY_RANGE].try_into().unwrap());
        let initiator_resumption_token = buffer[INITIATOR_RESUMPTION_TOKEN_RANGE].try_into().unwrap();
        let responder_resumption_token = buffer[RESPONDER_RESUMPTION_TOKEN_RANGE].try_into().unwrap();
        let initiator_key = Zeroizing::new(buffer[INITIATOR_KEY_RANGE].try_into().unwrap());
        let responder_key = Zeroizing::new(buffer[RESPONDER_KEY_RANGE].try_into().unwrap());

        SymmetricKeys {
            initiator_key,
            responder_key,
            initiator_resumption_token,
            responder_resumption_token,
            resumption_key,
        }
    }
}
