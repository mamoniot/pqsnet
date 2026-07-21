use zeroize::Zeroizing;

use crate::{
    crypto::{
        aes256::{ColdPathCipher, TAG_LEN, to_handshake_nonce},
        shake256::Shake256,
    },
    error::Error,
    messages::{
        initialize::{RESUMPTION_KEY_LEN, RESUMPTION_TOKEN_LEN},
        resume::COUNTER_SKIP,
        shared::*,
    },
    session_layer::SessionLayer,
};

pub struct SymmetricState<S: SessionLayer> {
    key_buffer: Zeroizing<[u8; SHAKE256_MAX_OUTPUT_LEN]>,
    counter: u32,
    _s: std::marker::PhantomData<S>,
}

impl<S: SessionLayer> Default for SymmetricState<S> {
    fn default() -> Self {
        let mut key_buffer = Zeroizing::new([0u8; SHAKE256_MAX_OUTPUT_LEN]);
        key_buffer[CHAINING_KEY_START..CHAINING_KEY_END].copy_from_slice(&PROTOCOL_DOMAIN_NAME_SHAKE256);
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

        hasher.finish(&mut self.key_buffer[..]);
    }

    pub fn encrypt_and_mix(&mut self, plaintext_and_pad: &mut [u8], finished: bool) {
        let key_len = if finished {
            SHAKE256_MAX_OUTPUT_LEN
        } else {
            CHANNEL_BINDING_END
        };

        let (plaintext, pad) = plaintext_and_pad.split_at_mut(plaintext_and_pad.len() - TAG_LEN);

        let tag = S::ColdPathCipher::encrypt_in_place(
            (&self.key_buffer[AES_KEY_START..AES_KEY_END]).try_into().unwrap(),
            to_handshake_nonce(self.counter),
            plaintext,
        );
        self.counter += 1;
        pad.copy_from_slice(&tag);

        let mut hasher = S::Shake256Impl::new();
        hasher.update(&self.key_buffer[CHAINING_KEY_START..CHAINING_KEY_END]);
        hasher.update(plaintext_and_pad);

        hasher.finish(&mut self.key_buffer[..key_len]);
    }

    pub fn mix_and_decrypt(&mut self, ciphertext_and_tag: &mut [u8], finished: bool) -> Result<(), Error> {
        let key_len = if finished {
            SHAKE256_MAX_OUTPUT_LEN
        } else {
            CHANNEL_BINDING_END
        };
        let mut hasher = S::Shake256Impl::new();

        hasher.update(&self.key_buffer[CHAINING_KEY_START..CHAINING_KEY_END]);
        hasher.update(ciphertext_and_tag);

        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - TAG_LEN);

        let auth = S::ColdPathCipher::decrypt_in_place(
            (&self.key_buffer[AES_KEY_START..AES_KEY_END]).try_into().unwrap(),
            to_handshake_nonce(self.counter),
            ciphertext,
            tag.try_into().unwrap(),
        );
        self.counter += 1;

        hasher.finish(&mut self.key_buffer[..key_len]);

        if auth { Ok(()) } else { Err(Error::Inauthentic) }
    }

    pub fn channel_binding(&self) -> &[u8] {
        &self.key_buffer[CHANNEL_BINDING_START..CHANNEL_BINDING_END]
    }

    pub fn split(
        self,
    ) -> (
        S::HotPathDuplexCipherImpl,
        [u8; RESUMPTION_TOKEN_LEN],
        Zeroizing<[u8; RESUMPTION_KEY_LEN]>,
    ) {
        todo!()
    }
}
