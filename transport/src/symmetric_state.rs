use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::{
    SymmetricKeys,
    crypto::{aes256::TAG_LEN, prelude::*},
    error::{AuthError, Error},
    key_bundle::{AuthenticBundle, BundleHash, SecretBundle},
    protocol::{derivation::*, domain},
};

pub struct SymmetricState<C: CryptoAndMem> {
    key_buffer: Zeroizing<[u8; SHAKE256_HANDSHAKE_OUTPUT_LEN]>,
    _c: PhantomData<C>,
}

impl<C: CryptoAndMem> Clone for SymmetricState<C> {
    fn clone(&self) -> Self {
        Self { key_buffer: self.key_buffer.clone(), _c: Default::default() }
    }
}

impl<C: CryptoAndMem> SymmetricState<C> {
    fn hash3(&self, step_no: u8, shared_data: &[u8]) -> C::Xof {
        let mut hasher = C::Xof::new();
        hasher.update(&[step_no]);
        hasher.update(&self.key_buffer[CHAINING_KEY_RANGE]);
        hasher.update(shared_data);
        hasher
    }

    pub fn mix(&mut self, step_no: u8, shared_data: &[u8]) {
        self.hash3(step_no, shared_data).finish(&mut self.key_buffer[..]);
    }

    pub fn new(aad: &[u8]) -> Self {
        let mut ret = Self { key_buffer: Zeroizing::new([0u8; _]), _c: PhantomData };

        ret.key_buffer[..domain::HANDSHAKE_SALT.len()].copy_from_slice(domain::HANDSHAKE_SALT);
        ret.mix(0, aad);

        ret
    }

    pub fn encrypt_and_mix(&mut self, step_no: u8, plaintext_and_pad: &mut [u8]) {
        let (plaintext, pad) = plaintext_and_pad.split_at_mut(plaintext_and_pad.len() - TAG_LEN);

        let tag = C::Cipher::encrypt_in_place(
            (&self.key_buffer[AES_KEY_RANGE]).try_into().unwrap(),
            domain::to_handshake_idnce(step_no),
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
            domain::to_handshake_idnce(step_no),
            ciphertext,
            tag.try_into().unwrap(),
        );

        hasher.finish(&mut self.key_buffer[..]);

        if auth { Ok(()) } else { Err(Error::Inauthentic) }
    }

    fn channel_binding(&self) -> [u8; CHANNEL_BINDING_LEN] {
        self.key_buffer[CHANNEL_BINDING_RANGE].try_into().unwrap()
    }

    pub fn sign(&mut self, step_no: u8, secret_key_bundle: &SecretBundle<C>, plaintext_and_pad: &mut [u8]) {
        let plaintext_end = plaintext_and_pad.len() - TAG_LEN;

        let sign = secret_key_bundle.sign(&[step_no], &self.channel_binding());
        plaintext_and_pad[..plaintext_end].copy_from_slice(&sign);

        self.encrypt_and_mix(step_no, plaintext_and_pad);
    }

    pub fn verify(
        &mut self,
        step_no: u8,
        remote_key_bundle: &AuthenticBundle<C>,
        ciphertext_and_tag: &mut [u8],
        secs_since_unix_epoch: Option<u64>,
    ) -> Result<(), AuthError> {
        let ciphertext_end = ciphertext_and_tag.len() - TAG_LEN;

        let sign_channel_binding = self.channel_binding();

        self.decrypt_and_mix(step_no, ciphertext_and_tag)?;

        remote_key_bundle.verify(
            &[step_no],
            &sign_channel_binding,
            &ciphertext_and_tag[..ciphertext_end].try_into().unwrap(),
            secs_since_unix_epoch,
        )
    }

    /// This is not a MAC, this is just a checksum for whether or not both peers agree on
    /// each other's key bundles and bundle versions prior to going through with 1-rtt resumption.
    pub fn bundle_checksum(&self, initiator_hash: &BundleHash, responder_hash: &BundleHash, output: &mut [u8]) {
        let mut hasher = C::Xof::new();
        hasher.update(&self.channel_binding());
        hasher.update(initiator_hash);
        hasher.update(responder_hash);

        hasher.finish(output);
    }

    pub fn split(self, step_no: u8, is_init: bool) -> SymmetricKeys {
        let mut key_buffer = Zeroizing::new([0u8; _]);

        self.hash3(step_no, &[]).finish(&mut key_buffer[..]);

        SymmetricKeys::new(is_init, key_buffer)
    }
}
