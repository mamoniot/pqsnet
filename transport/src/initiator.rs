use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{
    crypto::prelude::*,
    error::{Error, InitError},
    key_bundle::{AuthenticBundle, SecretBundle},
    protocol::*,
    symmetric_state::{Resumption, SymmetricKeys, SymmetricState},
};

pub struct InitializeState<C: Crypto> {
    symmetric: SymmetricState<C>,
    fallback: Option<SymmetricState<C>>,
    decapsulation_key: C::DecapsulationKey,
    payload: Box<[u8]>,
    secret_key_bundle: Arc<SecretBundle<C::PublicSigningKey, C::SecretSigningKey>>,
    remote_key_bundle: Option<Arc<AuthenticBundle<C::PublicSigningKey>>>,
}

pub struct HandshakeFinished<'a, C: Crypto> {
    pub message_to_send: Option<Vec<u8>>,
    pub keys: SymmetricKeys,
    pub remote_key_bundle: Arc<AuthenticBundle<C::PublicSigningKey>>,
    pub recv_payload: &'a mut [u8],
}

impl<C: Crypto> InitializeState<C> {
    pub fn initialize(
        aad: &[u8],
        secret_key_bundle: Arc<SecretBundle<C::PublicSigningKey, C::SecretSigningKey>>,
        resumption: Option<Resumption<C>>,
        payload: Box<[u8]>,
    ) -> Result<InitializeState<C>, InitError> {
        use initialize::*;

        /* HANDSHAKE LEN AND FLAGS HANDLING */

        let mut init_message = Vec::new();

        if resumption.is_some() {
            // In this case, we want to use the resumption key to resume this socket with 1-rtt.
            init_message.resize(PAYLOAD_START + payload.len() + PAYLOAD_REV_START, 0);
        } else {
            // In this case, we have no resumption key and want to start from scratch with 2-rtt.
            init_message.resize(EPHEMERAL_ENC_KEY_END, 0);
        }

        /* MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

        let (encapsulation_key, decapsulation_key) = C::DecapsulationKey::generate();
        init_message[EPHEMERAL_ENC_KEY_RANGE].copy_from_slice(&encapsulation_key);

        /* RESUMPTION TOKEN HANDLING */

        let mut fallback = None;
        let mut remote_key_bundle = None;
        let mut symmetric = SymmetricState::<C>::new(aad);

        if let Some(resumption) = resumption {
            init_message[RESUMPTION_TOKEN_RANGE].copy_from_slice(&resumption.token[..]);

            symmetric.mix(9, &init_message[..RESUMPTION_TOKEN_END]);

            // If we are allowing fallback we need the symmetric state from before mixing the
            // secret resumption key.
            fallback = Some(symmetric.clone());

            symmetric.mix(10, &resumption.key[..]);

            /* RESUMPTION HANDLING */

            let payload_end = init_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = init_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = init_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = init_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = init_message.len() - ONLINE_SIGN_TAG_REV_END;

            /* KEY BUNDLE CHECKSUM HANDLING */

            let mut bundle_hasher = C::Hasher::new();
            bundle_hasher.update(&symmetric.channel_binding());
            bundle_hasher.update(secret_key_bundle.bundle_hash());
            bundle_hasher.update(resumption.remote_key_bundle.bundle_hash());

            bundle_hasher.finish(&mut init_message[KEY_BUNDLE_CHECKSUM_RANGE]);

            /* PAYLOAD ENCODING */

            init_message[PAYLOAD_START..payload_end].copy_from_slice(&payload[..]);

            symmetric.encrypt_and_mix(11, &mut init_message[KEY_BUNDLE_CHECKSUM_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let sign = secret_key_bundle.sign(domain::INITIALIZE_BINDING, &symmetric.channel_binding());
            init_message[online_sign_start..online_sign_end].copy_from_slice(&sign);

            symmetric.encrypt_and_mix(12, &mut init_message[online_sign_start..online_sign_tag_end]);

            if let Some(fallback) = &mut fallback {
                // A fallback handshake must still authenticate the entire init message.
                fallback.mix(14, &init_message[RESUMPTION_TOKEN_END..]);
            }

            remote_key_bundle = Some(resumption.remote_key_bundle);
        } else {
            /* FULL HANDSHAKE HANDLING */

            symmetric.mix(1, &init_message[..]);
        }

        Ok(InitializeState {
            symmetric,
            fallback,
            decapsulation_key,
            payload,
            secret_key_bundle,
            remote_key_bundle,
        })
    }

    pub fn process_reply<'a>(mut self, reply_message: &'a mut [u8]) -> Result<HandshakeFinished<'a, C>, Error> {
        let handshake_type;
        let remote_key_bundle;
        let recv_payload;
        let mut symmetric;
        {
            use reply::*;

            if reply_message.len() < PAYLOAD_START + PAYLOAD_REV_START {
                return Err(Error::Invalid);
            }

            /* HANDSHAKE FLAGS HANDLING */

            handshake_type = reply_message[HANDSHAKE_TYPE_IDX];

            if handshake_type > HANDSHAKE_TYPE_MAX {
                return Err(Error::Invalid);
            } else if handshake_type == HANDSHAKE_TYPE_FALLBACK {
                symmetric = self.fallback.ok_or(Error::Inauthentic)?;
            } else {
                symmetric = self.symmetric;
            }

            /* MLKEM1024 CIPHERTEXT HANDLING */

            let ciphertext = (&reply_message[EPHEMERAL_CIPHERTEXT_RANGE]).try_into().unwrap();

            let shared_secret = Zeroizing::new(
                self.decapsulation_key
                    .decapsulate(ciphertext)
                    .ok_or(Error::Inauthentic)?,
            );

            symmetric.mix(2, &reply_message[..EPHEMERAL_CIPHERTEXT_END]);
            symmetric.mix(3, &shared_secret[..]);

            /* PAYLOAD HANDLING */

            let payload_end = reply_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = reply_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = reply_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = reply_message.len() - ONLINE_SIGN_TAG_REV_START;

            symmetric.decrypt_and_mix(4, &mut reply_message[PAYLOAD_START..payload_tag_end])?;

            let key_bundle_end;
            if handshake_type != HANDSHAKE_TYPE_RESUME {
                /* KEY BUNDLE HANDLING */

                let mixed_payload = &reply_message[PAYLOAD_START..payload_end];
                let result = AuthenticBundle::authenticate::<C::Hasher>(mixed_payload);
                let (key_bundle, key_bundle_len) = result.map_err(|_| Error::Inauthentic)?;
                remote_key_bundle = Arc::new(key_bundle);

                key_bundle_end = PAYLOAD_START + key_bundle_len;

                if handshake_type == HANDSHAKE_TYPE_FALLBACK
                    && ((remote_key_bundle.flags() & self.secret_key_bundle.flags())
                        & key_bundle::FLAG_RELIABLE_STORAGE)
                        > 0
                {
                    return Err(Error::Inauthentic);
                }

                if let Some(expected_key_bundle) = self.remote_key_bundle {
                    /* If the offline hashes are not equal then we are not connecting with the party we
                    intended to connect to. A party's offline key is their id and it must never change. */
                    if !expected_key_bundle.offline_eq(&remote_key_bundle) {
                        return Err(Error::Inauthentic);
                    }
                }
            } else if let Some(key_bundle) = self.remote_key_bundle {
                remote_key_bundle = key_bundle;
                key_bundle_end = PAYLOAD_START;
            } else {
                return Err(Error::Invalid);
            }

            /* ONLINE SIGNATURE HANDLING */

            symmetric.decrypt_and_mix(5, &mut reply_message[online_sign_start..online_sign_tag_end])?;

            let sign = (&reply_message[online_sign_start..online_sign_end]).try_into().unwrap();
            remote_key_bundle
                .verify(domain::REPLY_BINDING, &symmetric.channel_binding(), sign)
                .map_err(|_| Error::Inauthentic)?;

            recv_payload = &mut reply_message[key_bundle_end..payload_end];
            if handshake_type == HANDSHAKE_TYPE_RESUME {
                /* SPLIT */

                return Ok(HandshakeFinished {
                    message_to_send: None,
                    keys: symmetric.split(13),
                    remote_key_bundle,
                    recv_payload,
                });
            }
        }
        {
            use confirm::*;

            let local_key_bundle = self.secret_key_bundle.public_bundle_bytes();

            let key_bundle_end = PAYLOAD_START + local_key_bundle.len();
            let payload_end = key_bundle_end + self.payload.len();
            let payload_tag_end = payload_end + PAYLOAD_TAG_LEN;
            let online_sign_start = payload_tag_end;
            let online_sign_end = online_sign_start + ONLINE_SIGN_LEN;
            let online_sign_tag_end = online_sign_end + ONLINE_SIGN_TAG_LEN;

            let mut confirm_message = vec![0; online_sign_tag_end];

            /* PAYLOAD HANDLING */

            confirm_message[PAYLOAD_START..key_bundle_end].copy_from_slice(local_key_bundle);

            confirm_message[key_bundle_end..payload_end].copy_from_slice(&self.payload[..]);

            symmetric.encrypt_and_mix(6, &mut confirm_message[PAYLOAD_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let sign = self
                .secret_key_bundle
                .sign(domain::CONFIRM_BINDING, &symmetric.channel_binding());
            confirm_message[online_sign_start..online_sign_end].copy_from_slice(&sign);

            symmetric.encrypt_and_mix(7, &mut confirm_message[online_sign_start..online_sign_tag_end]);

            Ok(HandshakeFinished {
                message_to_send: Some(confirm_message),
                keys: symmetric.split(8),
                remote_key_bundle,
                recv_payload,
            })
        }
    }

    pub fn secret_key_bundle(&self) -> &Arc<SecretBundle<C::PublicSigningKey, C::SecretSigningKey>> {
        &self.secret_key_bundle
    }
    pub fn remote_key_bundle(&self) -> &AuthenticBundle<C::PublicSigningKey> {
        &self.secret_key_bundle
    }
}
