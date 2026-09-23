use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{
    crypto::prelude::*,
    error::{Error, InitError},
    key_bundle::{AuthenticBundle, PrivateBundleSL},
    protocol::{
        flags::*,
        *,
    },
    session_layer::{ResumptionKey, ResumptionToken, SessionLayer},
    symmetric_state::{SymmetricKeys, SymmetricState},
};

pub struct InitializeState<S: SessionLayer> {
    symmetric: SymmetricState<S>,
    fallback: Option<SymmetricState<S>>,
    decapsulation_key: S::DecapsulationKeyImpl,
    payload: Box<[u8]>,
    private_key_bundle: PrivateBundleSL<S>,
    remote_key_bundle: Option<Arc<AuthenticBundle<S::PublicSigningKeyImpl>>>,
}

impl<S: SessionLayer> InitializeState<S> {
    pub fn initialize(
        mut sl: S,
        aad: &[u8],
        resumption: Option<(
            &ResumptionToken,
            &ResumptionKey,
            Arc<AuthenticBundle<S::PublicSigningKeyImpl>>,
        )>,
        payload: Box<[u8]>,
    ) -> Result<InitializeState<S>, InitError> {
        use initialize::*;

        /* HANDSHAKE LEN AND FLAGS HANDLING */

        let private_key_bundle = sl.private_key_bundle();

        let mut init_message = Vec::new();

        let mut init_flags = private_key_bundle.flags as u8 & HANDSHAKE_FLAGS_MASK;
        if let Some((_, _, key_bundle)) = &resumption {
            init_flags |= key_bundle.flags as u8 & HANDSHAKE_FLAGS_MASK;
        }

        if resumption.is_some() {
            init_flags |= HANDSHAKE_FLAG_USE_RESUMPTION;
            // In this case, we want to use the resumption key to resume this socket with 1-rtt.
            init_message.resize(PAYLOAD_START + payload.len() + PAYLOAD_REV_START, 0);
        } else if init_flags & HANDSHAKE_FLAG_USE_RESUMPTION > 0 {
            return Err(InitError::ResumptionKeyRequired);
        } else {
            // In this case, we have no resumption key and want to start from scratch with 2-rtt.
            init_message.resize(EPHEMERAL_ENC_KEY_END, 0);
        }

        /* MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

        let (encapsulation_key, decapsulation_key) = S::DecapsulationKeyImpl::generate();
        init_message[EPHEMERAL_ENC_KEY_RANGE].copy_from_slice(&encapsulation_key);


        /* RESUMPTION TOKEN HANDLING */

        let mut fallback = None;
        let mut remote_key_bundle = None;
        let mut symmetric = SymmetricState::<S>::new(aad);

        if let Some((token, key, key_bundle)) = resumption {
            debug_assert!(init_flags & HANDSHAKE_FLAG_USE_RESUMPTION > 0);

            init_message[RESUMPTION_TOKEN_RANGE].copy_from_slice(token);

            symmetric.mix(&init_message[..RESUMPTION_TOKEN_END]);

            if init_flags & HANDSHAKE_FLAG_DENY_FALLBACK == 0 {
                // If we are allowing fallback we need the symmetric state from before mixing the
                // secret resumption key.
                fallback = Some(symmetric.clone())
            }

            symmetric.mix(&key[..]);

            /* RESUMPTION HANDLING */

            let payload_end = init_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = init_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = init_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = init_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = init_message.len() - ONLINE_SIGN_TAG_REV_END;

            /* KEY BUNDLE CHECKSUM HANDLING */

            let mut bundle_hasher = S::Shake256Impl::new();
            bundle_hasher.update(&symmetric.channel_binding());
            bundle_hasher.update(&private_key_bundle.bundle_hash);
            bundle_hasher.update(&key_bundle.bundle_hash);

            bundle_hasher.finish(&mut init_message[KEY_BUNDLE_CHECKSUM_RANGE]);

            /* PAYLOAD ENCODING */

            init_message[PAYLOAD_START..payload_end].copy_from_slice(&payload[..]);

            symmetric.encrypt_and_mix(&mut init_message[KEY_BUNDLE_CHECKSUM_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let sign = private_key_bundle.sign(domain::INITIALIZE_BINDING, &symmetric.channel_binding());
            init_message[online_sign_start..online_sign_end].copy_from_slice(&sign);

            symmetric.encrypt_and_mix(&mut init_message[online_sign_start..online_sign_tag_end]);

            if let Some(fallback) = &mut fallback {
                // A fallback handshake must still authenticate the entire init message.
                fallback.mix(&init_message[RESUMPTION_TOKEN_END..]);
            }

            remote_key_bundle = Some(key_bundle);
        } else {
            /* FULL HANDSHAKE HANDLING */

            symmetric.mix(&init_message[..]);
        }

        Ok(InitializeState {
            symmetric,
            fallback,
            decapsulation_key,
            payload,
            private_key_bundle,
            remote_key_bundle,
        })
    }

    pub fn process_response<'a>(
        mut self,
        mut sl: S,
        reply_message: &'a mut [u8],
    ) -> Result<(Option<Vec<u8>>, Arc<AuthenticBundle<S::PublicSigningKeyImpl>>, SymmetricKeys, &'a mut [u8]), Error> {

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
            } else if handshake_type != HANDSHAKE_TYPE_FALLBACK {
                symmetric = self.symmetric;
            } else {
                symmetric = self.fallback.ok_or(Error::Inauthentic)?;
            }

            /* MLKEM1024 CIPHERTEXT HANDLING */

            let ciphertext = (&reply_message[EPHEMERAL_CIPHERTEXT_RANGE]).try_into().unwrap();

            let shared_secret = Zeroizing::new(self.decapsulation_key.decapsulate(ciphertext).ok_or(Error::Inauthentic)?);

            symmetric.mix(&reply_message[..EPHEMERAL_CIPHERTEXT_END]);
            symmetric.mix(&shared_secret[..]);

            /* PAYLOAD HANDLING */

            let payload_end = reply_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = reply_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = reply_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = reply_message.len() - ONLINE_SIGN_TAG_REV_START;

            symmetric.decrypt_and_mix(&mut reply_message[PAYLOAD_START..payload_tag_end])?;

            let key_bundle_end;
            if handshake_type != HANDSHAKE_TYPE_RESUME {
                /* KEY BUNDLE HANDLING */

                let (key_bundle, key_bundle_len) = AuthenticBundle::authenticate_and_get_len::<S::Shake256Impl>(&reply_message[PAYLOAD_START..payload_end])
                        .map_err(|_| Error::Inauthentic)?;

                key_bundle_end = PAYLOAD_START + key_bundle_len;

                if let Some(expected_key_bundle) = self.remote_key_bundle {
                    /* If the offline hashes are not equal then we are not connecting with the party we
                    intended to connect to. A party's offline key is their id and it must never change. */
                    if expected_key_bundle.offline_hash != key_bundle.offline_hash {
                        return Err(Error::Inauthentic);
                    }
                }

                remote_key_bundle = key_bundle;
            } else if let Some(key_bundle) = self.remote_key_bundle {
                remote_key_bundle = key_bundle;
                key_bundle_end = PAYLOAD_START;
            } else {
                return Err(Error::Invalid);
            }

            /* ONLINE SIGNATURE HANDLING */

            symmetric.decrypt_and_mix(&mut reply_message[online_sign_start..online_sign_tag_end])?;

            remote_key_bundle
                .verify(
                    domain::REPLY_BINDING,
                    &symmetric.channel_binding(),
                    (&reply_message[online_sign_start..online_sign_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;

            recv_payload = &mut reply_message[key_bundle_end..payload_end];
            if handshake_type == HANDSHAKE_TYPE_RESUME {
                /* SPLIT */

                return Ok((None, remote_key_bundle, symmetric.split(), recv_payload));
            }
        }
        {
            use confirm::*;

            let local_key_bundle = self.private_key_bundle.public_bundle_bytes();

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

            symmetric.encrypt_and_mix(&mut confirm_message[PAYLOAD_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let sign = self.private_key_bundle.sign(domain::CONFIRM_BINDING, &symmetric.channel_binding());
            confirm_message[online_sign_start..online_sign_end].copy_from_slice(&sign);

            symmetric.encrypt_and_mix(&mut confirm_message[online_sign_start..online_sign_tag_end]);

            /* STATE MANAGEMENT */

            Ok((Some(confirm_message), remote_key_bundle, symmetric.split(), recv_payload))
        }
    }
}
