use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{
    crypto::prelude::*,
    error::{Error, InitError},
    key_bundle::{AuthenticBundle, PrivateBundleSL, check_handshake_flags},
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
    init_flags: u8,
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
            if init_flags & HANDSHAKE_FLAG_FULL_HANDSHAKE > 0 {
                // In this case, we want to use the resumption key while also completing the full,
                // 2-rtt handshake.
                init_message.resize(FULL_HANSHAKE_RESUMPTION_LEN, 0);
            } else {
                // In this case, we want to use the resumption key to resume this socket with 1-rtt.
                init_message.resize(RESUMTION_LEN_MIN + payload.len(), 0);
            }
        } else if init_flags & HANDSHAKE_FLAG_USE_RESUMPTION > 0 {
            return Err(InitError::ResumptionKeyRequired);
        } else {
            // In this case, we have no resumption key and want to start from scratch with 2-rtt.
            init_message.resize(FULL_HANSHAKE_LEN, 0);
        }

        /* HANDSHAKE VERSION AND FLAGS ENCODING */

        init_message[HANDSHAKE_FLAGS_IDX] = init_flags;

        /* MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

        let (encapsulation_key, decapsulation_key) = S::DecapsulationKeyImpl::generate();
        init_message[EPHEMERAL_ENC_KEY_RANGE].copy_from_slice(&encapsulation_key);

        /* RESUMPTION TOKEN HANDLING */

        let mut symmetric = SymmetricState::<S>::new(aad);
        let mut fallback = None;
        let mut remote_key_bundle = None;

        if let Some((token, key, key_bundle)) = resumption {
            debug_assert!(init_flags & HANDSHAKE_FLAG_USE_RESUMPTION > 0);

            init_message[RESUMPTION_TOKEN_RANGE].copy_from_slice(token);

            symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_RANGE]);

            if init_flags & HANDSHAKE_FLAG_DENY_FALLBACK == 0 {
                // If we are allowing fallback we need the symmetric state from before mixing the
                // secret resumption key.
                fallback = Some(symmetric.clone())
            }

            symmetric.mix(&key[..]);

            if init_flags & HANDSHAKE_FLAG_FULL_HANDSHAKE > 0 {
                /* FULL HANDSHAKE RESUMPTION HANDLING */

                // We are doing a full handshake so the payload gets sent later.
                symmetric.encrypt_and_mix(&mut init_message[FULL_HANDSHAKE_RESUMPTION_TAG_RANGE]);
            } else {
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
            }

            if let Some(fallback) = &mut fallback {
                // A fallback handshake must still authenticate the entire init message.
                fallback.mix(&init_message[PREMESSAGE_RESUMPTION_END..]);
            }

            remote_key_bundle = Some(key_bundle);
        } else {
            /* FULL HANDSHAKE HANDLING */

            symmetric.mix(&init_message[PREMESSAGE_FULL_HANDSHAKE_RANGE]);
        }

        Ok(InitializeState {
            symmetric,
            fallback,
            init_flags,
            decapsulation_key,
            payload,
            private_key_bundle,
            remote_key_bundle,
        })
    }

    pub(crate) fn process_response<'a>(
        mut self,
        mut sl: S,
        response_message: &'a mut [u8],
    ) -> Result<(Option<Vec<u8>>, Arc<AuthenticBundle<S::PublicSigningKeyImpl>>, SymmetricKeys, &'a mut [u8]), Error> {
        use flags::*;

        /* REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

        let response_flags;
        let payload_len;
        let mut symmetric;
        {
            use reply::*;

            if response_message.len() < MESSAGE_MIN_LEN {
                return Err(Error::Invalid);
            }

            /* HANDSHAKE FLAGS HANDLING */

            response_flags = response_message[HANDSHAKE_FLAGS_IDX];
            if !check_handshake_flags(self.init_flags, response_flags) {
                // Do not allow a flag downgrade.
                return Err(Error::Inauthentic);
            }

            // If this message does not have the deny fallback flag we assume we must fallback.
            if response_flags & HANDSHAKE_FLAG_DENY_FALLBACK > 0 {
                symmetric = self.symmetric;
            } else {
                symmetric = self.fallback.ok_or(Error::Inauthentic)?;
            }

            /* MLKEM1024 CIPHERTEXT HANDLING */

            symmetric.mix(&response_message[PREMESSAGE_RANGE]);

            let ciphertext = (&response_message[EPHEMERAL_CIPHERTEXT_RANGE]).try_into().unwrap();

            let shared_secret = Zeroizing::new(self.decapsulation_key.decapsulate(ciphertext).ok_or(Error::Inauthentic)?);

            symmetric.mix(&shared_secret[..]);

            /* PAYLOAD HANDLING */

            let payload_tag_end = response_message.len() - PAYLOAD_TAG_REV_START;

            symmetric.decrypt_and_mix(&mut response_message[PAYLOAD_LEN_START..payload_tag_end])?;

            payload_len =
                u16::from_be_bytes(response_message[PAYLOAD_LEN_RANGE].try_into().unwrap()) as usize;
        }

        let key_bundle;
        if response_flags & HANDSHAKE_FLAG_FULL_HANDSHAKE > 0 {
            /* REPLY DECODING */

            use reply::*;
            let payload_end = PAYLOAD_LEN_START + payload_len;
            let key_bundle_start = payload_end;
            let key_bundle_end = response_message.len() - KEY_BUNDLE_REV_START;
            let payload_tag_end = response_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = response_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = response_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = response_message.len() - ONLINE_SIGN_TAG_REV_START;

            if key_bundle_start >= key_bundle_end {
                return Err(Error::Invalid);
            }

            /* KEY BUNDLE HANDLING */

            key_bundle = AuthenticBundle::authenticate::<S::Shake256Impl>(&response_message[key_bundle_start..key_bundle_end])
                    .map_err(|_| Error::Inauthentic)?;

            if !key_bundle.check_handshake_flags(response_flags) {
                return Err(Error::Inauthentic);
            }

            if let Some(expected_key_bundle) = self.remote_key_bundle {
                /* If the offline hashes are not equal then we are not connecting with the party we
                intended to connect to. A party's offline key is their id and it must never change. */
                if expected_key_bundle.offline_hash != key_bundle.offline_hash {
                    return Err(Error::Inauthentic);
                }
            }

            /* ONLINE SIGNATURE HANDLING */

            symmetric.decrypt_and_mix(&mut response_message[online_sign_start..online_sign_tag_end])?;

            key_bundle
                .verify(
                    domain::REPLY_BINDING,
                    &symmetric.channel_binding(),
                    (&response_message[online_sign_start..online_sign_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;
        } else if let Some(key_bundle) = self.remote_key_bundle {
            /* RESUME DECODING */

            use resume::*;
            let payoad_end = response_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = response_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = response_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = response_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = response_message.len() - ONLINE_SIGN_TAG_REV_START;

            if PAYLOAD_START >= payoad_end {
                return Err(Error::Invalid);
            }

            /* ONLINE SIGNATURE HANDLING */

            symmetric.decrypt_and_mix(&mut response_message[online_sign_start..online_sign_tag_end])?;

            key_bundle
                .verify(
                    domain::RESUME_BINDING,
                    &symmetric.channel_binding(),
                    (&response_message[online_sign_start..online_sign_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;


            /* STATE MANAGEMENT */
            // TODO: Add session layer authentication here.

            return Ok((None, key_bundle, symmetric.split(), &mut response_message[PAYLOAD_START..PAYLOAD_START + payload_len]));
        } else {
            // If we do not know the responder's key bundle we cannot accept a resume message.
            return Err(Error::Inauthentic);
        }
        {
            use confirm::*;

            let local_key_bundle = self.private_key_bundle.public_bundle_bytes();

            let payload_end = PAYLOAD_LEN_START + self.payload.len();
            let key_bundle_start = payload_end;
            let key_bundle_end = key_bundle_start + local_key_bundle.len();
            let payload_tag_end = key_bundle_end + PAYLOAD_TAG_LEN;
            let online_sign_start = payload_tag_end;
            let online_sign_end = online_sign_start + ONLINE_SIGN_LEN;
            let online_sign_tag_end = online_sign_end + ONLINE_SIGN_TAG_LEN;

            let mut confirm_message = vec![0; online_sign_tag_end];

            /* PAYLOAD HANDLING */

            confirm_message[PAYLOAD_LEN_RANGE].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
            confirm_message[PAYLOAD_START..payload_end].copy_from_slice(&self.payload[..]);

            /* KEY BUNDLE HANDLING */

            confirm_message[key_bundle_start..key_bundle_end].copy_from_slice(local_key_bundle);

            symmetric.encrypt_and_mix(&mut confirm_message[PAYLOAD_LEN_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let sign = self.private_key_bundle.sign(domain::CONFIRM_BINDING, &symmetric.channel_binding());
            confirm_message[online_sign_start..online_sign_end].copy_from_slice(&sign);

            symmetric.encrypt_and_mix(&mut confirm_message[online_sign_start..online_sign_tag_end]);

            /* STATE MANAGEMENT */

            Ok((Some(confirm_message), key_bundle, symmetric.split(), &mut response_message[PAYLOAD_START..PAYLOAD_START + payload_len]))
        }
    }
}
