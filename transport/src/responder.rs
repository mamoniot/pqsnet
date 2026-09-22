use zeroize::Zeroizing;

use crate::{
    crypto::prelude::*,
    key_bundle::{AuthenticBundle, OFFLINE_HASH_LEN},
    protocol::*,
    session_layer::SessionLayer,
    symmetric_state::{SymmetricKeys, SymmetricState},
};

pub(crate) struct ReplyState<S: SessionLayer> {
    symmetric: SymmetricState<S>,
    expected_offline_hash: Option<[u8; OFFLINE_HASH_LEN]>,
}

pub enum ResponseOk<'a, S: SessionLayer> {
    Complete(SymmetricKeys, &'a mut [u8]),
    Incomplete(Vec<u8>, ReplyState<S>),
}

pub enum Error {
    Invalid,
    Inauthentic,
    InvalidPayload,
}

impl From<crate::error::Error> for Error {
    fn from(value: crate::error::Error) -> Self {
        todo!()
    }
}

impl<S: SessionLayer> ReplyState<S> {
    /// Reserves a socket in the socket table for use.
    /// Reserved sockets cannot receive packets and cannot be reserved twice simultaneously.
    /// If this socket is dropped, its socket id is unreserved, preventing a memory leak.
    /// This guard does not hold any locks and cannot cause a deadlock.
    pub(crate) fn init<'a>(
        mut sl: S,
        aad: &[u8],
        init_message: &'a mut [u8],
        create_payload: impl FnOnce(&mut Vec<u8>),
    ) -> Result<ResponseOk<'a, S>, Error> {
        use shared::*;
        let mut symmetric = SymmetricState::<S>::default();

        let shared_secret;
        let ciphertext;
        let private_key_bundle;
        // `handshake_flags` may only be or'd into.
        // TODO: improve this system.
        let mut handshake_flags;
        let mut recv_payload = None;
        let mut fallback = false;
        let mut expected_offline_hash = None;
        {
            use initialize::*;

            if init_message.len() < EPHEMERAL_ENC_KEY_END {
                return Err(Error::Invalid);
            }

            /* START OF HANDSHAKE VERSION AND FLAGS HANDLING */

            handshake_flags = init_message[HANDSHAKE_FLAGS_IDX];

            /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let ephemeral_enc_key = &init_message[EPHEMERAL_ENC_KEY_RANGE];
            let result = S::DecapsulationKeyImpl::encapsulate(ephemeral_enc_key.try_into().unwrap());
            let (ss, c) = result.ok_or(Error::Inauthentic)?;
            ciphertext = c;
            shared_secret = Zeroizing::new(ss);

            /* START OF RESUMPTION TOKEN HANDLING */

            if handshake_flags & HANDSHAKE_FLAGS_USE_RESUMPTION > 0 {
                if init_message.len() < PAYLOAD_START + PAYLOAD_REV_START {
                    return Err(Error::Invalid);
                }

                symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_RANGE]);

                let resumption_token = (&init_message[RESUMPTION_TOKEN_RANGE]).try_into().unwrap();

                if let Some((resumption_key, resumption_key_bundle)) = sl.lookup_resumption_key(resumption_token) {
                    let payload_end = init_message.len() - PAYLOAD_REV_START;
                    let payload_tag_start = init_message.len() - PAYLOAD_TAG_REV_END;
                    let payload_tag_end = init_message.len() - PAYLOAD_TAG_REV_START;
                    let online_sign_start = init_message.len() - ONLINE_SIGNATURE_REV_END;
                    let online_sign_end = init_message.len() - ONLINE_SIGNATURE_REV_START;
                    let online_sign_tag_end = init_message.len() - ONLINE_SIGNATURE_TAG_REV_START;

                    handshake_flags |= HANDSHAKE_FLAGS_DENY_FALLBACK;

                    symmetric.mix(&resumption_key[..]);

                    let checksum_channel_binding = symmetric.channel_binding();

                    /* START OF PAYLOAD HANDLING */

                    symmetric.decrypt_and_mix(&mut init_message[PAYLOAD_START..payload_tag_end])?;

                    let payload_len = u16::from_be_bytes(init_message[PAYLOAD_LEN_RANGE].try_into().unwrap()) as usize;
                    if payload_len != payload_end - PAYLOAD_START {
                        return Err(Error::Invalid);
                    }

                    private_key_bundle = sl.private_key_bundle();

                    let mut bundle_hasher = S::Shake256Impl::new();
                    bundle_hasher.update(&checksum_channel_binding);
                    bundle_hasher.update(&resumption_key_bundle.uid.to_be_bytes());
                    bundle_hasher.update(&private_key_bundle.uid.to_be_bytes());

                    let mut local_checksum = [0; KEY_BUNDLE_CHECKSUM_LEN];
                    bundle_hasher.finish(&mut local_checksum);

                    let remote_checksum = &init_message[KEY_BUNDLE_CHECKSUM_RANGE];
                    let has_correct_keys = &local_checksum[..] == remote_checksum;

                    /* An incorrect bundle xor indicates one party currently has an outdated or
                    incorrect public key of the other party. So we need to do a full handshake to
                    re-exchange public keys. */
                    if !has_correct_keys {
                        handshake_flags |= HANDSHAKE_FLAGS_FULL_HANDSHAKE;
                    }

                    if !resumption_key_bundle.check_handshake_flags(handshake_flags) {
                        return Err(Error::Inauthentic);
                    }

                    recv_payload = Some(&init_message[PAYLOAD_START..payload_end]);

                    /* START OF ONLINE SIGNATURE HANDLING */

                    let signature_channel_binding = symmetric.channel_binding();

                    symmetric.decrypt_and_mix(&mut init_message[online_sign_start..online_sign_tag_end])?;

                    /* Authentication of the initiator's signature is skipped when doing a full
                    handshake if the initiator has the incorrect keys. A full handshake will
                    force the initiator to send a second, better signature later. */
                    if has_correct_keys {
                        resumption_key_bundle
                            .verify(
                                domain::INITIALIZE_BINDING,
                                &signature_channel_binding,
                                (&init_message[online_sign_start..online_sign_end]).try_into().unwrap(),
                            )
                            .map_err(|_| Error::Inauthentic)?;
                    }

                    expected_offline_hash = Some(resumption_key_bundle.offline_hash);
                } else {
                    /* START OF UNRESUMED FALLBACK */

                    // We need to thoroughly check if fallback is enabled by the handshake flags and
                    // by our private key flags.
                    if handshake_flags & HANDSHAKE_FLAGS_DENY_FALLBACK > 0 {
                        return Err(Error::Inauthentic);
                    }
                    // In order to perform fallback a full handshake is required.
                    handshake_flags |= HANDSHAKE_FLAGS_FULL_HANDSHAKE;

                    // The full transcript of this exchange must be mixed into the symmetric state.
                    // So the remaining portion of the message is mixed to authenticate it.
                    symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_END..]);

                    private_key_bundle = sl.private_key_bundle();
                }
            } else {
                /* START OF UNRESUMED HANDLING */

                if init_message.len() != EPHEMERAL_ENC_KEY_END {
                    return Err(Error::Invalid);
                }

                // There will be no resumption so just hash the premessage and move on.
                symmetric.mix(&init_message[PREMESSAGE_UNRESUMED_RANGE]);
                private_key_bundle = sl.private_key_bundle();
            }

            if !private_key_bundle.check_handshake_flags(handshake_flags) {
                return Err(Error::Inauthentic);
            }
        }

        /* START OF REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

        let do_full = handshake_flags & HANDSHAKE_FLAGS_FULL_HANDSHAKE > 0;

        let mut reply_message = Vec::new();
        {
            use reply::*;
            reply_message.resize(PAYLOAD_START, 0);

            /* START OF HANDSHAKE VERSION AND FLAGS HANDLING */

            reply_message[HANDSHAKE_FLAGS_IDX] = handshake_flags;

            /* START OF MLKEM1024 CIPHERTEXT HANDLING */

            reply_message[EPHEMERAL_CIPHERTEXT_RANGE].copy_from_slice(&ciphertext);

            symmetric.mix(&reply_message[PREMESSAGE_RANGE]);

            symmetric.mix(shared_secret.as_ref());

            /* START OF PAYLOAD HANDLING */

            create_payload(&mut reply_message);
            let Ok(payload_len) = u16::try_from(reply_message.len() as isize - PAYLOAD_START as isize) else {
                return Err(Error::InvalidPayload);
            };
            reply_message[PAYLOAD_LEN_RANGE].copy_from_slice(&payload_len.to_be_bytes());
        };
        if do_full {
            /* START OF REPLY ENCODING */

            use reply::*;

            /* START OF KEY BUNDLE HANDLING */

            reply_message.extend_from_slice(private_key_bundle.public_bundle_bytes());

            let key_bundle_end = reply_message.len();

            let payload_tag_end = key_bundle_end + PAYLOAD_TAG_LEN;
            let online_signature_start = payload_tag_end;
            let online_signature_end = online_signature_start + ONLINE_SIGNATURE_LEN;
            let online_signature_tag_end = online_signature_end + ONLINE_SIGNATURE_TAG_LEN;

            /* START OF PAYLOAD HANDLING */

            reply_message.resize(online_signature_tag_end, 0);

            symmetric.encrypt_and_mix(&mut reply_message[PAYLOAD_LEN_START..payload_tag_end]);

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let signature = private_key_bundle.sign(domain::REPLY_BINDING, &symmetric.channel_binding());
            reply_message[online_signature_start..online_signature_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut reply_message[online_signature_start..online_signature_tag_end]);

            /* START OF STATE MANAGEMENT */

            Ok(ResponseOk::Incomplete(
                reply_message,
                ReplyState { symmetric, expected_offline_hash },
            ))
        } else {
            /* START OF RESUME ENCODING */

            use resume::*;
            let payload_end = reply_message.len();
            let payload_tag_end = payload_end + PAYLOAD_TAG_LEN;
            let online_signature_start = payload_tag_end;
            let online_signature_end = online_signature_start + ONLINE_SIGNATURE_LEN;
            let online_signature_tag_end = online_signature_end + ONLINE_SIGNATURE_TAG_LEN;

            /* START OF PAYLOAD HANDLING */

            reply_message.resize(online_signature_tag_end, 0);

            symmetric.encrypt_and_mix(&mut reply_message[PAYLOAD_LEN_START..payload_tag_end]);

            /* START OF ONLINE SIGNATURE HANDLING */

            let signature = private_key_bundle.sign(domain::RESUME_BINDING, &symmetric.channel_binding());
            reply_message[online_signature_start..online_signature_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut reply_message[online_signature_start..online_signature_tag_end]);

            // TODO: Add resumption token and key handling.

            Ok(ResponseOk::Complete(symmetric.split(), recv_payload))
        }
    }

    pub(crate) fn confirm<'a>(self, confirm_message: &'a mut [u8]) -> Result<(SymmetricKeys, &'a mut [u8]), Error> {
        let mut symmetric = self.symmetric;

        let recv_payload;
        {
            use confirm::*;
            if confirm_message.len() < PAYLOAD_START + KEY_BUNDLE_REV_START {
                return Err(Error::Invalid);
            }

            let key_bundle_end = confirm_message.len() - KEY_BUNDLE_REV_START;
            let payload_tag_end = confirm_message.len() - PAYLOAD_TAG_REV_START;
            let online_signature_start = confirm_message.len() - ONLINE_SIGNATURE_REV_END;
            let online_signature_end = confirm_message.len() - ONLINE_SIGNATURE_REV_START;
            let online_signature_tag_end = confirm_message.len() - ONLINE_SIGNATURE_TAG_REV_START;

            /* START OF PAYLOAD AND KEY BUNDLE HANDLING */

            symmetric.decrypt_and_mix(&mut confirm_message[PAYLOAD_LEN_START..payload_tag_end])?;

            let payload_len = u16::from_be_bytes(confirm_message[PAYLOAD_LEN_RANGE].try_into().unwrap()) as usize;

            let payload_end = PAYLOAD_START + payload_len;
            let key_bundle_start = payload_end;
            if key_bundle_start >= key_bundle_end {
                return Err(Error::Invalid);
            }

            let key_bundle = AuthenticBundle::<S::PublicSigningKeyImpl>::authenticate::<S::Shake256Impl>(
                &confirm_message[key_bundle_start..key_bundle_end],
            )
            .map_err(|_| Error::Inauthentic)?;

            if let Some(expected_offline_hash) = self.expected_offline_hash {
                /* If the offline hashes are not equal then we are not connecting with the party we
                intended to connect to. A party's offline key is their id and it must never change. */
                if key_bundle.offline_hash != expected_offline_hash {
                    return Err(Error::Inauthentic);
                }
            }

            /* START OF MLDSA87 HANDLING */

            let channel_binding = symmetric.channel_binding();

            symmetric.decrypt_and_mix(&mut confirm_message[online_signature_start..online_signature_tag_end])?;

            key_bundle
                .verify(
                    domain::REPLY_BINDING,
                    &channel_binding,
                    (&confirm_message[online_signature_start..online_signature_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;

            recv_payload = &mut confirm_message[PAYLOAD_START..payload_end];
        }

        Ok((symmetric.split(), recv_payload))
    }
}
