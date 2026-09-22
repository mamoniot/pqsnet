use zeroize::Zeroizing;

use crate::{
    crypto::prelude::*,
    error::ReplyError,
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
    Complete(Vec<u8>, SymmetricKeys, &'a mut [u8]),
    Incomplete(Vec<u8>, ReplyState<S>),
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
    ) -> Result<ResponseOk<'a, S>, ReplyError> {
        use flags::*;
        let mut symmetric = SymmetricState::<S>::new(aad);

        let shared_secret;
        let ciphertext;
        let private_key_bundle = sl.private_key_bundle();
        // `handshake_flags` may only be or'd into.
        // TODO: improve this system.
        let mut response_flags;
        let mut recv_payload = None;
        let mut expected_offline_hash = None;
        {
            use initialize::*;

            if init_message.len() < EPHEMERAL_ENC_KEY_END {
                return Err(ReplyError::Invalid);
            }

            /* HANDSHAKE FLAGS HANDLING */

            let init_flags = init_message[HANDSHAKE_FLAGS_IDX];
            response_flags = init_flags | private_key_bundle.flags as u8 & HANDSHAKE_FLAGS_MASK;

            /* MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let ephemeral_enc_key = &init_message[EPHEMERAL_ENC_KEY_RANGE];
            let result = S::DecapsulationKeyImpl::encapsulate(ephemeral_enc_key.try_into().unwrap());
            let (ss, c) = result.ok_or(ReplyError::Inauthentic)?;
            ciphertext = c;
            shared_secret = Zeroizing::new(ss);

            if init_flags & HANDSHAKE_FLAG_USE_RESUMPTION > 0 {
                /* RESUMPTION TOKEN HANDLING */

                if init_message.len() < RESUMPTION_TOKEN_END {
                    return Err(ReplyError::Invalid);
                }

                symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_RANGE]);

                let resumption_token = (&init_message[RESUMPTION_TOKEN_RANGE]).try_into().unwrap();
                if let Some((resumption_key, remote_key_bundle)) = sl.lookup_resumption_key(resumption_token) {
                    expected_offline_hash = Some(remote_key_bundle.offline_hash);

                    symmetric.mix(&resumption_key[..]);

                    if init_flags & HANDSHAKE_FLAG_FULL_HANDSHAKE > 0 {
                        /* FULL HANDSHAKE RESUMPTION HANDLING */

                        if init_message.len() != FULL_HANSHAKE_RESUMPTION_LEN {
                            return Err(ReplyError::Invalid);
                        }

                        symmetric.decrypt_and_mix(&mut init_message[FULL_HANDSHAKE_RESUMPTION_TAG_RANGE])?;

                        // Resumption was successful so we deny fallback.
                        response_flags |= HANDSHAKE_FLAG_DENY_FALLBACK;
                    } else {
                        /* RESUMPTION HANDLING */

                        if init_message.len() < PAYLOAD_START + PAYLOAD_REV_START {
                            return Err(ReplyError::Invalid);
                        }
                        let payload_end = init_message.len() - PAYLOAD_REV_START;
                        let payload_tag_end = init_message.len() - PAYLOAD_TAG_REV_START;
                        let online_sign_start = init_message.len() - ONLINE_SIGN_REV_END;
                        let online_sign_end = init_message.len() - ONLINE_SIGN_REV_START;
                        let online_sign_tag_end = init_message.len() - ONLINE_SIGN_TAG_REV_START;

                        /* PAYLOAD HANDLING */

                        let checksum_channel_binding = symmetric.channel_binding();

                        symmetric.decrypt_and_mix(&mut init_message[KEY_BUNDLE_CHECKSUM_START..payload_tag_end])?;

                        let payload_len =
                            u16::from_be_bytes(init_message[PAYLOAD_LEN_RANGE].try_into().unwrap()) as usize;
                        if payload_len != payload_end - PAYLOAD_START {
                            return Err(ReplyError::Invalid);
                        }

                        recv_payload = Some(PAYLOAD_START..payload_end);

                        /* KEY BUNDLE CHECKSUM HANDLING */

                        let mut bundle_hasher = S::Shake256Impl::new();
                        bundle_hasher.update(&checksum_channel_binding);
                        bundle_hasher.update(&remote_key_bundle.bundle_hash);
                        bundle_hasher.update(&private_key_bundle.bundle_hash);

                        let mut local_checksum = [0; KEY_BUNDLE_CHECKSUM_LEN];
                        bundle_hasher.finish(&mut local_checksum);

                        let remote_checksum = &init_message[KEY_BUNDLE_CHECKSUM_RANGE];
                        /* An incorrect bundle checksum indicates one party currently has an
                        outdated or incorrect public key of the other party. So we need to do a
                        fallback handshake to re-exchange public keys. */
                        let has_correct_bundle = &local_checksum[..] == remote_checksum;

                        /* ONLINE SIGNATURE HANDLING */

                        let signature_channel_binding = symmetric.channel_binding();

                        symmetric.decrypt_and_mix(&mut init_message[online_sign_start..online_sign_tag_end])?;

                        /* Authentication of the initiator's signature is skipped when doing a
                        full handshake if the initiator has the incorrect keys. A full handshake
                        will force the initiator to send a second, better signature later. */
                        if has_correct_bundle {
                            if !remote_key_bundle.check_handshake_flags(init_flags) {
                                return Err(ReplyError::Inauthentic);
                            }

                            remote_key_bundle
                                .verify(
                                    domain::INITIALIZE_BINDING,
                                    &signature_channel_binding,
                                    (&init_message[online_sign_start..online_sign_end]).try_into().unwrap(),
                                )
                                .map_err(|_| ReplyError::Inauthentic)?;
                        } else {
                            response_flags |= HANDSHAKE_FLAG_FULL_HANDSHAKE;
                        }

                        // Resumption was successful so we deny fallback.
                        response_flags |= HANDSHAKE_FLAG_DENY_FALLBACK;
                    }
                } else if response_flags & HANDSHAKE_FLAG_DENY_FALLBACK > 0 {
                    return Err(ReplyError::Inauthentic);
                } else {
                    /* FULL HANDSHAKE FALLBACK */

                    symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_END..]);

                    response_flags |= HANDSHAKE_FLAG_FULL_HANDSHAKE;
                }
            } else {
                /* FULL HANDSHAKE HANDLING */

                if init_message.len() != FULL_HANSHAKE_LEN {
                    return Err(ReplyError::Invalid);
                }

                // There will be no resumption so just hash the premessage and move on.
                symmetric.mix(&init_message[PREMESSAGE_FULL_HANDSHAKE_RANGE]);
            }
        }
        /* REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

        let mut response_message = Vec::new();
        {
            use reply::*;
            response_message.resize(PAYLOAD_START, 0);

            /* HANDSHAKE VERSION AND FLAGS HANDLING */

            response_message[HANDSHAKE_FLAGS_IDX] = response_flags;

            /* MLKEM1024 CIPHERTEXT HANDLING */

            response_message[EPHEMERAL_CIPHERTEXT_RANGE].copy_from_slice(&ciphertext);

            symmetric.mix(&response_message[PREMESSAGE_RANGE]);

            symmetric.mix(&shared_secret[..]);

            /* PAYLOAD HANDLING */

            create_payload(&mut response_message);

            let Ok(payload_len) = u16::try_from(response_message.len() as isize - PAYLOAD_START as isize) else {
                return Err(ReplyError::InvalidPayload);
            };
            response_message[PAYLOAD_LEN_RANGE].copy_from_slice(&payload_len.to_be_bytes());
        }
        if response_flags & HANDSHAKE_FLAG_FULL_HANDSHAKE > 0 {
            /* REPLY MESSAGE ENCODING */

            use reply::*;

            /* KEY BUNDLE HANDLING */

            response_message.extend_from_slice(private_key_bundle.public_bundle_bytes());

            response_message.resize(response_message.len() + MESSAGE_TAIL_LEN, 0);

            let payload_tag_end = response_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = response_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = response_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = response_message.len() - ONLINE_SIGN_TAG_REV_START;

            /* PAYLOAD ENCRYPTION */

            symmetric.encrypt_and_mix(&mut response_message[PAYLOAD_LEN_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let signature = private_key_bundle.sign(domain::REPLY_BINDING, &symmetric.channel_binding());
            response_message[online_sign_start..online_sign_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut response_message[online_sign_start..online_sign_tag_end]);

            /* STATE CHANGE */

            Ok(ResponseOk::Incomplete(
                response_message,
                ReplyState { symmetric, expected_offline_hash },
            ))
        } else {
            /* RESUME MESSAGE ENCODING */

            use resume::*;

            response_message.resize(response_message.len() + MESSAGE_TAIL_LEN, 0);

            let payload_tag_end = response_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = response_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = response_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = response_message.len() - ONLINE_SIGN_TAG_REV_START;

            /* PAYLOAD ENCRYPTION */

            symmetric.encrypt_and_mix(&mut response_message[PAYLOAD_LEN_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let signature = private_key_bundle.sign(domain::RESUME_BINDING, &symmetric.channel_binding());
            response_message[online_sign_start..online_sign_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut response_message[online_sign_start..online_sign_tag_end]);

            // TODO: Add resumption token and key handling.

            Ok(ResponseOk::Complete(
                response_message,
                symmetric.split(),
                &mut init_message[recv_payload.unwrap()],
            ))
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
            let online_sign_start = confirm_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = confirm_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = confirm_message.len() - ONLINE_SIGN_TAG_REV_START;

            /* PAYLOAD AND KEY BUNDLE HANDLING */

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

            /* MLDSA87 HANDLING */

            let channel_binding = symmetric.channel_binding();

            symmetric.decrypt_and_mix(&mut confirm_message[online_sign_start..online_sign_tag_end])?;

            key_bundle
                .verify(
                    domain::REPLY_BINDING,
                    &channel_binding,
                    (&confirm_message[online_sign_start..online_sign_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;

            recv_payload = &mut confirm_message[PAYLOAD_START..payload_end];
        }

        Ok((symmetric.split(), recv_payload))
    }
}
