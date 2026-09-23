use zeroize::Zeroizing;

use crate::{
    crypto::prelude::*,
    error::{Error, ReplyError},
    key_bundle::{AuthenticBundle, OFFLINE_HASH_LEN},
    protocol::*,
    session_layer::SessionLayer,
    symmetric_state::{SymmetricKeys, SymmetricState},
};

pub struct ReplyState<S: SessionLayer> {
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
    pub fn init<'a>(
        mut sl: S,
        aad: &[u8],
        init_message: &'a mut [u8],
        require_resumption: bool,
        create_payload: impl FnOnce(&mut Vec<u8>),
    ) -> Result<ResponseOk<'a, S>, ReplyError> {
        let shared_secret;
        let ciphertext;
        let private_key_bundle;
        let handshake_type;
        let mut recv_payload = None;
        let mut expected_offline_hash = None;
        let mut symmetric;
        {
            use initialize::*;

            if init_message.len() < EPHEMERAL_ENC_KEY_END {
                return Err(ReplyError::Invalid);
            }

            /* MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let ephemeral_enc_key = &init_message[EPHEMERAL_ENC_KEY_RANGE];
            let result = S::DecapsulationKeyImpl::encapsulate(ephemeral_enc_key.try_into().unwrap());
            let (ss, c) = result.ok_or(ReplyError::Inauthentic)?;
            ciphertext = c;
            shared_secret = Zeroizing::new(ss);

            /* RESUMPTION TOKEN HANDLING */

            symmetric = SymmetricState::<S>::new(aad);

            let has_resumption_token = init_message.len() >= RESUMPTION_TOKEN_END;
            let resumption = if has_resumption_token {
                symmetric.mix(&init_message[..RESUMPTION_TOKEN_END]);

                let resumption_token = (&init_message[RESUMPTION_TOKEN_RANGE]).try_into().unwrap();
                sl.lookup_resumption_key(resumption_token)
            } else if require_resumption {
                return Err(ReplyError::Inauthentic);
            } else if init_message.len() == EPHEMERAL_ENC_KEY_END {
                None
            } else {
                return Err(ReplyError::Invalid);
            };

            private_key_bundle = sl.private_key_bundle();

            if let Some((resumption_key, remote_key_bundle)) = resumption {
                expected_offline_hash = Some(remote_key_bundle.offline_hash);

                symmetric.mix(&resumption_key[..]);

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
                    remote_key_bundle
                        .verify(
                            domain::INITIALIZE_BINDING,
                            &signature_channel_binding,
                            (&init_message[online_sign_start..online_sign_end]).try_into().unwrap(),
                        )
                        .map_err(|_| ReplyError::Inauthentic)?;

                    handshake_type = reply::HANDSHAKE_TYPE_RESUME;
                } else {
                    handshake_type = reply::HANDSHAKE_TYPE_FULL;
                }
            } else if has_resumption_token {
                /* FALLBACK */

                symmetric.mix(&init_message[RESUMPTION_TOKEN_END..]);

                handshake_type = reply::HANDSHAKE_TYPE_FALLBACK;
            } else {
                /* FULL HANDSHAKE */

                symmetric.mix(&init_message[..]);
                handshake_type = reply::HANDSHAKE_TYPE_FULL;
            }

            symmetric.mix(init_message);
        }
        /* REPLY MESSAGE SHARED SECTION */

        let mut reply_message = Vec::new();
        {
            use reply::*;
            reply_message.resize(PAYLOAD_START, 0);

            /* HANDSHAKE TYPE HANDLING */

            reply_message[HANDSHAKE_TYPE_IDX] = handshake_type;

            /* MLKEM1024 CIPHERTEXT HANDLING */

            reply_message[EPHEMERAL_CIPHERTEXT_RANGE].copy_from_slice(&ciphertext);

            symmetric.mix(&reply_message[..EPHEMERAL_CIPHERTEXT_END]);
            symmetric.mix(&shared_secret[..]);

            /* PAYLOAD HANDLING */

            if handshake_type != HANDSHAKE_TYPE_RESUME {
                /* KEY BUNDLE HANDLING */

                reply_message.extend_from_slice(private_key_bundle.public_bundle_bytes());
            }

            create_payload(&mut reply_message);

            reply_message.resize(reply_message.len() + PAYLOAD_REV_START, 0);

            /* PAYLOAD ENCRYPTION */

            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = reply_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = reply_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = reply_message.len() - ONLINE_SIGN_TAG_REV_START;

            symmetric.encrypt_and_mix(&mut reply_message[PAYLOAD_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            let signature = private_key_bundle.sign(domain::REPLY_BINDING, &symmetric.channel_binding());
            reply_message[online_sign_start..online_sign_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut reply_message[online_sign_start..online_sign_tag_end]);

            if handshake_type != HANDSHAKE_TYPE_RESUME {
                Ok(ResponseOk::Incomplete(
                    reply_message,
                    ReplyState { symmetric, expected_offline_hash },
                ))
            } else {
                Ok(ResponseOk::Complete(
                    reply_message,
                    symmetric.split(),
                    &mut init_message[recv_payload.unwrap()],
                ))
            }
        }
    }

    pub fn confirm<'a>(self, confirm_message: &'a mut [u8]) -> Result<(SymmetricKeys, &'a mut [u8]), Error> {
        let mut symmetric = self.symmetric;

        let recv_payload;
        {
            use confirm::*;
            if confirm_message.len() < PAYLOAD_START + PAYLOAD_REV_START {
                return Err(Error::Invalid);
            }

            let payload_end = confirm_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = confirm_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = confirm_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_end = confirm_message.len() - ONLINE_SIGN_REV_START;
            let online_sign_tag_end = confirm_message.len() - ONLINE_SIGN_TAG_REV_START;

            /* PAYLOAD AND KEY BUNDLE HANDLING */

            symmetric.decrypt_and_mix(&mut confirm_message[PAYLOAD_START..payload_tag_end])?;

            let (key_bundle, key_bundle_len) = AuthenticBundle::<S::PublicSigningKeyImpl>::authenticate::<
                S::Shake256Impl,
            >(&confirm_message[PAYLOAD_START..payload_end])
            .map_err(|_| Error::Inauthentic)?;
            let key_bundle_end = PAYLOAD_START + key_bundle_len;

            if let Some(expected_offline_hash) = self.expected_offline_hash {
                /* If the offline hashes are not equal then we are not connecting with the party we
                intended to connect to. A party's offline key is their id and it must never change. */
                if key_bundle.offline_hash != expected_offline_hash {
                    return Err(Error::Inauthentic);
                }
            }

            /* ONLINE SIGNATURE HANDLING */

            let channel_binding = symmetric.channel_binding();

            symmetric.decrypt_and_mix(&mut confirm_message[online_sign_start..online_sign_tag_end])?;

            key_bundle
                .verify(
                    domain::CONFIRM_BINDING,
                    &channel_binding,
                    (&confirm_message[online_sign_start..online_sign_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;

            recv_payload = &mut confirm_message[key_bundle_end..payload_end];
        }

        Ok((symmetric.split(), recv_payload))
    }
}
