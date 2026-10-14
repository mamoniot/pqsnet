use constant_time_eq::constant_time_eq_32;

use crate::{
    HandshakeComplete,
    api::{Resumption, ResumptionToken},
    crypto::prelude::*,
    error::{Error, ReplyError},
    key_bundle::{AuthenticBundle, OfflineHash, SecretBundle},
    protocol::*,
    symmetric_state::SymmetricState,
};

pub struct ReplyState<C: CryptoAndMem> {
    symmetric: SymmetricState<C>,
    remote_offline_hash: Option<OfflineHash>,
    reject_if_remote_has_reliable_storage: bool,
}

pub enum InitOk<'a, C: CryptoAndMem> {
    Complete(HandshakeComplete<'a, C>),
    Incomplete(C::MessageMem, ReplyState<C>),
}

impl<C: CryptoAndMem> ReplyState<C> {
    pub fn get_resumption_token(init_message: &mut [u8]) -> Option<ResumptionToken> {
        use initialize::*;

        if init_message.len() >= RESUMPTION_TOKEN_END {
            Some(init_message[RESUMPTION_TOKEN_RANGE].try_into().unwrap())
        } else {
            None
        }
    }

    pub fn process_initialize<'a>(
        aad: &[u8],
        init_message: &'a mut [u8],
        secret_key_bundle: &SecretBundle<C>,
        resumption: Option<Resumption<C>>,
        secs_since_unix_epoch: u64,
        alloc: <C::MessageMem as Mem>::Alloc,
        create_payload: impl FnOnce() -> C::PayloadMem,
    ) -> Result<InitOk<'a, C>, ReplyError> {
        /* INITIALIZE MESSAGE DECODING */

        let shared_secret;
        let ciphertext;
        let handshake_type;
        let mut symmetric;
        let mut resume = None;
        let mut remote_offline_hash = None;
        {
            use initialize::*;

            if init_message.len() < EPHEMERAL_ENC_KEY_END {
                return Err(ReplyError::Invalid);
            }

            /* MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let ephemeral_enc_key = &init_message[EPHEMERAL_ENC_KEY_RANGE];
            let result = C::DecapsulationKey::encapsulate(ephemeral_enc_key.try_into().unwrap());
            (shared_secret, ciphertext) = result.ok_or(ReplyError::Inauthentic)?;

            /* RESUMPTION TOKEN HANDLING */

            symmetric = SymmetricState::new(aad);

            let has_resumption_token = init_message.len() >= RESUMPTION_TOKEN_END;
            if has_resumption_token {
                symmetric.mix(9, &init_message[..RESUMPTION_TOKEN_END]);

                let resumption_token = (&init_message[RESUMPTION_TOKEN_RANGE]).try_into().unwrap();

                if let Some(resumption) = &resumption
                    && !constant_time_eq_32(&resumption.token, resumption_token)
                {
                    return Err(ReplyError::IncorrectResumption);
                }
            } else if init_message.len() != EPHEMERAL_ENC_KEY_END {
                return Err(ReplyError::Invalid);
            }

            if let Some(resumption) = resumption {
                remote_offline_hash = Some(*resumption.remote_key_bundle.offline_hash());

                symmetric.mix(10, &resumption.key[..]);

                /* RESUMPTION HANDLING */

                if init_message.len() < PAYLOAD_START + PAYLOAD_REV_START {
                    return Err(ReplyError::Invalid);
                }
                let payload_end = init_message.len() - PAYLOAD_REV_START;
                let payload_tag_end = init_message.len() - PAYLOAD_TAG_REV_START;
                let online_sign_start = init_message.len() - ONLINE_SIGN_REV_END;
                let online_sign_tag_end = init_message.len() - ONLINE_SIGN_TAG_REV_START;

                /* PAYLOAD HANDLING */

                let mut local_checksum = [0; KEY_BUNDLE_CHECKSUM_LEN];
                symmetric.checksum(
                    resumption.remote_key_bundle.bundle_hash(),
                    secret_key_bundle.bundle_hash(),
                    &mut local_checksum,
                );

                symmetric.decrypt_and_mix(11, &mut init_message[KEY_BUNDLE_CHECKSUM_START..payload_tag_end])?;

                let remote_checksum = &init_message[KEY_BUNDLE_CHECKSUM_RANGE].try_into().unwrap();
                /* An incorrect bundle checksum indicates one party currently has an
                outdated or incorrect public key of the other party. So we need to do a
                full handshake to re-exchange public keys. */
                let has_correct_bundle = constant_time_eq_32(&local_checksum, remote_checksum);

                /* ONLINE SIGNATURE HANDLING */

                symmetric.verify(
                    12,
                    has_correct_bundle.then_some(&resumption.remote_key_bundle),
                    &mut init_message[online_sign_start..online_sign_tag_end],
                    secs_since_unix_epoch,
                )?;

                /* Authentication of the initiator's signature is skipped when doing a
                full handshake if the initiator has the incorrect keys. A full handshake
                will force the initiator to send a second, better signature later. */
                if has_correct_bundle {
                    handshake_type = reply::HANDSHAKE_TYPE_RESUME;
                    resume = Some((resumption.remote_key_bundle, PAYLOAD_START..payload_end));
                } else {
                    handshake_type = reply::HANDSHAKE_TYPE_FULL;
                }
            } else if has_resumption_token {
                /* FALLBACK */

                symmetric.mix(14, &init_message[RESUMPTION_TOKEN_END..]);

                handshake_type = reply::HANDSHAKE_TYPE_FALLBACK;
            } else {
                /* FULL HANDSHAKE */

                symmetric.mix(1, &init_message[..]);

                handshake_type = reply::HANDSHAKE_TYPE_FULL;
            }
        }
        /* REPLY MESSAGE ENCODING */
        {
            use reply::*;

            let payload = create_payload();
            let message_len = if handshake_type == HANDSHAKE_TYPE_RESUME {
                PAYLOAD_START + payload.len() + PAYLOAD_REV_START
            } else {
                PAYLOAD_START + secret_key_bundle.public_bytes().len() + payload.len() + PAYLOAD_REV_START
            };
            let mut reply_message = C::MessageMem::malloc(alloc, message_len).ok_or(ReplyError::AllocFailure)?;

            /* HANDSHAKE TYPE HANDLING */

            reply_message[HANDSHAKE_TYPE_IDX] = handshake_type;

            /* MLKEM1024 CIPHERTEXT HANDLING */

            reply_message[EPHEMERAL_CIPHERTEXT_RANGE].copy_from_slice(&ciphertext);

            symmetric.mix(2, &reply_message[..EPHEMERAL_CIPHERTEXT_END]);
            symmetric.mix(3, &shared_secret[..]);

            /* PAYLOAD HANDLING */

            if handshake_type != HANDSHAKE_TYPE_RESUME {
                /* KEY BUNDLE HANDLING */

                let key_bundle_end = PAYLOAD_START + secret_key_bundle.public_bytes().len();

                reply_message[PAYLOAD_START..key_bundle_end].clone_from_slice(secret_key_bundle.public_bytes());
            }

            let payload_start = reply_message.len() - PAYLOAD_REV_START - payload.len();
            let payload_end = reply_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;
            let online_sign_start = reply_message.len() - ONLINE_SIGN_REV_END;
            let online_sign_tag_end = reply_message.len() - ONLINE_SIGN_TAG_REV_START;

            reply_message[payload_start..payload_end].clone_from_slice(&payload);

            symmetric.encrypt_and_mix(4, &mut reply_message[PAYLOAD_START..payload_tag_end]);

            /* ONLINE SIGNATURE HANDLING */

            symmetric.sign(
                5,
                secret_key_bundle,
                &mut reply_message[online_sign_start..online_sign_tag_end],
            );

            if let Some((remote_key_bundle, recv_payload_range)) = resume {
                Ok(InitOk::Complete(HandshakeComplete {
                    message_to_send: Some(reply_message),
                    keys: symmetric.split(13),
                    remote_key_bundle,
                    recv_payload: &mut init_message[recv_payload_range],
                }))
            } else {
                Ok(InitOk::Incomplete(
                    reply_message,
                    ReplyState {
                        symmetric,
                        remote_offline_hash,
                        reject_if_remote_has_reliable_storage: handshake_type == HANDSHAKE_TYPE_FALLBACK
                            && (secret_key_bundle.flags() & key_bundle::FLAG_RELIABLE_STORAGE) > 0,
                    },
                ))
            }
        }
    }

    pub fn process_confirm<'a>(
        self,
        confirm_message: &'a mut [u8],
        secs_since_unix_epoch: u64,
        alloc: <C::BundleMem as Mem>::Alloc,
    ) -> Result<HandshakeComplete<'a, C>, Error> {
        /* CONFIRM MESSAGE DECODING */

        use confirm::*;

        if confirm_message.len() < PAYLOAD_START + PAYLOAD_REV_START {
            return Err(Error::Invalid);
        }

        let payload_end = confirm_message.len() - PAYLOAD_REV_START;
        let payload_tag_end = confirm_message.len() - PAYLOAD_TAG_REV_START;
        let online_sign_start = confirm_message.len() - ONLINE_SIGN_REV_END;
        let online_sign_tag_end = confirm_message.len() - ONLINE_SIGN_TAG_REV_START;

        /* PAYLOAD AND KEY BUNDLE HANDLING */

        let mut symmetric = self.symmetric;

        symmetric.decrypt_and_mix(6, &mut confirm_message[PAYLOAD_START..payload_tag_end])?;

        let mixed_payload = &confirm_message[PAYLOAD_START..payload_end];
        let remote_key_bundle = AuthenticBundle::authenticate(mixed_payload, secs_since_unix_epoch, alloc)?;

        let key_bundle_end = PAYLOAD_START + remote_key_bundle.public_bytes().len();

        if let Some(remote_offline_hash) = &self.remote_offline_hash {
            /* If the offline hashes are not equal then we are not connecting with the party we
            intended to connect to. A party's offline key is their id and it must never change. */
            if !remote_key_bundle.offline_eq_raw(remote_offline_hash) {
                return Err(Error::Inauthentic);
            }
        }

        if self.reject_if_remote_has_reliable_storage
            && (remote_key_bundle.flags() & key_bundle::FLAG_RELIABLE_STORAGE) > 0
        {
            return Err(Error::Inauthentic);
        }

        /* ONLINE SIGNATURE HANDLING */

        symmetric.verify(
            7,
            Some(&remote_key_bundle),
            &mut confirm_message[online_sign_start..online_sign_tag_end],
            secs_since_unix_epoch,
        )?;

        let recv_payload = &mut confirm_message[key_bundle_end..payload_end];

        Ok(HandshakeComplete {
            message_to_send: None,
            keys: symmetric.split(8),
            remote_key_bundle,
            recv_payload,
        })
    }
}
