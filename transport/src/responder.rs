use std::sync::{Arc, atomic::AtomicU64};

use zeroize::Zeroizing;

use crate::{
    context::{Context, HandshakeState, RecvOk, Socket, SocketGuard, SocketState}, crypto::prelude::*, desegmentation::{Mtu, Segmenter}, error::Error, protocol::{shared::*, *}, session_layer::{ResumptionAction, SessionLayer}, symmetric_state::SymmetricState,
};

pub struct ReplyState<S: SessionLayer> {
    segmenter: Segmenter,
    symmetric: SymmetricState<S>,
    send_socket_id: u32,
}

impl<S: SessionLayer> Context<S> {
    pub(crate) fn process_initialize(
        &self,
        mut sl: S,
        init_message: &mut [u8],
        mtu: Mtu,
    ) -> Result<RecvOk<S>, Error> {
        let mut symmetric = SymmetricState::<S>::default();

        let shared_secret;
        let ciphertext;
        let send_socket_id;
        let mut fallback = false;
        {
            use initialize::*;

            /* START OF SEND SOCKET ID HANDLING */

            send_socket_id =
                u32::from_be_bytes(init_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].try_into().unwrap());

            /* START OF RESUMPTION TOKEN HANDLING */

            // TODO: Check message length.
            let handshake_variant = init_message[HANDSHAKE_VARIANT_IDX];
            if (handshake_variant & RESUMPTION_RESUME_FLAG) > 0 {

                symmetric.mix(&init_message[..RESUMPTION_TOKEN_END]);

                let resumption_token = (&init_message[RESUMPTION_TOKEN_START..RESUMPTION_TOKEN_END])
                    .try_into()
                    .unwrap();

                let resumption_key = None;
                if let Some(v) = self.resumption_table.get(resumption_token) {
                    let v = v.value();
                    if let Some(s) = v.socket.upgrade() {
                        let guard = s.lock.read().unwrap();
                        if let Some(c) = &guard[v.cipher_idx as usize] {
                            resumption_key = Some((c.resumption_key.clone(), v.socket.clone()));
                        }
                    }
                }

                if let Some((resumption_key, pre_socket)) = &resumption_key {
                    symmetric.mix(&resumption_key[..]);
                } else {
                    match sl.lookup_resumption_key(resumption_token) {
                        ResumptionAction::ResumeWithKey { key } => {
                            symmetric.mix(&key[..]);
                        }
                        ResumptionAction::ReplyUnknown => {
                        }
                        ResumptionAction::Reject => {
                            return Err(Error::Inauthentic);
                        }
                    }
                }
            } else {
                symmetric.mix(&init_message[..RESUMPTION_TAG_END]);
            }



            /* START OF MLDSA87 KEY BUNDLE HANDLING */

            let auth = S::PublicKeyBundleImpl::verify(
                (&reply_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_PUBKEY_END])
                    .try_into()
                    .unwrap(),
                OFFLINE_KEY_CERTIFICATION_DOMAIN_NAME,
                &reply_message[STATIC_ONLINE_PUBKEY_START..STATIC_ONLINE_PUBKEY_END],
                (&reply_message[STATIC_OFFLINE_SIGN_START..STATIC_OFFLINE_SIGN_END])
                    .try_into()
                    .unwrap(),
            );
            if !auth {
                return Err(Error::Inauthentic);
            }

            /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let result = S::DecapsulationKeyImpl::encapsulate(
                (&init_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_END])
                    .try_into()
                    .unwrap(),
            );
            if let Some((ss, c)) = result {
                ciphertext = c;
                shared_secret = Zeroizing::new(ss);
            } else {
                return Err(Error::Inauthentic);
            }
        }

        let mut reply_message = if do_resume {
            symmetric.start_resume();

            Segmenter::create_message(resume::MESSAGE_LEN, resume::HEADER_LEN, send_socket_id, mtu)
        } else {
            Segmenter::create_message(reply::MESSAGE_LEN, reply::HEADER_LEN, send_socket_id, mtu)
        };
        {
            /* START OF REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

            use reply::*;

            /* START OF HEADER MIXING */

            symmetric.mix(&reply_message[..HEADER_LEN]);

            /* START OF MLKEM1024 CIPHERTEXT ENCRYPTION */

            reply_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_END].copy_from_slice(&ciphertext);

            symmetric.encrypt_and_mix(
                &mut reply_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_TAG_END],
                false,
            );

            /* START OF MLKEM1024 SHARED SECRET MIXING */

            symmetric.mix(shared_secret.as_ref());
        }
        if do_resume {
            use resume::*;

            /* START OF RECV SOCKET ID HANDLING */

            let recv_socket = self.reserve_socket(&mut sl);

            reply_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&recv_socket.id().to_be_bytes());

            /* START OF PAYLOAD ENCRYPTION */

            let payload_tag_end =  MESSAGE_LEN - PAYLOAD_TAG_REV_START;

            symmetric.encrypt_and_mix(&mut reply_message[NEW_SOCKET_ID_START..payload_tag_end], true);

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, resumption_token, resupmtion_key) = symmetric.split();

            let segmenter = Segmenter::new(reply_message, HEADER_LEN, mtu);

            recv_socket.insert(SocketState::AwaitingData {
                segmenter: segmenter.clone(),
                cipher,
                send_socket_id,
            });

            Ok(RecvOk::SendResume(segmenter))
        } else {
            use reply::*;

            /* START OF MLDSA87 KEY BUNDLE ENCODING */

            reply_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_SIGN_END]
                .copy_from_slice(&sl.static_public_keys().encode_key_bundle());

            /* START OF RECV SOCKET ID HANDLING */

            let recv_socket = self.reserve_socket(&mut sl);

            reply_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&recv_socket.id().to_be_bytes());

            /* START OF PAYLOAD ENCRYPTION */

            let payload_tag_end = MESSAGE_LEN - PAYLOAD_TAG_REV_START;

            symmetric.encrypt_and_mix(&mut reply_message[STATIC_OFFLINE_PUBKEY_START..payload_tag_end], false);

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let static_online_sign_start = MESSAGE_LEN - STATIC_ONLINE_SIGN_REV_END;
            let static_online_sign_end = MESSAGE_LEN - STATIC_ONLINE_SIGN_REV_START;
            let static_online_sign_tag_end = MESSAGE_LEN - STATIC_ONLINE_SIGN_TAG_REV_START;

            let signature = sl
                .static_public_keys()
                .sign_with_online(REPLY_BINDING_DOMAIN_NAME, symmetric.channel_binding());

            reply_message[static_online_sign_start..static_online_sign_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(
                &mut reply_message[static_online_sign_start..static_online_sign_tag_end],
                false,
            );

            /* START OF STATE MANAGEMENT */

            let segmenter = Segmenter::new(reply_message, HEADER_LEN, mtu);

            recv_socket.insert(SocketState::Handshake {
                state: HandshakeState::SendingReply(ReplyState {
                    segmenter: segmenter.clone(),
                    symmetric,
                    send_socket_id,
                }),
                desegmenter: Default::default(),
            });

            Ok(RecvOk::SendReply(segmenter))
        }
    }

    pub(crate) fn process_confirm(
        &self,
        mut sl: S,
        state: ReplyState<S>,
        guard: SocketGuard<S>,
        confirm_message: &mut [u8],
    ) -> Result<RecvOk<S>, Error> {
        let mut symmetric = state.symmetric;
        let send_socket_id = state.send_socket_id;
        {
            use confirm::*;

            /* START OF HEADER MIXING */

            symmetric.mix(&confirm_message[..HEADER_LEN]);

            /* START OF MLDSA87 KEY BUNDLE ENCODING */

            confirm_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_SIGN_END]
                .copy_from_slice(&sl.static_public_keys().encode_key_bundle());

            /* START OF PAYLOAD DECRYPTION */

            let payload_tag_end = confirm_message.len() - PAYLOAD_TAG_REV_START;

            symmetric.mix_and_decrypt(
                &mut confirm_message[STATIC_OFFLINE_PUBKEY_START..payload_tag_end],
                false,
            )?;

            /* START OF MLDSA87 KEY BUNDLE HANDLING */

            let auth = S::PublicKeyBundleImpl::verify(
                (&confirm_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_PUBKEY_END])
                    .try_into()
                    .unwrap(),
                OFFLINE_KEY_CERTIFICATION_DOMAIN_NAME,
                &confirm_message[STATIC_ONLINE_PUBKEY_START..STATIC_ONLINE_PUBKEY_END],
                (&confirm_message[STATIC_OFFLINE_SIGN_START..STATIC_OFFLINE_SIGN_END])
                    .try_into()
                    .unwrap(),
            );
            if !auth {
                return Err(Error::Inauthentic);
            }

            /* START OF MLDSA87 HANDLING */

            let static_online_sign_start = confirm_message.len() - STATIC_ONLINE_SIGN_REV_END;
            let static_online_sign_end = confirm_message.len() - STATIC_ONLINE_SIGN_REV_START;
            let static_online_sign_tag_end = confirm_message.len() - STATIC_ONLINE_SIGN_TAG_REV_START;

            symmetric.mix_and_decrypt(
                &mut confirm_message[static_online_sign_start..static_online_sign_tag_end],
                true,
            )?;

            let auth = S::PublicKeyBundleImpl::verify(
                (&confirm_message[STATIC_ONLINE_PUBKEY_START..STATIC_ONLINE_PUBKEY_END])
                    .try_into()
                    .unwrap(),
                CONFIRM_BINDING_DOMAIN_NAME,
                symmetric.channel_binding(),
                (&confirm_message[static_online_sign_start..static_online_sign_end])
                    .try_into()
                    .unwrap(),
            );
            if !auth {
                return Err(Error::Inauthentic);
            }
        }
        {
            // TODO: Add session layer authentication here.

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, resumption_token, resupmtion_key) = symmetric.split();

            guard.insert(SocketState::Active(Arc::new(Socket {
                segmenter: None,
                cipher,
                antireplay: Default::default(),
                send_socket_id,
                counter: AtomicU64::new(AES_GCM_INIT_COUNTER as u64),
            })));

            Ok(RecvOk::Confirm)
        }
    }
}
