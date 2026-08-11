use std::sync::{Arc, atomic::AtomicU64};

use zeroize::Zeroizing;

use crate::{
    context::{Context, RecvOk},
    crypto::prelude::*,
    desegmentation::{Mtu, Segmenter},
    error::Error,
    key_bundle::AuthenticBundle,
    protocol::{
        domain::{INITIALIZE_BINDING, REPLY_BINDING, RESUME_BINDING},
        shared::*,
        *,
    },
    session_layer::SessionLayer,
    socket::{HandshakeState, Socket},
    symmetric_state::SymmetricState,
};

pub struct ReplyState<S: SessionLayer> {
    symmetric: SymmetricState<S>,
    send_socket_id: u32,
    key_bundle: Option<AuthenticBundle<S::PublicSigningKeyImpl>>,
}

impl<S: SessionLayer> Context<S> {
    pub(crate) fn process_initialize(
        &self,
        mut sl: S,
        init_message: &mut [u8],
        mtu: Mtu,
        send_payload: &[u8],
    ) -> Result<RecvOk<S>, Error> {
        let mut symmetric = SymmetricState::<S>::default();

        let shared_secret;
        let ciphertext;
        let send_socket_id;
        let private_key_bundle;
        // `handshake_flags` may only be or'd into.
        let mut handshake_flags;
        let mut recv_payload = None;
        let mut fallback = false;
        let key_bundle = None;
        {
            use initialize::*;

            /* START OF HANDSHAKE VERSION AND FLAGS HANDLING */

            if init_message[HANDSHAKE_VERSION_IDX] != HANDSHAKE_VERSION_VALUE {
                return Err(Error::Invalid);
            }

            handshake_flags = init_message[HANDSHAKE_FLAGS_IDX];

            /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let result =
                S::DecapsulationKeyImpl::encapsulate((&init_message[EPHEMERAL_ENC_KEY_RANGE]).try_into().unwrap());
            if let Some((ss, c)) = result {
                ciphertext = c;
                shared_secret = Zeroizing::new(ss);
            } else {
                return Err(Error::Inauthentic);
            }

            /* START OF SEND SOCKET ID HANDLING */

            send_socket_id = u32::from_be_bytes(init_message[NEW_SOCKET_ID_RANGE].try_into().unwrap());

            /* START OF RESUMPTION TOKEN HANDLING */

            if handshake_flags & HANDSHAKE_FLAGS_USE_RESUMPTION > 0 {
                symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_RANGE]);

                let resumption_token = (&init_message[RESUMPTION_TOKEN_RANGE]).try_into().unwrap();

                if let Some((resumption_key, key_bundle)) = sl.lookup_resumption_key(resumption_token) {
                    let payload_end = init_message.len() - PAYLOAD_REV_START;
                    let bundle_uid_xor_start = init_message.len() - BUNDLE_UID_XOR_REV_END;
                    let bundle_uid_xor_end = init_message.len() - BUNDLE_UID_XOR_REV_START;
                    let online_sign_start = init_message.len() - ONLINE_SIGNATURE_REV_END;
                    let online_sign_end = init_message.len() - ONLINE_SIGNATURE_REV_START;
                    let online_sign_tag_end = init_message.len() - RESUMPTION_TAG_REV_START;

                    handshake_flags |= HANDSHAKE_FLAGS_DENY_FALLBACK;

                    symmetric.mix(&resumption_key[..]);

                    /* START OF EXPECTED BUNDLE UID HANDLING */

                    symmetric.decrypt_and_mix(&mut init_message[RESUMPTION_ENCRYPTION_START..online_sign_tag_end])?;

                    let uid_xor = u128::from_be_bytes(
                        init_message[bundle_uid_xor_start..bundle_uid_xor_end]
                            .try_into()
                            .unwrap(),
                    );

                    private_key_bundle = sl.private_key_bundle();
                    let expected_uid_xor = private_key_bundle.uid ^ key_bundle.uid;

                    /* An incorrect bundle xor indicates one party currently has an outdated or
                    incorrect public key of the other party. So we need to do a full handshake to
                    re-exchange public keys. */
                    if expected_uid_xor != uid_xor {
                        /* Authentication of the initiator's signature is skipped when doing a full
                        handshake due to an incorrect bundle xor. A full handshake will
                        force the initiator to send a second, much stronger signature later. */
                        handshake_flags |= HANDSHAKE_FLAGS_FULL_HANDSHAKE;
                    } else {
                        if !key_bundle.check_handshake_flags(handshake_flags) {
                            return Err(Error::Inauthentic);
                        }
                        /* START OF PAYLOAD HANDLING */

                        recv_payload = Some(&init_message[PAYLOAD_START..payload_end]);

                        /* START OF ONLINE SIGNATURE HANDLING */

                        key_bundle
                            .verify(
                                INITIALIZE_BINDING,
                                symmetric.channel_binding(),
                                (&init_message[online_sign_start..online_sign_end]).try_into().unwrap(),
                            )
                            .map_err(|_| Error::Inauthentic)?;
                    }

                    if !private_key_bundle.check_handshake_flags(handshake_flags) {
                        return Err(Error::Inauthentic);
                    }
                } else {
                    // private_key_bundle = sl.private_key_bundle();
                    todo!("lookup or fallback")
                }
            } else {
                // There will be no resumption so just hash the premessage and move on.
                symmetric.mix(&init_message[PREMESSAGE_DEFAULT_HANDSHAKE_RANGE]);
                private_key_bundle = sl.private_key_bundle();
            }
        }

        /* START OF REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

        let do_full = handshake_flags & HANDSHAKE_FLAGS_FULL_HANDSHAKE > 0;
        let message_len = if do_full {
            reply::MESSAGE_MIN_LEN_WITHOUT_BUNDLE + private_key_bundle.public_bundle_bytes().len() + send_payload.len()
        } else {
            symmetric.start_resume();

            resume::MESSAGE_MIN_LEN + send_payload.len()
        };

        let mut reply_message = Segmenter::create_message(message_len, reply::HEADER_LEN, send_socket_id, mtu);
        let socket;
        {
            use reply::*;

            /* START OF HANDSHAKE VERSION AND FLAGS HANDLING */

            reply_message[HANDSHAKE_VERSION_IDX] = HANDSHAKE_VERSION_VALUE;
            reply_message[HANDSHAKE_FLAGS_IDX] = handshake_flags;

            /* START OF MLKEM1024 CIPHERTEXT HANDLING */

            reply_message[EPHEMERAL_CIPHERTEXT_RANGE].copy_from_slice(&ciphertext);

            symmetric.mix(&reply_message[PREMESSAGE_RANGE]);

            symmetric.mix(shared_secret.as_ref());

            /* START OF RECV SOCKET ID HANDLING */

            socket = self.reserve_socket(&mut sl);

            reply_message[NEW_SOCKET_ID_RANGE].copy_from_slice(&socket.recv_socket_id.to_be_bytes());
        };
        if do_full {
            /* START OF REPLY ENCODING */

            use reply::*;
            let payload_end = message_len - PAYLOAD_REV_START;
            let payload_start = payload_end - send_payload.len();
            let key_bundle_end = payload_start;

            let payload_tag_end = message_len - PAYLOAD_TAG_REV_START;
            let online_signature_start = message_len - ONLINE_SIGNATURE_REV_END;
            let online_signature_end = message_len - ONLINE_SIGNATURE_REV_START;
            let online_signature_tag_end = message_len - ONLINE_SIGNATURE_TAG_REV_START;

            /* START OF KEY BUNDLE HANDLING */

            reply_message[KEY_BUNDLE_START..key_bundle_end].copy_from_slice(&private_key_bundle.public_bundle_bytes());

            /* START OF PAYLOAD HANDLING */

            reply_message[payload_start..payload_end].copy_from_slice(send_payload);

            symmetric.encrypt_and_mix(&mut reply_message[PAYLOAD_ENCRYPTION_START..payload_tag_end]);

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let signature = private_key_bundle.sign(REPLY_BINDING, symmetric.channel_binding());
            reply_message[online_signature_start..online_signature_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut reply_message[online_signature_start..online_signature_tag_end]);

            /* START OF STATE MANAGEMENT */

            let segmenter = Segmenter::new(reply_message, HEADER_LEN, mtu);

            *socket.state.write().unwrap() = HandshakeState::SendingReply {
                state: ReplyState { symmetric, key_bundle, send_socket_id },
                segmenter: segmenter.clone(),
                desegmenter: Default::default(),
            };

            Ok(RecvOk::SendReply(socket, segmenter))
        } else {
            /* START OF RESUME ENCODING */

            use resume::*;
            let payload_end = PAYLOAD_START + send_payload.len();
            let payload_tag_end = payload_end + PAYLOAD_TAG_LEN;
            let online_signature_start = payload_tag_end;
            let online_signature_end = online_signature_start + ONLINE_SIGNATURE_LEN;
            let online_signature_tag_end = online_signature_end + ONLINE_SIGNATURE_TAG_LEN;
            debug_assert_eq!(online_signature_tag_end, message_len);

            /* START OF PAYLOAD HANDLING */

            reply_message[PAYLOAD_START..payload_end].copy_from_slice(send_payload);

            symmetric.encrypt_and_mix(&mut reply_message[PAYLOAD_ENCRYPTION_START..payload_tag_end]);

            /* START OF ONLINE SIGNATURE HANDLING */

            let signature = private_key_bundle.sign(RESUME_BINDING, symmetric.channel_binding());
            reply_message[online_signature_start..online_signature_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut reply_message[online_signature_start..online_signature_tag_end]);

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, send_resumption_token, recv_resumption_token, resupmtion_key) = symmetric.split(false);

            let segmenter = Segmenter::new(reply_message, HEADER_LEN, mtu);

            *socket.state.write().unwrap() = HandshakeState::SendingResume { segmenter: segmenter.clone() };

            Ok(RecvOk::SendResume(socket, segmenter))
        }
    }

    pub(crate) fn process_confirm(
        &self,
        mut sl: S,
        state: ReplyState<S>,
        socket: Arc<Socket<S>>,
        confirm_message: &mut [u8],
    ) -> Result<RecvOk<S>, Error> {
        let mut symmetric = state.symmetric;
        let send_socket_id = state.send_socket_id;
        let expected_key_bundle = state.key_bundle;

        let recv_payload;
        {
            use confirm::*;
            let payload_end = confirm_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = confirm_message.len() - PAYLOAD_TAG_REV_START;
            let online_signature_start = confirm_message.len() - ONLINE_SIGNATURE_REV_END;
            let online_signature_end = confirm_message.len() - ONLINE_SIGNATURE_REV_START;
            let online_signature_tag_end = confirm_message.len() - ONLINE_SIGNATURE_TAG_REV_START;

            /* START OF PREMESSAGE MIXING */

            symmetric.mix(&confirm_message[PREMESSAGE_RANGE]);

            /* START OF KEY BUNDLE HANDLING */

            // TODO: This is a common operation.
            symmetric.decrypt_and_mix(&mut confirm_message[PAYLOAD_ENCRYPTION_START..payload_end])?;

            let (key_bundle, key_bundle_len) =
                AuthenticBundle::authenticate_and_get_end(&confirm_message[KEY_BUNDLE_START..])
                    .map_err(|_| Error::Inauthentic)?;

            if let Some(expected_key_bundle) = expected_key_bundle {
                /* If the offline hashes are not equal then we are not connecting with the party we
                intended to connect to. A party's offline key is their id and it must never change. */
                if expected_key_bundle.offline_hash() != key_bundle.offline_hash() {
                    return Err(Error::Inauthentic);
                }
            }

            let payload_start = KEY_BUNDLE_START + key_bundle_len;

            /* START OF PAYLOAD HANDLING */

            recv_payload = &confirm_message[payload_start..payload_end];

            /* START OF MLDSA87 HANDLING */

            // TODO: This is a common operation.
            symmetric.decrypt_and_mix(&mut confirm_message[online_signature_start..online_signature_tag_end])?;

            let auth = key_bundle
                .verify(
                    REPLY_BINDING,
                    symmetric.channel_binding(),
                    (&confirm_message[online_signature_start..online_signature_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;
        }
        {
            // TODO: Add session layer authentication here.

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, send_resumption_token, recv_resumption_token, resupmtion_key) = symmetric.split(false);

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
