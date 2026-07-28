use std::sync::{Arc, Weak, atomic::AtomicU64};

use rand_core::Rng;
use zeroize::Zeroizing;

use crate::{
    context::{Context, RecvOk}, crypto::prelude::*, desegmentation::{Mtu, Segmenter}, error::Error, key_bundle::{AuthenticBundle, PrivateBundleSL, check_handshake_flags}, protocol::{
        domain::{CONFIRM_BINDING, INITIALIZE_BINDING, REPLY_BINDING},
        shared::*,
        *,
    }, session_layer::{ResumptionKey, ResumptionToken, SessionLayer}, socket::{HandshakeState, Socket}, symmetric_state::SymmetricState,
};

pub struct InitializeState<S: SessionLayer> {
    symmetric: SymmetricState<S>,
    fallback: Option<SymmetricState<S>>,
    init_handshake_flags: u8,
    decapsulation_key: S::DecapsulationKeyImpl,
    payload: Box<[u8]>,
    private_key_bundle: Option<PrivateBundleSL<S>>,
    key_bundle: Option<AuthenticBundle<S::PublicSigningKeyImpl>>,
}

impl<S: SessionLayer> Context<S> {
    pub fn initialize(
        &self,
        mut sl: S,
        resumption: Option<(
            &ResumptionToken,
            &ResumptionKey,
            AuthenticBundle<S::PublicSigningKeyImpl>,
        )>,
        combined_bundle_flags: u8,
        mtu: Mtu,
        payload: Box<[u8]>,
    ) -> Result<Arc<Socket<S>>, Error> {
        use initialize::*;

        /* START OF HANDSHAKE VERSION AND FLAGS HANDLING */

        let (message_len, init_handshake_flags) = match (resumption.is_some(), combined_bundle_flags) {
            // If we have a resumption token, we need to signal that to the responder.
            (true, f) if f & HANDSHAKE_FLAGS_FULL_HANDSHAKE > 0 => {
                (MESSAGE_LEN_WITH_FULL, f | HANDSHAKE_FLAGS_USE_RESUMPTION)
            }
            // If we are not doing a full handshake, we must send our signature in this message.
            (true, f) => (
                MESSAGE_MIN_LEN_WITH_SIGN + payload.len(),
                f | HANDSHAKE_FLAGS_USE_RESUMPTION,
            ),
            // If the flags say to use resumption, but there is not resumption token, we must abort.
            (false, f) if f & HANDSHAKE_FLAGS_USE_RESUMPTION > 0 => return Err(Error::Invalid),
            // If there is not a resumption token then we must to do a full handshake.
            (false, f) => (MESSAGE_LEN_WITHOUT_SIGN, f | HANDSHAKE_FLAGS_FULL_HANDSHAKE),
        };
        debug_assert!(check_handshake_flags(combined_bundle_flags, init_handshake_flags));

        /* START OF HEADER ENCODING */

        let mut init_message = Segmenter::create_message(message_len, HEADER_LEN, 0, mtu);

        init_message[INITIALIZE_UID_RANGE].copy_from_slice(&sl.rng().next_u64().to_be_bytes());

        /* START OF HANDSHAKE VERSION AND FLAGS ENCODING */

        init_message[HANDSHAKE_VERSION_IDX] = HANDSHAKE_VERSION_VALUE;
        init_message[HANDSHAKE_FLAGS_IDX] = init_handshake_flags;

        /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

        let (encapsulation_key, decapsulation_key) = S::DecapsulationKeyImpl::generate();
        init_message[EPHEMERAL_ENC_KEY_RANGE].copy_from_slice(&encapsulation_key);

        /* START OF SEND SOCKET ID HANDLING */

        let socket = self.reserve_socket(&mut sl);

        init_message[NEW_SOCKET_ID_RANGE].copy_from_slice(&socket.recv_socket_id.to_be_bytes());

        /* START OF RESUMPTION TOKEN HANDLING */

        let mut symmetric = SymmetricState::<S>::default();
        let mut fallback = None;
        let mut key_bundle = None;
        let mut private_key_bundle = None;

        if let Some((token, key, bundle)) = resumption {
            init_message[RESUMPTION_TOKEN_RANGE].copy_from_slice(token);

            symmetric.mix(&init_message[PREMESSAGE_RESUMPTION_RANGE]);

            if init_handshake_flags & HANDSHAKE_FLAGS_DENY_FALLBACK == 0 {
                // If we are allowing fallback we need the symmetric state from before mixing the
                // secret resumption key.
                fallback = Some(symmetric.clone())
            }

            symmetric.mix(&key[..]);

            if init_handshake_flags & HANDSHAKE_FLAGS_FULL_HANDSHAKE > 0 {
                let resumption_tag_start = message_len - RESUMPTION_TAG_REV_END;
                let resumption_tag_end = message_len - RESUMPTION_TAG_REV_START;

                /* START OF RESUMPTION TAG HANDLING */

                symmetric.encrypt_and_mix(&mut init_message[resumption_tag_start..resumption_tag_end]);
            } else {
                let payload_end = message_len - PAYLOAD_REV_START;
                let bundle_uid_xor_start = message_len - BUNDLE_UID_XOR_REV_END;
                let bundle_uid_xor_end = message_len - BUNDLE_UID_XOR_REV_START;
                let online_sign_start = message_len - ONLINE_SIGNATURE_REV_END;
                let online_sign_end = message_len - ONLINE_SIGNATURE_REV_START;
                let online_sign_tag_end = message_len - RESUMPTION_TAG_REV_START;

                /* START OF PAYLOAD ENCODING */

                init_message[PAYLOAD_START..payload_end].copy_from_slice(&payload[..]);

                /* START OF EXPECTED KEY UID HANDLING */

                let local_private_key_bundle = sl.private_key_bundle();

                let uid_xor = bundle.uid ^ local_private_key_bundle.uid;
                init_message[bundle_uid_xor_start..bundle_uid_xor_end].copy_from_slice(&uid_xor.to_be_bytes());

                /* START OF ONLINE SIGNATURE HANDLING */

                let sign = local_private_key_bundle.sign(INITIALIZE_BINDING, symmetric.channel_binding());
                init_message[online_sign_start..online_sign_end].copy_from_slice(&sign);

                symmetric.encrypt_and_mix(&mut init_message[bundle_uid_xor_start..online_sign_tag_end]);

                private_key_bundle = Some(local_private_key_bundle);
            }

            key_bundle = Some(bundle);
        } else {
            symmetric.mix(&init_message[PREMESSAGE_DEFAULT_HANDSHAKE_RANGE]);
        }

        /* START OF STATE MANAGEMENT */

        let segmenter = Segmenter::new(init_message, HEADER_LEN, mtu);

        *socket.state.write().unwrap() = HandshakeState::SendingInitialize {
            state: InitializeState {
                symmetric,
                fallback,
                decapsulation_key,
                init_handshake_flags,
                payload,
                key_bundle,
                private_key_bundle,
            },
            segmenter,
            desegmenter: Default::default(),
        };

        Ok(socket)
    }

    pub(crate) fn process_reply(
        &self,
        mut sl: S,
        state: InitializeState<S>,
        guard: SocketGuard<S>,
        reply_message: &mut [u8],
        mtu: Mtu,
    ) -> Result<RecvOk<S>, Error> {
        use shared::*;

        let mut fallback = state.fallback;
        let mut symmetric = state.symmetric;
        let mut decapsulation_key = state.decapsulation_key;
        let mut init_handshake_flags = state.init_handshake_flags;
        let mut expected_key_bundle = state.key_bundle;
        let mut send_payload = state.payload;

        /* START OF REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

        let send_socket_id;
        let handshake_flags;
        {
            use reply::*;

            /* START OF HANDSHAKE VERSION AND FLAGS HANDLING */

            if reply_message[HANDSHAKE_VERSION_IDX] != HANDSHAKE_VERSION_VALUE {
                return Err(Error::Invalid);
            }

            handshake_flags = reply_message[HANDSHAKE_FLAGS_IDX];
            if !check_handshake_flags(init_handshake_flags, handshake_flags) {
                return Err(Error::Inauthentic);
            }

            // If this message does not have the deny fallback flag we must fallback.
            if handshake_flags & HANDSHAKE_FLAGS_DENY_FALLBACK == 0 {
                symmetric = fallback.ok_or(Error::Inauthentic)?;
            }

            /* START OF MLKEM1024 CIPHERTEXT HANDLING */

            symmetric.mix(&reply_message[PREMESSAGE_RANGE]);

            let result =
                decapsulation_key.decapsulate((&reply_message[EPHEMERAL_CIPHERTEXT_RANGE]).try_into().unwrap());
            let shared_secret = if let Some(ss) = result {
                Zeroizing::new(ss)
            } else {
                return Err(Error::Inauthentic);
            };

            symmetric.mix(&shared_secret[..]);

            /* START OF RECV SOCKET ID HANDLING */

            send_socket_id = u32::from_be_bytes(reply_message[NEW_SOCKET_ID_RANGE].try_into().unwrap());
        }

        let recv_payload;
        let key_bundle;
        if handshake_flags & HANDSHAKE_FLAGS_FULL_HANDSHAKE > 0 {
            /* START OF REPLY DECODING */

            use reply::*;
            let payload_end = reply_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;
            let online_signature_start = reply_message.len() - ONLINE_SIGNATURE_REV_END;
            let online_signature_end = reply_message.len() - ONLINE_SIGNATURE_REV_START;
            let online_signature_tag_end = reply_message.len() - ONLINE_SIGNATURE_TAG_REV_START;

            /* START OF KEY BUNDLE HANDLING */

            symmetric.decrypt_and_mix(&mut reply_message[KEY_BUNDLE_START..payload_tag_end])?;

            let key_bundle_len;
            (key_bundle, key_bundle_len) =
                AuthenticBundle::authenticate_and_get_end(&reply_message[KEY_BUNDLE_START..])
                    .map_err(|_| Error::Inauthentic)?;

            if !key_bundle.check_handshake_flags(handshake_flags) {
                return Err(Error::Inauthentic);
            }

            if let Some(expected_key_bundle) = expected_key_bundle {
                /* If the offline hashes are not equal then we are not connecting with the party we
                intended to connect to. A party's offline key is their id and it must never change. */
                if expected_key_bundle.offline_hash != key_bundle.offline_hash {
                    return Err(Error::Inauthentic);
                }
            }

            let payload_start = KEY_BUNDLE_START + key_bundle_len;

            /* START OF PAYLOAD HANDLING */

            recv_payload = &reply_message[payload_start..payload_end];

            /* START OF MLDSA87 HANDLING */

            symmetric.decrypt_and_mix(&mut reply_message[online_signature_start..online_signature_tag_end])?;

            let auth = key_bundle
                .verify(
                    REPLY_BINDING,
                    symmetric.channel_binding(),
                    (&reply_message[online_signature_start..online_signature_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;
        } else if let Some(key_bundle) = expected_key_bundle {
            /* START OF RESUME DECODING */

            use resume::*;
            let payload_end = reply_message.len() - PAYLOAD_REV_START;
            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;
            let online_signature_start = reply_message.len() - ONLINE_SIGNATURE_REV_END;
            let online_signature_end = reply_message.len() - ONLINE_SIGNATURE_REV_START;
            let online_signature_tag_end = reply_message.len() - ONLINE_SIGNATURE_TAG_REV_START;

            /* START OF PAYLOAD HANDLING */

            recv_payload = &reply_message[PAYLOAD_START..payload_tag_end];

            /* START OF MLDSA87 HANDLING */

            symmetric.decrypt_and_mix(&mut reply_message[online_signature_start..online_signature_tag_end])?;

            let auth = key_bundle
                .verify(
                    REPLY_BINDING,
                    symmetric.channel_binding(),
                    (&reply_message[online_signature_start..online_signature_end])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Error::Inauthentic)?;

            {
                // TODO: Add session layer authentication here.
                // Consider how to authenticate with socket coherency.
            }

            /* START OF STATE MANAGEMENT */

            let (cipher, send_resumption_token, recv_resumption_token, resupmtion_key) = symmetric.split(true);

            guard.insert(SocketState::Active { socket: todo!(), cipher_idx: false });

            return Ok(todo!());
        } else {
            // If we do not know the responder's key bundle we cannot accept a resume message.
            return Err(Error::Inauthentic);
        }
        {
            // TODO: Add session layer authentication here.
            // Consider how to authenticate with socket coherency.
        }
        {
            use confirm::*;
            let key_bundle_end = KEY_BUNDLE_START + sl.bundle_len();
            let payload_start = key_bundle_end;
            let payload_end = payload_start + send_payload.len();
            let payload_tag_end = payload_end + PAYLOAD_TAG_LEN;
            let online_signature_start = payload_tag_end;
            let online_signature_end = online_signature_start + ONLINE_SIGNATURE_LEN;
            let online_signature_tag_end = online_signature_end + ONLINE_SIGNATURE_TAG_LEN;

            let message_len = online_signature_tag_end;

            /* START OF HEADER ENCODING AND MIXING */

            let mut confirm_message = Segmenter::create_message(message_len, HEADER_LEN, send_socket_id, mtu);

            symmetric.mix(&confirm_message[PREMESSAGE_RANGE]);

            /* START OF KEY BUNDLE HANDLING */

            confirm_message[KEY_BUNDLE_START..key_bundle_end].copy_from_slice(&sl.key_bundle());

            /* START OF PAYLOAD HANDLING */

            confirm_message[payload_start..payload_end].copy_from_slice(&send_payload[..]);

            symmetric.encrypt_and_mix(&mut confirm_message[PAYLOAD_ENCRYPTION_START..payload_tag_end]);

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let signature = sl.sign_with_online_key(CONFIRM_BINDING, symmetric.channel_binding());
            confirm_message[online_signature_start..online_signature_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(&mut confirm_message[online_signature_start..online_signature_tag_end]);

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, send_resumption_token, recv_resumption_token, resupmtion_key) = symmetric.split(true);

            let segmenter = Segmenter::new(confirm_message, HEADER_LEN, mtu);

            guard.insert(SocketState::AwaitingData {
                socket: Arc::new(Socket {
                    cipher,
                    antireplay: Default::default(),
                    send_socket_id,
                    counter: AtomicU64::new(AES_GCM_INIT_COUNTER as u64),
                }),
                segmenter,
                expiry_ts: u64,
                idx: 0,
            });

            Ok(RecvOk::SendReply(segmenter))
        }
    }

    pub(crate) fn process_resume(
        &self,
        mut sl: S,
        state: InitializeState<S>,
        guard: SocketGuard<S>,
        resume_message: &mut [u8],
        mtu: usize,
    ) -> Result<RecvOk<S>, Error> {
        let mut symmetric = state.symmetric;
        let mut decapsulation_key = state.decapsulation_key;

        let send_socket_id;
        {
            use resume::*;
            symmetric.start_resume();

            /* START OF HEADER MIXING */

            symmetric.mix(&resume_message[..HEADER_LEN]);

            /* START OF MLKEM1024 CIPHERTEXT HANDLING */

            symmetric.decrypt_and_mix(
                &mut resume_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_TAG_END],
                false,
            )?;

            let result = decapsulation_key.decapsulate(
                (&resume_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_END])
                    .try_into()
                    .unwrap(),
            );
            let shared_secret = if let Some(ss) = result {
                Zeroizing::new(ss)
            } else {
                return Err(Error::Inauthentic);
            };

            /* START OF MLKEM1024 SHARED SECRET MIXING */

            symmetric.mix(&shared_secret[..]);

            /* START OF PAYLOAD DECRYPTION */

            let payload_tag_end = resume_message.len() - PAYLOAD_TAG_REV_START;

            symmetric.decrypt_and_mix(&mut resume_message[NEW_SOCKET_ID_START..payload_tag_end], true)?;

            /* START OF RECV SOCKET ID HANDLING */

            send_socket_id = u32::from_be_bytes(
                resume_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END]
                    .try_into()
                    .unwrap(),
            );
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

            Ok(RecvOk::Resume)
        }
    }
}
