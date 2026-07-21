use std::sync::{Arc, atomic::AtomicU64};

use zeroize::Zeroizing;

use crate::{
    context::{Context, HandshakeState, RecvOk, Socket, SocketGuard, SocketState},
    crypto::prelude::*,
    desegmentation::precalc_segments,
    error::Error,
    messages::{shared::*, *},
    session_layer::{ResumptionAction, SessionLayer},
    symmetric_state::SymmetricState,
};

pub struct ReplyState<S: SessionLayer> {
    reply_message: Arc<[u8]>,
    symmetric: SymmetricState<S>,
    send_socket_id: u32,
}

impl<S: SessionLayer> Context<S> {
    pub(crate) fn process_initialize(
        &self,
        mut sl: S,
        init_message: &mut [u8],
        mtu: usize,
    ) -> Result<RecvOk<S>, Error> {
        let mut symmetric = SymmetricState::<S>::default();

        let shared_secret;
        let ciphertext;
        let send_socket_id;
        let mut do_resume = false;
        {
            use initialize::*;
            /* START OF RESUMPTION TOKEN HANDLING */

            symmetric.mix(&init_message[..RESUMPTION_TOKEN_END]);

            let resumption_token = (&init_message[RESUMPTION_TOKEN_START..RESUMPTION_TOKEN_END])
                .try_into()
                .unwrap();

            match sl.lookup_resumption_key(resumption_token) {
                ResumptionAction::ResumeKnownWithKey { key } => {
                    symmetric.mix(&key[..]);
                    do_resume = true;
                }
                ResumptionAction::AuthWithKey { key } => {
                    symmetric.mix(&key[..]);
                }
                ResumptionAction::AuthUnknown => {
                    symmetric.mix(&[0; RESUMPTION_KEY_LEN]);
                }
                ResumptionAction::Reject => {
                    return Err(Error::Inauthentic);
                }
            }

            /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            symmetric.mix_and_decrypt(
                &mut init_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_TAG_END],
                false,
            )?;

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

            /* START OF SEND SOCKET ID HANDLING */

            symmetric.mix_and_decrypt(&mut init_message[NEW_SOCKET_ID_START..PAYLOAD_TAG_END], false)?;

            send_socket_id =
                u32::from_be_bytes(init_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].try_into().unwrap());
        }

        let mut reply_message = Vec::new();
        if do_resume {
            symmetric.start_resume();
            reply_message.resize(resume::MESSAGE_LEN, 0);
        } else {
            reply_message.resize(reply::MESSAGE_LEN, 0);
        }
        {
            /* START OF REPLY MESSAGE AND RESUME MESSAGE SHARED SECTION */

            use reply::*;

            /* START OF HEADER ENCODING AND MIXING */

            reply_message[SOCKET_ID_START..SOCKET_ID_END].copy_from_slice(&send_socket_id.to_be_bytes());

            (reply_message[SEGMENT_TOTAL_IDX], reply_message[SEGMENT_REMAINDER_IDX]) =
                precalc_segments(reply::HEADER_LEN, reply_message.len(), mtu);

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

            symmetric.encrypt_and_mix(&mut reply_message[NEW_SOCKET_ID_START..PAYLOAD_TAG_END], true);

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, resumption_token, resupmtion_key) = symmetric.split();

            recv_socket.insert(SocketState::AwaitingData {
                resend_until_recv: reply_message.into(),
                cipher,
                send_socket_id,
            });

            Ok(RecvOk::ResumeSent)
        } else {
            use reply::*;

            /* START OF MLDSA87 KEY BUNDLE ENCODING */

            reply_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_SIGN_END]
                .copy_from_slice(&sl.static_public_keys().encode_key_bundle());

            /* START OF RECV SOCKET ID HANDLING */

            let recv_socket = self.reserve_socket(&mut sl);

            reply_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&recv_socket.id().to_be_bytes());

            /* START OF PAYLOAD ENCRYPTION */

            symmetric.encrypt_and_mix(&mut reply_message[STATIC_OFFLINE_PUBKEY_START..PAYLOAD_TAG_END], false);

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let signature = sl
                .static_public_keys()
                .sign_with_online(REPLY_BINDING_DOMAIN_NAME, symmetric.channel_binding());

            reply_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_END].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(
                &mut reply_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_TAG_END],
                false,
            );

            /* START OF STATE MANAGEMENT */

            recv_socket.insert(SocketState::Handshake {
                state: HandshakeState::SendingReply(ReplyState {
                    reply_message: reply_message.into(),
                    symmetric,
                    send_socket_id,
                }),
                desegmenter: Default::default(),
            });

            Ok(RecvOk::ReplySent)
        }
    }

    pub(crate) fn process_confirm(
        &self,
        mut sl: S,
        state: ReplyState<S>,
        guard: SocketGuard<S>,
        confirm_message: &mut [u8],
        mtu: usize,
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

            symmetric.mix_and_decrypt(
                &mut confirm_message[STATIC_OFFLINE_PUBKEY_START..PAYLOAD_TAG_END],
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

            symmetric.mix_and_decrypt(
                &mut confirm_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_TAG_END],
                true,
            )?;

            let auth = S::PublicKeyBundleImpl::verify(
                (&confirm_message[STATIC_ONLINE_PUBKEY_START..STATIC_ONLINE_PUBKEY_END])
                    .try_into()
                    .unwrap(),
                CONFIRM_BINDING_DOMAIN_NAME,
                symmetric.channel_binding(),
                (&confirm_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_END])
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
                cipher,
                antireplay: Default::default(),
                send_socket_id,
                counter: AtomicU64::new(AES_GCM_INIT_COUNTER as u64),
            })));

            Ok(RecvOk::ReplySent)
        }
    }
}
