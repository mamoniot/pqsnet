use std::sync::{Arc, atomic::AtomicU64};

use zeroize::Zeroizing;

use crate::{
    context::{Context, HandshakeState, RecvOk, Socket, SocketGuard, SocketState},
    crypto::prelude::*,
    desegmentation::precalc_segments,
    error::Error,
    messages::{shared::AES_GCM_INIT_COUNTER, *},
    session_layer::SessionLayer,
    symmetric_state::SymmetricState,
};

pub struct InitializeState<S: SessionLayer> {
    message: Arc<[u8]>,
    symmetric: SymmetricState<S>,
    decapsulation_key: S::DecapsulationKeyImpl,
}

impl<S: SessionLayer> Context<S> {
    pub fn initialize(&self, mut sl: S, resumption_token: &[u8], resumption_key: &[u8], mtu: usize) {
        use {initialize::*, shared::*};
        let mut symmetric = SymmetricState::<S>::default();

        let mut init_message = vec![0; PAYLOAD_TAG_END];

        /* START OF HEADER ENCODING */

        (init_message[SEGMENT_TOTAL_IDX], init_message[SEGMENT_REMAINDER_IDX]) =
            precalc_segments(HEADER_LEN, init_message.len(), mtu);

        /* START OF RESUMPTION TOKEN HANDLING */

        init_message[RESUMPTION_TOKEN_START..RESUMPTION_TOKEN_END].copy_from_slice(resumption_token);

        symmetric.mix(&init_message[..RESUMPTION_TOKEN_END]);

        symmetric.mix(resumption_key);

        /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

        let (encapsulation_key, decapsulation_key) = S::DecapsulationKeyImpl::generate();
        init_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_END].copy_from_slice(&encapsulation_key);

        symmetric.encrypt_and_mix(
            &mut init_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_TAG_END],
            false,
        );

        /* START OF SEND SOCKET ID HANDLING */
        let socket_guard = self.reserve_socket(&mut sl);

        init_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&socket_guard.id().to_be_bytes());

        symmetric.encrypt_and_mix(&mut init_message[NEW_SOCKET_ID_START..PAYLOAD_TAG_END], false);

        /* START OF STATE MANAGEMENT */

        socket_guard.insert(SocketState::Handshake {
            state: HandshakeState::SendingInitialize(InitializeState {
                message: init_message.into(),
                symmetric,
                decapsulation_key,
            }),
            desegmenter: Default::default(),
        })
    }

    pub(crate) fn process_reply(
        &self,
        mut sl: S,
        state: InitializeState<S>,
        guard: SocketGuard<S>,
        reply_message: &mut [u8],
        mtu: usize,
    ) -> Result<RecvOk<S>, Error> {
        use shared::*;

        let mut symmetric = state.symmetric;
        let mut decapsulation_key = state.decapsulation_key;

        let send_socket_id;
        {
            use reply::*;

            /* START OF HEADER MIXING */

            symmetric.mix(&reply_message[..HEADER_LEN]);

            /* START OF MLKEM1024 CIPHERTEXT HANDLING */

            symmetric.mix_and_decrypt(
                &mut reply_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_TAG_END],
                false,
            )?;

            let result = decapsulation_key.decapsulate(
                (&reply_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_END])
                    .try_into()
                    .unwrap(),
            );
            let shared_secret = if let Some(ss) = result {
                Zeroizing::new(ss)
            } else {
                return Err(Error::Inauthentic);
            };

            /* START OF MLKEM1024 SHARED SECRET MIXING */

            symmetric.mix(shared_secret.as_ref());

            /* START OF PAYLOAD DECRYPTION */

            symmetric.mix_and_decrypt(&mut reply_message[STATIC_OFFLINE_PUBKEY_START..PAYLOAD_TAG_END], false)?;

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

            /* START OF RECV SOCKET ID HANDLING */

            send_socket_id = u32::from_be_bytes(
                reply_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END]
                    .try_into()
                    .unwrap(),
            );

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            symmetric.mix_and_decrypt(
                &mut reply_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_TAG_END],
                false,
            )?;

            let auth = S::PublicKeyBundleImpl::verify(
                (&reply_message[STATIC_ONLINE_PUBKEY_START..STATIC_ONLINE_PUBKEY_END])
                    .try_into()
                    .unwrap(),
                REPLY_BINDING_DOMAIN_NAME,
                symmetric.channel_binding(),
                (&reply_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_END])
                    .try_into()
                    .unwrap(),
            );
            if !auth {
                return Err(Error::Inauthentic);
            }
        }
        {
            // TODO: Add session layer authentication here.
        }
        {
            use confirm::*;
            let mut confirm_message = vec![0; MESSAGE_LEN];

            /* START OF HEADER ENCODING AND MIXING */

            confirm_message[SOCKET_ID_START..SOCKET_ID_END].copy_from_slice(&send_socket_id.to_be_bytes());

            (
                confirm_message[SEGMENT_TOTAL_IDX],
                confirm_message[SEGMENT_REMAINDER_IDX],
            ) = precalc_segments(HEADER_LEN, confirm_message.len(), mtu);

            symmetric.mix(&confirm_message[..HEADER_LEN]);

            /* START OF MLDSA87 KEY BUNDLE ENCODING */

            confirm_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_SIGN_END]
                .copy_from_slice(&sl.static_public_keys().encode_key_bundle());

            /* START OF PAYLOAD ENCRYPTION */

            symmetric.encrypt_and_mix(
                &mut confirm_message[STATIC_OFFLINE_PUBKEY_START..PAYLOAD_TAG_END],
                false,
            );

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let signature = sl
                .static_public_keys()
                .sign_with_online(CONFIRM_BINDING_DOMAIN_NAME, symmetric.channel_binding());

            confirm_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_END].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(
                &mut confirm_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_TAG_END],
                true,
            );

            // TODO: Add resumption token and key handling.
            let (cipher, resumption_token, resupmtion_key) = symmetric.split();

            /* START OF STATE MANAGEMENT */

            guard.insert(SocketState::Active(Arc::new(Socket {
                cipher,
                antireplay: Default::default(),
                send_socket_id,
                counter: AtomicU64::new(AES_GCM_INIT_COUNTER as u64),
            })));

            Ok(RecvOk::ReplySent)
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

            symmetric.mix_and_decrypt(
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

            symmetric.mix(shared_secret.as_ref());

            /* START OF PAYLOAD DECRYPTION */

            symmetric.mix_and_decrypt(&mut resume_message[NEW_SOCKET_ID_START..PAYLOAD_TAG_END], true)?;

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
                cipher,
                antireplay: Default::default(),
                send_socket_id,
                counter: AtomicU64::new(AES_GCM_INIT_COUNTER as u64),
            })));

            Ok(RecvOk::ReplySent)
        }
    }
}
