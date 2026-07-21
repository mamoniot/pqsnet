use std::sync::{Arc, atomic::AtomicU64};

use rand_core::Rng;
use zeroize::Zeroizing;

use crate::{
    context::{Context, HandshakeState, RecvOk, Socket, SocketGuard, SocketState}, crypto::prelude::*, desegmentation::{Mtu, Segmenter}, error::Error, messages::{shared::AES_GCM_INIT_COUNTER, *}, session_layer::SessionLayer, symmetric_state::SymmetricState,
};

pub struct InitializeState<S: SessionLayer> {
    segmenter: Segmenter,
    symmetric: SymmetricState<S>,
    decapsulation_key: S::DecapsulationKeyImpl,
}

impl<S: SessionLayer> Context<S> {
    pub fn initialize(&self, mut sl: S, resumption_token: &[u8], resumption_key: &[u8], mtu: Mtu) {
        use initialize::*;
        let mut symmetric = SymmetricState::<S>::default();

        /* START OF HEADER ENCODING */

        let mut init_message = Segmenter::create_message(MESSAGE_LEN, HEADER_LEN, 0, mtu);

        init_message[INITIALIZE_ID_START..INITIALIZE_ID_END].copy_from_slice(&sl.rng().next_u64().to_be_bytes());

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

        let payload_tag_end = MESSAGE_LEN - PAYLOAD_TAG_REV_START;

        let socket_guard = self.reserve_socket(&mut sl);

        init_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&socket_guard.id().to_be_bytes());

        symmetric.encrypt_and_mix(&mut init_message[NEW_SOCKET_ID_START..payload_tag_end], false);

        /* START OF STATE MANAGEMENT */

        let segmenter = Segmenter::new(init_message, HEADER_LEN, mtu);

        socket_guard.insert(SocketState::Handshake {
            state: HandshakeState::SendingInitialize(InitializeState {
                segmenter,
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
        mtu: Mtu,
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

            let payload_tag_end = reply_message.len() - PAYLOAD_TAG_REV_START;

            symmetric.mix_and_decrypt(&mut reply_message[STATIC_OFFLINE_PUBKEY_START..payload_tag_end], false)?;

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

            let static_online_sign_start = reply_message.len() - STATIC_ONLINE_SIGN_REV_END;
            let static_online_sign_end = reply_message.len() - STATIC_ONLINE_SIGN_REV_START;
            let static_online_sign_tag_end = reply_message.len() - STATIC_ONLINE_SIGN_TAG_REV_START;

            symmetric.mix_and_decrypt(
                &mut reply_message[static_online_sign_start..static_online_sign_tag_end],
                false,
            )?;

            let auth = S::PublicKeyBundleImpl::verify(
                (&reply_message[STATIC_ONLINE_PUBKEY_START..STATIC_ONLINE_PUBKEY_END])
                    .try_into()
                    .unwrap(),
                REPLY_BINDING_DOMAIN_NAME,
                symmetric.channel_binding(),
                (&reply_message[static_online_sign_start..static_online_sign_end])
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

            /* START OF HEADER ENCODING AND MIXING */

            let mut confirm_message = Segmenter::create_message(MESSAGE_LEN, HEADER_LEN, send_socket_id, mtu);

            symmetric.mix(&confirm_message[..HEADER_LEN]);

            /* START OF MLDSA87 KEY BUNDLE ENCODING */

            confirm_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_SIGN_END]
                .copy_from_slice(&sl.static_public_keys().encode_key_bundle());

            /* START OF PAYLOAD ENCRYPTION */

            let payload_tag_end = MESSAGE_LEN - PAYLOAD_TAG_REV_START;

            symmetric.encrypt_and_mix(
                &mut confirm_message[STATIC_OFFLINE_PUBKEY_START..payload_tag_end],
                false,
            );

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let static_online_sign_start = MESSAGE_LEN - STATIC_ONLINE_SIGN_REV_END;
            let static_online_sign_end = MESSAGE_LEN - STATIC_ONLINE_SIGN_REV_START;
            let static_online_sign_tag_end = MESSAGE_LEN - STATIC_ONLINE_SIGN_TAG_REV_START;

            let signature = sl
                .static_public_keys()
                .sign_with_online(CONFIRM_BINDING_DOMAIN_NAME, symmetric.channel_binding());

            confirm_message[static_online_sign_start..static_online_sign_end].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(
                &mut confirm_message[static_online_sign_start..static_online_sign_tag_end],
                true,
            );

            /* START OF STATE MANAGEMENT */

            // TODO: Add resumption token and key handling.
            let (cipher, resumption_token, resupmtion_key) = symmetric.split();

            let segmenter = Segmenter::new(confirm_message, HEADER_LEN, mtu);

            guard.insert(SocketState::Active(Arc::new(Socket {
                cipher,
                segmenter: Some(segmenter.clone()),
                antireplay: Default::default(),
                send_socket_id,
                counter: AtomicU64::new(AES_GCM_INIT_COUNTER as u64),
            })));

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

            let payload_tag_end = resume_message.len() - PAYLOAD_TAG_REV_START;

            symmetric.mix_and_decrypt(&mut resume_message[NEW_SOCKET_ID_START..payload_tag_end], true)?;

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
