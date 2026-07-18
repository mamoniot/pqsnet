use dashmap::DashMap;
use rand_core::*;
use zeroize::Zeroizing;

use crate::{
    crypto::{mldsa87::*, mlkem1024::*},
    desegmentation::{self, Desegmentation},
    init_table::{Entry, InitTable},
    messages::*,
    session_layer::SessionLayer,
    symmetric_state::SymmetricState,
};

pub struct Context<S: SessionLayer> {
    init_table: InitTable<Desegmentation<{ initialize::HEADER_LEN }>>,
    socket_table: DashMap<u32, SocketState<S>>,
}

enum SocketState<S: SessionLayer> {
    Reserved,
    SentInitialize {
        symmetric: SymmetricState<S>,
        decapsulation_key: S::DecapsulationKeyImpl,
    },
    SentReply {
        symmetric: SymmetricState<S>,
        send_socket_id: u32,
    },
    Active(Socket<S>),
}

pub struct Socket<S: SessionLayer> {
    todo: S,
}

pub enum RecvResult<S: SessionLayer> {
    NewSocket(Socket<S>),
}

impl<S: SessionLayer> Context<S> {
    pub fn recv(&self, sl: S, packet: &mut [u8]) -> RecvResult<S> {
        let key_id = u32::from_be_bytes(
            packet[shared::SOCKET_ID_START..shared::SOCKET_ID_END]
                .try_into()
                .unwrap(),
        );

        if key_id == initialize::NULL_KEY_ID {
            let initialize_id = u64::from_be_bytes(
                packet[initialize::INITIALIZE_ID_START..initialize::INITIALIZE_ID_END]
                    .try_into()
                    .unwrap(),
            );
            if Desegmentation::<{ initialize::HEADER_LEN }>::is_single_segment(packet) {
                self.process_initialize(sl, packet);
            } else {
                // The following line locks init_table.
                // That lock is dropped before `process_initialize` is called.
                match self.init_table.entry(initialize_id) {
                    Entry::Vacant(entry) => match Desegmentation::first_recv(packet, initialize::PAYLOAD_TAG_END) {
                        desegmentation::FirstRecvResult::Segmented(desegmentation) => {
                            entry.insert(desegmentation);
                        }
                        desegmentation::FirstRecvResult::NotSegmented => {
                            drop(entry);

                            self.process_initialize(sl, packet);
                        }
                        desegmentation::FirstRecvResult::Invalid => todo!(),
                    },
                    Entry::Occupied(mut entry) => match entry.get_mut().recv(packet) {
                        desegmentation::RecvResult::Complete => {
                            let mut message = entry.remove().complete();

                            self.process_initialize(sl, message.as_mut());
                        }
                        desegmentation::RecvResult::Invalid => todo!(),
                        desegmentation::RecvResult::Duplicate => todo!(),
                        desegmentation::RecvResult::Incomplete => todo!(),
                    },
                }
            }
        }

        todo!()
    }

    fn initialize(&self, mut sl: S, resumption_token: &[u8], resumption_key: &[u8]) {
        use initialize::*;
        let mut symmetric = SymmetricState::<S>::default();

        let mut send_message = vec![0; PAYLOAD_TAG_END];

        /* START OF HEADER ENCODING */
        // TODO: Partially handle segmentation to fill seg_total and seg_rem.

        /* START OF RESUMPTION TOKEN HANDLING */

        send_message[RESUMPTION_TOKEN_START..RESUMPTION_TOKEN_END].copy_from_slice(resumption_token);

        symmetric.mix(&send_message[..RESUMPTION_TOKEN_END]);

        symmetric.mix(resumption_key);

        /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

        let (encapsulation_key, decapsulation_key) = S::DecapsulationKeyImpl::generate();
        send_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_END].copy_from_slice(&encapsulation_key);

        symmetric.encrypt_and_mix(
            &mut send_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_TAG_END],
            false,
        );

        /* START OF SEND SOCKET ID HANDLING */
        let recv_socket_id = self.generate_socket_id(&mut sl);

        send_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&recv_socket_id.to_be_bytes());

        symmetric.encrypt_and_mix(&mut send_message[NEW_SOCKET_ID_START..PAYLOAD_TAG_END], false);

        /* START OF STATE MANAGEMENT */

        self.socket_table.insert(recv_socket_id, SocketState::SentInitialize { symmetric, decapsulation_key });
    }

    fn process_initialize(&self, mut sl: S, recv_message: &mut [u8]) -> bool {
        use shared::*;
        let mut symmetric = SymmetricState::<S>::default();

        let shared_secret;
        let ciphertext;
        let send_socket_id;
        {
            use initialize::*;

            /* START OF RESUMPTION TOKEN HANDLING */

            symmetric.mix(&recv_message[..RESUMPTION_TOKEN_END]);

            let resumption_token = (&recv_message[RESUMPTION_TOKEN_START..RESUMPTION_TOKEN_END])
                .try_into()
                .unwrap();

            if let Some(resumption_key) = sl.lookup_resumption_key(resumption_token) {
                symmetric.mix(&resumption_key);
            } else {
                symmetric.mix(&[0; RESUMPTION_KEY_LEN]);
            }

            /* START OF MLKEM1024 EPHEMERAL ENCAPSULATION KEY HANDLING */

            let auth = symmetric.mix_and_decrypt(
                &mut recv_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_TAG_END],
                false,
            );
            if !auth {
                return false;
            }

            let result = S::DecapsulationKeyImpl::encapsulate(
                (&recv_message[EPHEMERAL_ENC_KEY_START..EPHEMERAL_ENC_KEY_END])
                    .try_into()
                    .unwrap(),
            );
            if let Some((ss, c)) = result {
                ciphertext = c;
                shared_secret = Zeroizing::new(ss);
            } else {
                return false;
            }

            /* START OF SEND SOCKET ID HANDLING */

            let auth = symmetric.mix_and_decrypt(&mut recv_message[NEW_SOCKET_ID_START..PAYLOAD_TAG_END], false);
            if !auth {
                return false;
            }

            send_socket_id =
                u32::from_be_bytes(recv_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].try_into().unwrap());
        }
        {
            use reply::*;
            let mut send_message = vec![0; STATIC_ONLINE_SIGN_TAG_END];

            /* START OF HEADER ENCODING */
            // TODO: Partially handle segmentation to fill seg_total and seg_rem.

            send_message[SOCKET_ID_START..SOCKET_ID_END].copy_from_slice(&send_socket_id.to_be_bytes());

            /* START OF MLKEM1024 CIPHERTEXT ENCRYPTION */

            send_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_END].copy_from_slice(&ciphertext);

            symmetric.encrypt_and_mix(
                &mut send_message[EPHEMERAL_CIPHERTEXT_START..EPHEMERAL_CIPHERTEXT_TAG_END],
                false,
            );

            /* START OF MLKEM1024 SHARED SECRET MIXING */

            symmetric.mix(shared_secret.as_ref());

            /* START OF MLDSA87 KEY BUNDLE ENCODING */

            send_message[STATIC_OFFLINE_PUBKEY_START..STATIC_OFFLINE_SIGN_END]
                .copy_from_slice(&sl.static_public_keys().encode_key_bundle());

            /* START OF RECV SOCKET ID HANDLING */

            let recv_socket_id = self.generate_socket_id(&mut sl);

            send_message[NEW_SOCKET_ID_START..NEW_SOCKET_ID_END].copy_from_slice(&recv_socket_id.to_be_bytes());

            /* START OF MLDSA87 KEY BUNDLE AND RECV SOCKET ID ENCRYPTION */

            symmetric.encrypt_and_mix(&mut send_message[STATIC_OFFLINE_PUBKEY_START..PAYLOAD_TAG_END], false);

            /* START OF MLDSA87 SIGNING AND ENCRYPTION */

            let signature = sl
                .static_public_keys()
                .sign_with_online(REPLY_BINDING_DOMAIN_NAME, symmetric.channel_binding());

            send_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_END].copy_from_slice(&signature);

            symmetric.encrypt_and_mix(
                &mut send_message[STATIC_ONLINE_SIGN_START..STATIC_ONLINE_SIGN_TAG_END],
                false,
            );

            self.socket_table.insert(recv_socket_id, SocketState::SentReply { symmetric, send_socket_id });

            true
        }
    }

    fn generate_socket_id(&self, sl: &mut S) -> u32 {
        loop {
            // Rejection sample a unique socket id.
            let candidate = sl.rng().next_u32();
            if let dashmap::Entry::Vacant(entry) = self.socket_table.entry(candidate) {
                entry.insert(SocketState::Reserved);
                return candidate;
            }
        }
    }

    pub fn send() {}
}
