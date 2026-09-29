use std::sync::{Arc, OnceLock, Weak};

use cbor4ii::serde::to_writer;
use dashmap::{DashMap, Entry};
use psqnet_transport::{
    HandshakeComplete,
    error::Error,
    initiator::InitState,
    key_bundle::SecretBundle,
    responder::{InitOk, ReplyState},
};
use tracing::*;

use crate::{
    application_layer::Route,
    channel::Channel,
    crypto::{
        mldsa::{MlDsa87PublicKey, MlDsa87SecretKey},
        transport::Crypto,
    },
    desegmenter::{Desegmenter, NewResult, SegError},
    protocol::*,
    session::SessionInner,
    varint::*,
};

pub(crate) type SocketId = u64;

pub(crate) struct Socket<R: Route> {
    session: Weak<SessionInner<R>>,
}

pub(crate) enum HandshakeEntry {
    CoolDown,
    Init(Desegmenter),
    Open {
        reserved_socket_id: SocketId,
        desegmenter: Option<Desegmenter>,
        cur_message: Vec<u8>,
        state: InitState<Crypto>,
    },
    Reply {
        reserved_socket_id: SocketId,
        desegmenter: Option<Desegmenter>,
        cur_message: Vec<u8>,
        state: ReplyState<Crypto>,
    },
}

pub struct Context<R: Route> {
    socket_table: DashMap<SocketId, Option<Socket<R>>>,
    hanshake_table: DashMap<u128, HandshakeEntry>,
    secret_bundle: Arc<SecretBundle<MlDsa87PublicKey, MlDsa87SecretKey>>,
}

impl<R: Route> Context<R> {
    fn create_payload(&self, writer: impl std::io::Write) -> SocketId {
        let mut i = 0;
        loop {
            i += 1;
            let new_socket_id = if i <= 2 {
                rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U16_MAX as u64)
            } else {
                rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U32_MAX as u64)
            };
            if !self.socket_table.contains_key(&new_socket_id) {
                // Without this match there would be a race condition from chance `socket_id` collisions.
                match self.socket_table.entry(new_socket_id) {
                    Entry::Occupied(_) => {
                        continue;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(None);
                    }
                }

                to_writer(
                    writer,
                    &HandshakePayload {
                        major_version: CUR_MAJOR_VERSION,
                        minor_version: CUR_MINOR_VERSION,
                        socket_id: new_socket_id,
                    },
                );
                return new_socket_id;
            }
        }
    }

    pub async fn open(&self, route: R) -> Result<Channel<R>, ()> {
        let mut handshake_no: u128 = rand::random();
        handshake_no >>= 8;
        debug_assert_eq!(SOCKET_ID_INIT_MESSAGE, 0);

        let reply_no = handshake_no + HANDSHAKE_NO_SOCKET_ID_INC;

        let mut payload = Vec::new();
        let reserved_socket_id = self.create_payload(&mut payload);

        let (cur_message, state) = InitState::initialize(
            &handshake_no.to_be_bytes(),
            self.secret_bundle.clone(),
            None,
            payload.into(),
        );

        self.hanshake_table.insert(
            reply_no,
            HandshakeEntry::Open {
                reserved_socket_id,
                desegmenter: None,
                cur_message,
                state,
            },
        );

        todo!()
    }

    pub fn drive(&self, packet: &mut [u8], route: R) {}

    fn recv_init_message(&self, handshake_no: u128, message: &mut [u8]) -> Option<Channel<R>> {
        trace!(handshake_no, "recv initial message");
        // If `reserved_socket_id` is `Some` then it is a key in `socket_table`
        // and needs to eventually be removed from it.
        let mut reserved_socket_id = None;
        let create_payload = |writer: &mut Vec<u8>| {
            let mut i = 0;
            loop {
                i += 1;
                let new_socket_id = if i <= 2 {
                    rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U16_MAX as u64)
                } else {
                    rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U32_MAX as u64)
                };
                if !self.socket_table.contains_key(&new_socket_id) {
                    // Without this match there would be a race condition from chance `socket_id` collisions.
                    match self.socket_table.entry(new_socket_id) {
                        Entry::Occupied(_) => {
                            continue;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(None);
                        }
                    }
                    reserved_socket_id = Some(new_socket_id);

                    to_writer(
                        writer,
                        &HandshakePayload {
                            major_version: CUR_MAJOR_VERSION,
                            minor_version: CUR_MINOR_VERSION,
                            socket_id: new_socket_id,
                        },
                    );
                    return;
                }
            }
        };

        match ReplyState::process_initialize(
            &handshake_no.to_be_bytes(),
            message,
            &self.secret_bundle,
            None,
            create_payload,
        ) {
            Ok(InitOk::Complete(complete)) => {
                todo!()
            }
            Ok(InitOk::Incomplete(cur_message, state)) => {
                let reserved_socket_id = reserved_socket_id.expect("reserved socket id was absent");

                let reply_no = handshake_no + HANDSHAKE_NO_SOCKET_ID_INC;
                let confirm_no = reply_no + HANDSHAKE_NO_SOCKET_ID_INC;

                self.hanshake_table.insert(
                    confirm_no,
                    HandshakeEntry::Reply { desegmenter: None, reserved_socket_id, cur_message, state },
                );
                // TODO: send reply message and queue it to be resent.
            }
            Err(e) => {
                if let Some(socket_id) = reserved_socket_id {
                    self.socket_table
                        .remove(&socket_id)
                        .expect("reserved socket id was absent");
                }
                todo!();
            }
        }
        None
    }

    pub fn recv(&self, packet: &mut [u8], route: R) -> Option<Channel<R>> {
        let mut packet_idx = 0;
        let idx = &mut packet_idx;

        let Some(socket_id) = varu64_try_read(packet, idx) else {
            warn!("received invalid socket id");
            return None;
        };

        if socket_id <= SOCKET_ID_RESERVED_MAX {
            if packet.len() < HANDSHAKE_NO_LEN {
                warn!("received invalid handshake id");
                return None;
            };
            if socket_id > SOCKET_ID_CONFIRM_MESSAGE {
                warn!(socket_id, "received unrecognized socket id in reserved range");
                return None;
            };

            let handshake_no = u128::from_be_bytes(packet[..HANDSHAKE_NO_LEN].try_into().unwrap());
            *idx = HANDSHAKE_NO_LEN;
            debug_assert_eq!(socket_id, (handshake_no >> (u128::BITS - 8)) as u64);

            match self.hanshake_table.entry(handshake_no) {
                Entry::Occupied(mut entry) => {
                    let mut _message_mem = None;
                    let message = match entry.get_mut() {
                        HandshakeEntry::CoolDown => {
                            debug!(handshake_no, "ignored handshake fragment while on cooldown");
                            return None;
                        }
                        HandshakeEntry::Init(desegmenter)
                        | HandshakeEntry::Reply { desegmenter: Some(desegmenter), .. } => {
                            match desegmenter.recv_mut(packet, idx) {
                                Ok(m) => _message_mem.insert(m),
                                Err(SegError::Segmented) => {
                                    trace!(handshake_no, "received handshake fragment");
                                    return None;
                                }
                                Err(SegError::Invalid) => {
                                    warn!("received invalid segmentation data");
                                    return None;
                                }
                            }
                        }
                        HandshakeEntry::Reply { desegmenter, .. } => {
                            debug_assert_eq!(socket_id, SOCKET_ID_CONFIRM_MESSAGE);

                            match Desegmenter::new(packet, idx) {
                                NewResult::Segmented(d) => {
                                    trace!(handshake_no, "received handshake fragment");
                                    *desegmenter = Some(d);
                                    return None;
                                }
                                NewResult::SingleSeg(message_range) => &mut packet[message_range],
                                NewResult::Invalid => {
                                    warn!(handshake_no, "received invalid segmentation data");
                                    return None;
                                }
                            }
                        }
                    };

                    match entry.insert(HandshakeEntry::CoolDown) {
                        HandshakeEntry::CoolDown => unreachable!(),
                        HandshakeEntry::Init(_) => {
                            return self.recv_init_message(handshake_no, message);
                        }
                        HandshakeEntry::Reply { reserved_socket_id, desegmenter, cur_message, state } => {
                            match state.process_confirm(message) {
                                Ok(HandshakeComplete { message_to_send, keys, remote_key_bundle, recv_payload }) => {
                                    todo!()
                                }
                                Err(error) => {
                                    warn!(handshake_no, error = ?error, "could not authenticate handshake confirmation");
                                }
                            }
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    if socket_id != SOCKET_ID_INIT_MESSAGE {
                        debug!(
                            handshake_no,
                            "received non-init handshake fragment on an unused handshake no"
                        );
                        return None;
                    }

                    match Desegmenter::new(packet, idx) {
                        NewResult::Segmented(desegmenter) => {
                            entry.insert(HandshakeEntry::Init(desegmenter));
                            return None;
                        }
                        NewResult::SingleSeg(message_range) => {
                            entry.insert(HandshakeEntry::CoolDown);
                            return self.recv_init_message(handshake_no, &mut packet[message_range]);
                        }
                        NewResult::Invalid => {
                            warn!(
                                handshake_no,
                                "received invalid segmentation data on an unused handshake no"
                            );
                            return None;
                        }
                    }
                }
            }
        } else {
            let session = self
                .socket_table
                .get(&socket_id)
                .and_then(|s| s.as_ref().map(|s| s.session.upgrade()))
                .flatten();
            let Some(session) = session else {
                info!(socket_id, "received unrecognized socket id");
                return None;
            };
            let j = *idx + 4;
            if j > packet.len() {
                warn!("received invalid counter");
                return None;
            }
            *idx = j;

            let (crypto_header, ciphertext) = packet.split_at_mut(*idx);
            todo!("antireplay");
            // if !entry.decryptor.decrypt_in_place(crypto_header, ciphertext) {
            //     info!("received corrupted or inauthentic packet");
            //     return None;
            // }

            // session.recv(packet, idx, route);
        }
        todo!()
    }
}
