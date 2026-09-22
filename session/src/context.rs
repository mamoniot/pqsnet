use std::{
    borrow::Cow,
    cell::UnsafeCell,
    sync::{OnceLock, Weak},
};

use cbor4ii::serde::to_writer;
use dashmap::{DashMap, Entry};
use tracing::*;

use crate::{
    application_layer::Route,
    channel::Channel,
    crypto::aes::HotAesGcmDecryptor,
    desegmenter::{Desegmenter, NewResult},
    protocol::*,
    session::{Session, SessionInner},
    varint::*,
};

pub(crate) type SocketId = u64;

pub(crate) struct Socket<R: Route> {
    session: Weak<SessionInner<R>>,
    decryptor: HotAesGcmDecryptor,
}

pub(crate) struct HandshakeProgress {
    pub(crate) state: UnsafeCell<HandshakeState>,
    pub(crate) cur_message: Vec<u8>,
    pub(crate) reserved_socket_id: SocketId,
    pub(crate) desegmenter: OnceLock<Desegmenter>,
}

pub(crate) enum HandshakeEntry {
    Init(Desegmenter),
    State(HandshakeProgress),
}

pub struct Context<R: Route> {
    socket_table: DashMap<SocketId, Option<Socket<R>>>,
    hanshake_table: DashMap<u128, HandshakeEntry>,
}

impl HandshakeEntry {
    pub fn recv_mut<'a>(&mut self, packet: &'a [u8], idx: &mut usize) -> Option<Cow<'a, [u8]>> {
        match self {
            HandshakeEntry::Init(desegmenter) => desegmenter.recv_mut(packet, idx).map(Cow::Owned),
            HandshakeEntry::State(progress) => match Desegmenter::new(packet, idx) {
                NewResult::Success(desegmenter) => {
                    progress.desegmenter = OnceLock::from(desegmenter);
                    None
                }
                NewResult::SingleSeg(message) => Some(Cow::Borrowed(message)),
                NewResult::Failure => None,
            },
        }
    }
}

impl<R: Route> Context<R> {
    pub async fn open_session(&self, packet: &mut [u8], route: R) -> Result<Channel<R>, ()> {
        todo!()
    }

    pub fn drive(&self, packet: &mut [u8], route: R) {}

    pub fn recv_init_message(&self, handshake_header: u128, message: &[u8]) -> Option<Channel<R>> {
        trace!(handshake_header, "recv initial message");
        // If `reserved_socket_id` is `Some` then it is a key in `socket_table`
        // and needs to eventually be removed from it.
        let mut reserved_socket_id = None;
        let mut create_payload = |writer| {
            let mut i = 0;
            loop {
                i += 1;
                let new_socket_id = if i <= 2 {
                    rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U16_MAX as u64)
                } else {
                    rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U32_MAX as u64)
                };
                if !self.socket_table.contains_key(&new_socket_id) {
                    self.socket_table.insert(new_socket_id, Default::default());
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
        match HandshakeState::reply(&handshake_header.to_be_bytes(), message, create_payload) {
            Ok(Complete(reply_message, keys)) => {
                todo!()
            }
            Ok(Incomplete(reply_message, state)) => {
                let socket_id = reserved_socket_id.expect("reserved socket id was absent");

                let response_header = handshake_header + HANDSHAKE_HEADER_SOCKET_ID_INC;
                let confirm_header = response_header + HANDSHAKE_HEADER_SOCKET_ID_INC;

                self.hanshake_table.insert(
                    confirm_header,
                    SocketState::Handshake(HandshakeProgress {
                        state,
                        cur_message: reply_message,
                        desegmenter: OnceLock::new(),
                    }),
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
            if packet.len() < HANDSHAKE_HEADER_LEN {
                warn!("received invalid handshake id");
                return None;
            };
            let handshake_header = u128::from_be_bytes(packet[..HANDSHAKE_HEADER_LEN].try_into().unwrap());
            *idx = HANDSHAKE_HEADER_LEN;
            debug_assert_eq!(socket_id, (handshake_header >> (u128::BITS - 8)) as u64);

            match socket_id {
                SOCKET_ID_INIT_MESSAGE => match self.hanshake_table.entry(handshake_header) {
                    Entry::Occupied(entry) => {
                        let HandshakeEntry::Init(desegmenter) = entry.get_mut() else {
                            unreachable!();
                        };
                        let Some(message) = desegmenter.recv(packet, idx) else {
                            trace!(handshake_header, "received initial message fragment for handshake");
                            return None;
                        };
                        entry.remove();
                        return self.recv_init_message(handshake_header, &message[..]);
                    }
                    Entry::Vacant(entry) => match Desegmenter::new(packet, idx) {
                        NewResult::Success(desegmenter) => {
                            entry.insert(HandshakeEntry::Init(desegmenter));
                            trace!(handshake_header, "received first message fragment for handshake");
                        }
                        NewResult::SingleSeg(message) => {
                            drop(entry);
                            return self.recv_init_message(handshake_header, message);
                        }
                        NewResult::Failure => {
                            warn!(handshake_header, "received invalid handshake fragment")
                        }
                    },
                },
                SOCKET_ID_RESPONSE_MESSAGE => {}
                SOCKET_ID_CONFIRM_MESSAGE => {}
                _ => {
                    warn!(socket_id, "received unrecognized socket id in reserved range");
                    return None;
                }
            }
            match self.hanshake_table.entry(handshake_header) {
                Entry::Occupied(entry) => {
                    let Some(message) = entry.get().recv_mut(packet, idx) else {
                        trace!("received handshake initial message fragment");
                        return None;
                    };
                    entry.remove();
                    return self.recv_init_message(handshake_header, &message[..]);
                }
                Entry::Vacant(entry) => match Desegmenter::new(packet, idx) {
                    NewResult::Success(desegmenter) => {
                        entry.insert(desegmenter);
                    }
                    NewResult::SingleSeg(message) => {
                        drop(entry);
                        return self.recv_init_message(handshake_header, message);
                    }
                    NewResult::Failure => {}
                },
            }
        } else {
            let Some(entry) = self.socket_table.get(&socket_id) else {
                info!("received unrecognized socket id '{socket_id}'");
                return None;
            };
            let Some(session) = entry.session.upgrade().map(Session) else {
                // if unhandled this case would be a race condition.
                info!("received unrecognized socket id '{socket_id}'");
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
            if !entry.decryptor.decrypt_in_place(crypto_header, ciphertext) {
                info!("received corrupted or inauthentic packet");
                return None;
            }

            session.recv(packet, idx, route);
        }
        todo!()
    }
}
