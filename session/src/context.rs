use std::{
    borrow::Cow,
    cell::UnsafeCell,
    sync::{Arc, OnceLock, Weak},
};

use cbor4ii::serde::to_writer;
use dashmap::{DashMap, Entry};
use psqnet_transport::{
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
    desegmenter::{Desegmenter, NewResult},
    protocol::*,
    session::{Session, SessionInner},
    varint::*,
};

pub(crate) type SocketId = u64;

pub(crate) struct Socket<R: Route> {
    session: Weak<SessionInner<R>>,
}

pub(crate) enum HandshakeEntry {
    CoolDown,
    Init(Desegmenter),
    Reply {
        reserved_socket_id: SocketId,
        desegmenter: OnceLock<Desegmenter>,
        cur_message: Vec<u8>,
        state: ReplyState<Crypto>,
    },
}

pub struct Context<R: Route> {
    socket_table: DashMap<SocketId, Option<Socket<R>>>,
    hanshake_table: DashMap<u128, HandshakeEntry>,
    secret_bundle: Arc<SecretBundle<MlDsa87PublicKey, MlDsa87SecretKey>>,
}

impl HandshakeEntry {
    pub fn recv_mut<'a>(&mut self, packet: &'a [u8], idx: &mut usize) -> Option<Cow<'a, [u8]>> {
        match self {
            HandshakeEntry::Init(desegmenter) => desegmenter.recv_mut(packet, idx).map(Cow::Owned),
            HandshakeEntry::CoolDown => None,
            HandshakeEntry::Reply { reserved_socket_id, desegmenter, cur_message, state } => todo!(),
        }
    }
}

impl<R: Route> Context<R> {
    pub async fn open_session(&self, packet: &mut [u8], route: R) -> Result<Channel<R>, ()> {
        todo!()
    }

    pub fn drive(&self, packet: &mut [u8], route: R) {}

    pub fn recv_init_message(&self, handshake_header: u128, message: &mut [u8]) -> Option<Channel<R>> {
        trace!(handshake_header, "recv initial message");
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
            &handshake_header.to_be_bytes(),
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

                let response_header = handshake_header + HANDSHAKE_HEADER_SOCKET_ID_INC;
                let confirm_header = response_header + HANDSHAKE_HEADER_SOCKET_ID_INC;

                self.hanshake_table.insert(
                    confirm_header,
                    HandshakeEntry::Reply {
                        desegmenter: OnceLock::new(),
                        reserved_socket_id,
                        cur_message,
                        state,
                    },
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
            if socket_id != SOCKET_ID_INIT_MESSAGE {
                warn!(socket_id, "received unrecognized socket id in reserved range");
                return None;
            };

            let handshake_header = u128::from_be_bytes(packet[..HANDSHAKE_HEADER_LEN].try_into().unwrap());
            *idx = HANDSHAKE_HEADER_LEN;
            debug_assert_eq!(socket_id, (handshake_header >> (u128::BITS - 8)) as u64);

            match self.hanshake_table.entry(handshake_header) {
                Entry::Occupied(mut entry) => {
                    let Some(message) = entry.get().recv_mut(packet, idx) else {
                        trace!("received handshake initial message fragment");
                        return None;
                    };

                    match entry.insert(HandshakeEntry::CoolDown) {
                        HandshakeEntry::CoolDown => unreachable!(),
                        HandshakeEntry::Init(_) => {
                            return self.recv_init_message(handshake_header, &mut message[..]);
                        }
                        HandshakeEntry::Reply { reserved_socket_id, desegmenter, cur_message, state } => todo!(),
                    }
                }
                Entry::Vacant(entry) => match Desegmenter::new(packet, idx) {
                    NewResult::Success(desegmenter) => {
                        entry.insert(HandshakeEntry::Init(desegmenter));
                    }
                    NewResult::SingleSeg(message_range) => {
                        drop(entry);
                        return self.recv_init_message(handshake_header, &mut packet[message_range]);
                    }
                    NewResult::Failure => {
                        warn!("received invalid segmentation data");
                    }
                },
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
