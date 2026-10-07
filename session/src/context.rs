use std::sync::{Arc, Weak};

use cbor4ii::serde::to_vec;
use dashmap::{DashMap, Entry};
use psqnet_transport::{
    HandshakeComplete,
    initiator::InitState,
    key_bundle::SecretBundle,
    responder::{InitOk, ReplyState},
};
use tracing::*;

use crate::{
    application_layer::Route,
    channel::Channel,
    crypto::{aes::HotAesGcmDecryptor, transport::Crypto},
    desegmenter::{Desegmenter, NewResult, SegError},
    protocol::*,
    session::{Session, SessionInner},
    varint::*,
};

pub(crate) type SocketId = u64;

pub(crate) struct Socket<R: Route> {
    session: Weak<SessionInner<R>>,
    decryptor: HotAesGcmDecryptor,
}

pub(crate) enum HandshakeEntry {
    CoolDown,
    ResponderRecv(Desegmenter<Box<[u8]>>),
    InitiatorSent {
        reserved_socket_id: SocketId,
        desegmenter: Option<Desegmenter<Box<[u8]>>>,
        cur_message: Vec<u8>,
        state: InitState<Crypto, Arc<SecretBundle<Crypto>>>,
    },
    ResponderSent {
        reserved_socket_id: SocketId,
        desegmenter: Option<Desegmenter<Box<[u8]>>>,
        cur_message: Vec<u8>,
        state: ReplyState<Crypto>,
    },
}

pub struct Context<R: Route> {
    socket_table: DashMap<SocketId, Option<Socket<R>>>,
    hanshake_table: DashMap<u128, HandshakeEntry>,
    secret_bundle: Arc<SecretBundle<Crypto>>,
}

pub fn secs_since_unix_epoch() -> u64 {
    std::time::SystemTime::UNIX_EPOCH.elapsed().expect("todo").as_secs()
}

impl<R: Route> Context<R> {
    fn create_payload(&self) -> (Vec<u8>, SocketId) {
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

                return (
                    to_vec(
                        Vec::new(),
                        &HandshakePayload {
                            major_version: CUR_MAJOR_VERSION,
                            minor_version: CUR_MINOR_VERSION,
                            socket_id: new_socket_id,
                        },
                    )
                    .expect("memory limit error"),
                    new_socket_id,
                );
            }
        }
    }

    pub async fn open(&self, route: R) -> Result<Channel<R>, ()> {
        let mut handshake_no: u128 = rand::random();
        handshake_no >>= 8;
        debug_assert_eq!(SOCKET_ID_INIT_MESSAGE, 0);

        let reply_no = handshake_no + HANDSHAKE_NO_SOCKET_ID_INC;

        let (payload, reserved_socket_id) = self.create_payload();

        let (cur_message, state) = InitState::initialize(
            &handshake_no.to_be_bytes(),
            self.secret_bundle.clone(),
            None,
            payload,
            (),
        );

        let pre_entry = self.hanshake_table.insert(
            reply_no,
            HandshakeEntry::InitiatorSent { reserved_socket_id, desegmenter: None, cur_message, state },
        );
        debug_assert!(pre_entry.is_none());

        todo!()
    }

    pub fn drive(&self, packet: &mut [u8], route: R) {}

    fn handshake_complete(&self, new_socket_id: SocketId, complete: HandshakeComplete<Crypto>) -> Option<Channel<R>> {
        None
    }

    fn recv_init_message(&self, handshake_no: u128, message: &mut [u8]) -> Option<Channel<R>> {
        trace!(handshake_no, "recv initial message");
        // If `reserved_socket_id` is `Some` then it is a key in `socket_table`
        // and needs to eventually be removed from it.
        let mut reserved_socket_id = None;
        let create_payload = || {
            let (p, s) = self.create_payload();
            reserved_socket_id = Some(s);
            p
        };

        match ReplyState::process_initialize(
            &handshake_no.to_be_bytes(),
            message,
            &self.secret_bundle,
            None,
            create_payload,
            secs_since_unix_epoch(),
            (),
        ) {
            Ok(InitOk::Complete(complete)) => {
                let reserved_socket_id = reserved_socket_id.expect("reserved socket id was absent");

                return self.handshake_complete(reserved_socket_id, complete);
            }
            Ok(InitOk::Incomplete(cur_message, state)) => {
                let reserved_socket_id = reserved_socket_id.expect("reserved socket id was absent");

                let reply_no = handshake_no + HANDSHAKE_NO_SOCKET_ID_INC;
                let confirm_no = reply_no + HANDSHAKE_NO_SOCKET_ID_INC;

                let responder_sent =
                    HandshakeEntry::ResponderSent { desegmenter: None, reserved_socket_id, cur_message, state };

                match self.hanshake_table.entry(confirm_no) {
                    Entry::Occupied(_) => {
                        // Cancel this handshake due to lack of unique `handshake_no`. This should
                        // never happen with a well behaved peer since the `handshake_no` is
                        // supposed to be randomized.
                        let _e = self.socket_table.remove(&reserved_socket_id);
                        debug_assert!(matches!(_e, Some((_, None))));
                        warn!(handshake_no, "handshake failed due to handshake no collision")
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(responder_sent);
                    }
                }
                // TODO: send reply message and queue it to be resent.
            }
            Err(error) => {
                if let Some(socket_id) = reserved_socket_id {
                    let _e = self.socket_table.remove(&socket_id);
                    debug_assert!(matches!(_e, Some((_, None))));
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
                        HandshakeEntry::ResponderRecv(desegmenter)
                        | HandshakeEntry::InitiatorSent { desegmenter: Some(desegmenter), .. }
                        | HandshakeEntry::ResponderSent { desegmenter: Some(desegmenter), .. } => {
                            match desegmenter.recv_mut(packet, idx, true, true, true) {
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
                        HandshakeEntry::InitiatorSent { desegmenter, .. }
                        | HandshakeEntry::ResponderSent { desegmenter, .. } => {
                            debug_assert!(desegmenter.is_none());

                            match Desegmenter::try_new(packet, idx, true, true, true, ()) {
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
                                NewResult::MissingLen | NewResult::AllocFailure => unreachable!(),
                            }
                        }
                    };

                    match entry.insert(HandshakeEntry::CoolDown) {
                        HandshakeEntry::CoolDown => unreachable!(),
                        HandshakeEntry::ResponderRecv(_) => {
                            return self.recv_init_message(handshake_no, message);
                        }
                        HandshakeEntry::InitiatorSent { reserved_socket_id, state, .. } => {
                            match state.process_reply(message, secs_since_unix_epoch(), (), ()) {
                                Ok(complete) => {
                                    return self.handshake_complete(reserved_socket_id, complete);
                                }
                                Err(error) => {
                                    warn!(handshake_no, error = ?error, "could not authenticate handshake reply");
                                    let _e = self.socket_table.remove(&reserved_socket_id);
                                    debug_assert!(matches!(_e, Some((_, None))));
                                }
                            }
                        }
                        HandshakeEntry::ResponderSent { reserved_socket_id, state, .. } => {
                            match state.process_confirm(message, secs_since_unix_epoch(), ()) {
                                Ok(complete) => {
                                    return self.handshake_complete(reserved_socket_id, complete);
                                }
                                Err(error) => {
                                    warn!(handshake_no, error = ?error, "could not authenticate handshake confirmation");
                                    let _e = self.socket_table.remove(&reserved_socket_id);
                                    debug_assert!(matches!(_e, Some((_, None))));
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

                    match Desegmenter::try_new(packet, idx, true, true, true, ()) {
                        NewResult::Segmented(desegmenter) => {
                            entry.insert(HandshakeEntry::ResponderRecv(desegmenter));
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
                        NewResult::MissingLen | NewResult::AllocFailure => unreachable!(),
                    }
                }
            }
        } else {
            let Some(entry) = self.socket_table.get(&socket_id) else {
                info!(socket_id, "received unrecognized socket id");
                return None;
            };
            let Some(socket) = entry.value() else {
                info!(socket_id, "received unrecognized socket id");
                return None;
            };
            let Some(session) = socket.session.upgrade().map(Session) else {
                info!(socket_id, "received unrecognized socket id");
                return None;
            };

            let j = *idx + 4;
            if j > packet.len() {
                warn!(socket_id, "received invalid counter");
                return None;
            }
            let counter = u32::from_be_bytes(packet[*idx..j].try_into().unwrap());
            *idx = j;

            // TODO: anti-replay
            if !socket.decryptor.decrypt_in_place(counter, &mut packet[*idx..]) {
                info!(socket_id, "received corrupted or inauthentic packet");
                return None;
            }

            session.recv(packet, idx, route);
        }
        todo!()
    }
}
