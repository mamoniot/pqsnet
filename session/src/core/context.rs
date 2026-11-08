
use std::{sync::Weak, task::{Poll, Waker}};

use arc_swap::ArcSwapAny;
use cbor4ii::serde::to_vec;
use dashmap::{DashMap, Entry};
use psqnet_transport::{
    HandshakeComplete, initiator::InitState, key_bundle::OfflineHash, responder::{InitOk, ReplyState},
};
use rand::RngExt;
use tracing::*;

use crate::core::{crypto::{SecretBundle, aes::HotAesGcmDecryptor, random::OpenSSLRand, transport::Crypto}, desegmenter::*, error::OpenError, protocol::*, runtime::{Runtime, Work}, session::{SessionInner, UnacceptedReceiver, UnacceptedSender}, varint::*, work::WorkInner};

pub(crate) struct  InitiatorSent {
    reserved_socket_id: SocketId,
    desegmenter: Option<Desegmenter<Box<[u8]>>>,
    segments: Segmenter,
    state: InitState<Crypto, SecretBundle>,
}

pub(crate) enum HandshakeEntry {
    CoolDown,
    ResponderRecv(Desegmenter<Box<[u8]>>),
    InitiatorSent(InitiatorSent, Waker),
    ResponderSent {
        reserved_socket_id: SocketId,
        desegmenter: Option<Desegmenter<Box<[u8]>>>,
        cur_message: Vec<u8>,
        state: ReplyState<Crypto>
    },
    Open(HandshakeComplete<'static, Crypto>, HandshakePayload),
}

pub(crate) struct Socket<R: Runtime> {
    pub(crate) decryptor: HotAesGcmDecryptor,
    pub(crate) session: Weak<SessionInner<R>>
}

pub struct Context<R: Runtime> {
    runtime: R,
    secret_key_bundle: ArcSwapAny<SecretBundle>,
    socket_table: DashMap<SocketId, Option<Socket<R>>>,
    hanshake_table: DashMap<u128, HandshakeEntry>,
}

impl<R: Runtime> Context<R> {
    pub fn new(runtime: R, secret_key_bundle: SecretBundle) -> Self {
        Self {
            runtime,
            secret_key_bundle: secret_key_bundle.into(),
            socket_table: DashMap::default(),
            hanshake_table: DashMap::default(),
        }
    }

    pub fn current_secret_key(&self) -> SecretBundle {
        self.secret_key_bundle.load_full()
    }

    pub fn replace_secret_key(&self, secret_key_bundle: SecretBundle) -> SecretBundle {
        self.secret_key_bundle.swap(secret_key_bundle)
    }

    pub async fn open(&self, remote_offline_hash: Option<OfflineHash>, route: R::Route) -> Result<UnacceptedSender<R>, OpenError> {
        let handshake_id = OpenSSLRand.random::<u128>() >> 8;
        debug_assert_eq!(SOCKET_ID_INIT_MESSAGE, 0);

        let reply_no = handshake_id + HANDSHAKE_NO_SOCKET_ID_INC;

        let (payload, reserved_socket_id) = self.create_payload();

        let (message, state) = InitState::initialize(
            &handshake_id.to_be_bytes(),
            self.current_secret_key(),
            None,
            self.runtime.secs_since_unix_epoch(),
            payload,
            (),
        )
        .expect("infallible memory allocation failed");

        let mtu = self.runtime.get_conservative_mtu(&route);
        assert!(mtu >= MIN_MTU);

        struct HandshakeFuture<'a, R: Runtime> {
            ctx: &'a Context<R>,
            reply_no: u128,
            entry: Option<InitiatorSent>,
        }

        impl<'a, R: Runtime> Future for HandshakeFuture<'a, R> {
            type Output = Result<UnacceptedSender<R>, OpenError>;

            fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
                if let Some(entry) = self.entry.take() {
                    self.ctx.hanshake_table.insert(
                        self.reply_no,
                        HandshakeEntry::InitiatorSent(entry, cx.waker().clone()),
                    );

                    self.ctx.runtime.spawn(Work(WorkInner::Handshake(self.reply_no)));
                    Poll::Pending
                } else {
                    let mut ret = Poll::Pending;
                    self.ctx.hanshake_table.alter(&self.reply_no, |_, entry| {
                        match entry {
                            HandshakeEntry::Open(handshake_complete, handshake_payload) => {
                                todo!();
                                ret = Poll::Ready(Ok(UnacceptedSender {

                                }));
                                HandshakeEntry::CoolDown
                            }
                            _ => entry
                        }
                    });
                    ret
                }
            }
        }

        HandshakeFuture {
            ctx: self,
            reply_no,
            entry: Some(InitiatorSent { reserved_socket_id, desegmenter: None, segments: Segmenter::new_handshake(message, handshake_id, mtu), state })
        }.await
    }

    pub fn recv(&self, packet: &mut [u8], route: R::Route) -> Option<UnacceptedReceiver<R>> {
        let mut packet_idx = 0;
        let idx = &mut packet_idx;

        let Some(socket_id) = varu32_try_read(packet, idx) else {
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

            let handshake_id = u128::from_be_bytes(packet[..HANDSHAKE_NO_LEN].try_into().unwrap());
            *idx = HANDSHAKE_NO_LEN;
            debug_assert_eq!(socket_id, (handshake_id >> (u128::BITS - 8)) as SocketId);

            match self.hanshake_table.entry(handshake_id) {
                Entry::Vacant(entry) => {
                    if socket_id != SOCKET_ID_INIT_MESSAGE {
                        debug!(
                            handshake_id,
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
                            return self.recv_init_message(handshake_id, &mut packet[message_range]);
                        }
                        NewResult::Invalid => {
                            warn!(
                                handshake_id,
                                "received invalid segmentation data on an unused handshake no"
                            );
                            return None;
                        }
                        NewResult::MissingLen | NewResult::AllocFailure => todo!(),
                    }
                }
                Entry::Occupied(mut entry) => {
                    let mut _message_mem = None;
                    let message = match entry.get_mut() {
                        // Entries are set to cooldown so resent messages do not trigger a handshake
                        // twice.
                        HandshakeEntry::CoolDown => {
                            debug!(handshake_id, "ignored handshake fragment while on cooldown");
                            return None;
                        }
                        //
                        HandshakeEntry::ResponderRecv(desegmenter)
                        | HandshakeEntry::InitiatorSent { desegmenter: Some(desegmenter), .. }
                        | HandshakeEntry::ResponderSent { desegmenter: Some(desegmenter), .. } => {
                            match desegmenter.recv_mut(packet, idx, true, true, true) {
                                Ok(m) => _message_mem.insert(m),
                                Err(SegError::Segmented) => {
                                    trace!(handshake_id, "received handshake fragment");
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
                                    trace!(handshake_id, "received handshake fragment");
                                    *desegmenter = Some(d);
                                    return None;
                                }
                                NewResult::SingleSeg(message_range) => &mut packet[message_range],
                                NewResult::Invalid => {
                                    warn!(handshake_id, "received invalid segmentation data");
                                    return None;
                                }
                                NewResult::MissingLen | NewResult::AllocFailure => unreachable!(),
                            }
                        }
                    };

                    match entry.insert(HandshakeEntry::CoolDown) {
                        HandshakeEntry::CoolDown => unreachable!(),
                        HandshakeEntry::ResponderRecv(_) => {
                            return self.recv_init_message(handshake_id, message);
                        }
                        HandshakeEntry::InitiatorSent { reserved_socket_id, state, .. } => {
                            match state.process_reply(message, self.runtime.secs_since_unix_epoch(), (), ()) {
                                Ok(complete) => {
                                    return self.handshake_complete(reserved_socket_id, complete);
                                }
                                Err(error) => {
                                    warn!(handshake_id, error = ?error, "could not authenticate handshake reply");
                                    let _e = self.socket_table.remove(&reserved_socket_id);
                                    debug_assert!(matches!(_e, Some((_, None))));
                                }
                            }
                        }
                        HandshakeEntry::ResponderSent { reserved_socket_id, state, .. } => {
                            match state.process_confirm(message, self.runtime.secs_since_unix_epoch(), ()) {
                                Ok(complete) => {
                                    return self.handshake_complete(reserved_socket_id, complete);
                                }
                                Err(error) => {
                                    warn!(handshake_id, error = ?error, "could not authenticate handshake confirmation");
                                    let _e = self.socket_table.remove(&reserved_socket_id);
                                    debug_assert!(matches!(_e, Some((_, None))));
                                }
                            }
                        }
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

    pub fn submit_work(&self, work: Work) {

    }

    pub fn close_all(&self) {

    }

    fn create_payload(&self) -> (Vec<u8>, SocketId) {
        let mut i = 0;
        loop {
            i += 1;
            let new_socket_id = if i <= 2 {
                rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U16_MAX as SocketId)
            } else {
                rand::random_range(SOCKET_ID_RESERVED_MAX + 1..VARINT_U32_MAX)
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

    fn handshake_complete(&self, new_socket_id: SocketId, complete: HandshakeComplete<Crypto>) -> Option<UnacceptedReceiver<R>> {
        let decryptor = HotAesGcmDecryptor::new(complete.keys.recv_key());

        self.socket_table.insert(new_socket_id, Some(Socket {
            decryptor,
        }));
        todo!()
    }

    fn recv_init_message(&self, handshake_id: u128, message: &mut [u8]) -> Option<UnacceptedReceiver<R>> {
        trace!(handshake_id, "recv initial message");
        // If `reserved_socket_id` is `Some` then it is a key in `socket_table`
        // and needs to eventually be removed from it.
        let mut reserved_socket_id = None;
        let create_payload = || {
            let (p, s) = self.create_payload();
            reserved_socket_id = Some(s);
            p
        };

        match ReplyState::process_initialize(
            &handshake_id.to_be_bytes(),
            message,
            &self.current_secret_key(),
            None,
            self.runtime.secs_since_unix_epoch(),
            (),
            create_payload,
        ) {
            Ok(InitOk::Complete(complete)) => {
                let reserved_socket_id = reserved_socket_id.expect("reserved socket id was absent");

                self.handshake_complete(reserved_socket_id, complete)
            }
            Ok(InitOk::Incomplete(cur_message, state)) => {
                let reserved_socket_id = reserved_socket_id.expect("reserved socket id was absent");

                let reply_id = handshake_id + HANDSHAKE_NO_SOCKET_ID_INC;
                let confirm_id = reply_id + HANDSHAKE_NO_SOCKET_ID_INC;

                let responder_sent =
                    HandshakeEntry::ResponderSent { desegmenter: None, reserved_socket_id, cur_message, state };

                match self.hanshake_table.entry(confirm_id) {
                    Entry::Occupied(_) => {
                        // Cancel this handshake due to lack of unique `handshake_id`. This should
                        // never happen with a well behaved peer since the `handshake_id` is
                        // supposed to be randomized.
                        let _e = self.socket_table.remove(&reserved_socket_id);
                        debug_assert!(matches!(_e, Some((_, None))));
                        warn!(handshake_id, "handshake failed due to handshake id collision");
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(responder_sent);

                        self.submit_work(Work(WorkInner::Handshake(confirm_id)));
                    }
                }
                None
            }
            Err(error) => {
                if let Some(socket_id) = reserved_socket_id {
                    let _e = self.socket_table.remove(&socket_id);
                    debug_assert!(matches!(_e, Some((_, None))));
                }
                todo!();
            }
        }
    }
}
