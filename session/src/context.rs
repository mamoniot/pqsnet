use std::sync::Weak;

use dashmap::{DashMap, Entry};
use tracing::*;

use crate::{application_layer::Route, channel::Channel, crypto::aes::HotAesGcmDecryptor, desegmenter::Desegmenter, protocol::*, session::{Session, SessionInner}, varint::*};

pub struct CContext {

}

pub(crate) type SocketId = u64;

pub(crate) enum SocketState<R: Route> {
    Handshake(Desegmenter<HandshakeState>),
    Open(Socket<R>)
}

pub(crate) struct Socket<R: Route> {
    session: Weak<SessionInner<R>>,
    decryptor: HotAesGcmDecryptor,
}

pub struct Context<R: Route> {
    crypto_ctx: CContext,
    socket_table: DashMap<SocketId, Socket<R>>,
    init_table: DashMap<u64, Desegmenter<()>>,
}

impl<R: Route> Context<R> {
    pub async fn open_session(&self, packet: &mut [u8], route: R) -> Result<Channel<R>, ()> {
        todo!()
    }

    pub fn drive(&self, packet: &mut [u8], route: R) {

    }

    pub fn recv(&self, packet: &mut [u8], route: R) -> Option<Channel<R>> {
        let mut packet_idx = 0;
        let i = &mut packet_idx;

        let Some(socket_id) = varu64_try_read(packet, i) else {
            warn!("received invalid socket id");
            return None;
        };

        if socket_id <= SOCKET_ID_RESERVED_MAX {
            if socket_id != SOCKET_ID_NEW_SESSION_V1 {
                warn!("received unrecognized socket id '{socket_id}' in reserved range");
                return None;
            }

            if packet.len() < HANDSHAKE_HEADER_LEN {
                warn!("received invalid handshake id");
                return None;
            };
            let handshake_header = u64::from_be_bytes(packet[..HANDSHAKE_HEADER_LEN].try_into().unwrap());

            match self.init_table.entry(handshake_header) {
                Entry::Occupied(entry) => {
                    let Some((message, _)) = entry.get().recv_mut(packet, i) else {
                        trace!("received handshake message fragment");
                        return None;
                    };
                    match new_handshake(&handshake_header.to_be_bytes(), message) {
                        Ok((reply_message, handshake_state)) => {

                        }
                        Err(e) => {

                        }
                    }
                }
                Entry::Vacant(entry) => {
                    let desegmenter = Desegmenter::new(packet, i)?;
                    entry.insert(desegmenter);
                }
            }

            let Some(handshake_len) = varusize_try_read(packet, i) else {

            }
            // Receive a new socket.
            self.crypto_ctx.recv_init(&packet[*i..], HANDSHAKE_PAYLOAD_LEN_MAX, |header_buf: &mut [u8], payload_buf: &mut [u8]| {

            });

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
            let j = *i + 4;
            if j > packet.len() {
                warn!("received invalid counter");
                return None;
            }
            *i = j;

            let (crypto_header, ciphertext) = packet.split_at_mut(*i);
            todo!("antireplay");
            if !entry.decryptor.decrypt_in_place(crypto_header, ciphertext) {
                info!("received corrupted or inauthentic packet");
                return None;
            }

            session.recv(packet, i, route);
        }
        todo!()
    }
}
