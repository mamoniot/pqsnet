use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use rand_core::*;

use crate::{
    crypto::prelude::*,
    desegmentation::{self, Desegmenter, Mtu, Segmenter},
    error::Error,
    init_table::{Entry, InitTable},
    initiator::InitializeState,
    protocol::{domain::to_data_nonce, *},
    responder::ReplyState,
    session_layer::{ResumptionToken, SessionLayer},
    socket::{Socket, SocketEntry},
};

pub struct Context<S: SessionLayer>(pub Arc<InnerContext<S>>);

impl<S: SessionLayer> std::ops::Deref for Context<S> {
    type Target = Arc<InnerContext<S>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct InnerContext<S: SessionLayer> {
    pub(crate) socket_count: AtomicUsize,
    init_table: InitTable<Desegmenter>,
    /// It must be the case that no handshake state can be modified in `socket_table` while its
    /// corresponding desegmenter is in the `is_complete` state.
    /// A desegmenter only enters the `is_complete` state in the brief window after a message has
    /// been fully desegmented, in which case the desegmenting thread must have mutually exclusive
    /// access to the corresponding handshake state.
    pub(crate) socket_table: DashMap<u32, SocketEntry<S>>,
}

pub(crate) struct ResumptionState<S: SessionLayer> {
    pub(crate) socket: Weak<Socket<S>>,
    pub(crate) cipher_idx: bool,
}

pub enum RecvOk<S: SessionLayer> {
    /// The packet received was dropped for being a duplicate of a previous packet.
    Duplicate,
    Incomplete,
    SendReply(Arc<Socket<S>>, Segmenter),
    SendResume(Arc<Socket<S>>, Segmenter),
    SendConfirm(Segmenter),
    Resume,
    Confirm,
    Data,
    NewSocket(Socket<S>),
}

impl<S: SessionLayer> Context<S> {
    pub fn recv<F: FnMut(&mut [u8])>(&self, sl: S, packet: &mut [u8], recv_mtu: Mtu) -> Result<RecvOk<S>, Error> {
        use shared::*;

        let recv_socket_id = u32::from_be_bytes(packet[SOCKET_ID_START..SOCKET_ID_END].try_into().unwrap());

        if recv_socket_id == initialize::NULL_KEY_ID {
            use initialize::*;
            /* START OF INITIALIZE DESEGMENTATION */

            let initialize_id = u64::from_be_bytes(packet[INITIALIZE_UID_RANGE].try_into().unwrap());
            // The following line locks `init_table`.
            // That lock is dropped before `process_initialize` is called.
            let entry = self.init_table.entry(initialize_id);
            match entry {
                Entry::Occupied(mut occupied_entry) => match occupied_entry.get_mut().recv(packet, HEADER_LEN) {
                    desegmentation::RecvResult::Invalid => Err(Error::Invalid),
                    desegmentation::RecvResult::Duplicate => Ok(RecvOk::Duplicate),
                    desegmentation::RecvResult::Incomplete => Ok(RecvOk::Incomplete),
                    desegmentation::RecvResult::NotSegmented => {
                        occupied_entry.remove();
                        self.process_initialize(sl, packet, recv_mtu)
                    }
                    desegmentation::RecvResult::Complete(mut message) => {
                        occupied_entry.remove();
                        self.process_initialize(sl, &mut message, recv_mtu)
                    }
                },
                Entry::Vacant(vacant_entry) => {
                    let mut desegmenter = Desegmenter::default();
                    match desegmenter.recv(packet, initialize::HEADER_LEN) {
                        desegmentation::RecvResult::Invalid => Err(Error::Invalid),
                        desegmentation::RecvResult::Duplicate => Ok(RecvOk::Duplicate),
                        desegmentation::RecvResult::Incomplete => {
                            vacant_entry.insert(desegmenter);
                            Ok(RecvOk::Incomplete)
                        }
                        desegmentation::RecvResult::NotSegmented => self.process_initialize(sl, packet, recv_mtu),
                        desegmentation::RecvResult::Complete(mut message) => {
                            self.process_initialize(sl, &mut message, recv_mtu)
                        }
                    }
                }
            }
        } else if let Some(socket_state) = self.socket_table.get(&recv_socket_id) {
            match socket_state.value() {
                SocketState::Reserved => todo!(),
                SocketState::Handshake { state: _, desegmenter } => {
                    let mut desegmenter = desegmenter.lock().unwrap();
                    match desegmenter.recv(packet, shared::SEGMENT_HEADER_END, todo!()) {
                        desegmentation::RecvResult::Invalid => Err(Error::Invalid),
                        desegmentation::RecvResult::Duplicate => Ok(RecvOk::Duplicate),
                        desegmentation::RecvResult::Incomplete => Ok(RecvOk::Incomplete),
                        desegmentation::RecvResult::NotSegmented => {
                            drop(desegmenter);
                            drop(socket_state);
                            self.process_handshake(sl, recv_socket_id, packet, recv_mtu)
                        }
                        desegmentation::RecvResult::Complete(mut message) => {
                            drop(desegmenter);
                            drop(socket_state);
                            self.process_handshake(sl, recv_socket_id, &mut message, recv_mtu)
                        }
                    }
                }
                SocketState::Active(socket) => {
                    let socket_clone = socket.clone();
                    drop(socket_state);
                    self.process_active(sl, socket_clone, packet)
                }
            }
        } else {
            todo!()
        }
    }

    fn process_handshake(
        &self,
        sl: S,
        socket_id: u32,
        message: &mut [u8],
        mtu: Mtu,
        generation: usize,
    ) -> Result<RecvOk<S>, Error> {
        let state = match self.socket_table.entry(socket_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let socket_state = entry.insert(SocketState::Reserved);
                match socket_state {
                    SocketState::Handshake { state, .. } => state,
                    _ => {
                        debug_assert!(false, "unreachable: race condition in socket table");
                        entry.insert(socket_state);
                        return Ok(RecvOk::Incomplete);
                    }
                }
            }
            dashmap::Entry::Vacant(_) => {
                debug_assert!(false, "unreachable: race condition in socket table");
                return Ok(RecvOk::Incomplete);
            }
        };

        let guard = SocketGuard { ctx: self, id: socket_id };

        match state {
            HandshakeState::SendingInitialize(state) => self.process_reply(sl, state, guard, message, mtu),
            HandshakeState::SendingReply(state) => self.process_confirm(sl, state, guard, message),
        }
    }

    fn process_active(&self, sl: S, socket: Arc<Socket<S>>, packet: &mut [u8]) -> Result<RecvOk<S>, Error> {
        use data::*;
        let counter = u32::from_be_bytes(packet[GCM_COUNTER_START..GCM_COUNTER_END].try_into().unwrap());

        if !socket.antireplay.check(counter) {
            return Ok(RecvOk::Duplicate);
        }

        let tag_start = packet.len() - TAG_LEN;
        let (data, tag) = packet[DATA_START..].split_at_mut(tag_start);
        let auth = socket
            .cipher
            .decrypt_in_place(to_data_nonce(counter), data, tag.try_into().unwrap());
        if !auth {
            return Err(Error::Inauthentic);
        }

        if !socket.antireplay.update(counter) {
            return Ok(RecvOk::Duplicate);
        }

        Ok(RecvOk::Data)
    }

    /*
        /// Reserves a socket id in the socket table for use in the form of a guard.
        /// Reserved socket ids cannot receive packets and cannot be reserved twice simultaneously.
        /// If this guard is dropped, the socket id is un-reserved, preventing a memory leak.
        /// This guard does not hold any locks and cannot cause a deadlock.
        pub(crate) fn reserve_socket<'a>(&'a self, sl: &mut S) -> SocketGuard<'a, S> {
            loop {
                // Rejection sample a unique socket id.
                let id = sl.rng().next_u32();
                if id != 0 {
                    if let dashmap::Entry::Vacant(entry) = self.socket_table.entry(id) {
                        entry.insert(SocketState::Reserved);
                        return SocketGuard { ctx: self, id };
                    }
                }
            }
        }
    */

    pub fn send() {}
}

impl<S: SessionLayer> Socket<S> {
    // TODO: Improve `packet` field.
    pub fn send(&self, packet: &mut [u8]) -> bool {
        use {data::*, shared::*};

        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        // This packet is encrypted with nonce value `counter`,
        // returned by atomically incrementing `self.counter` by 1.
        // Since `self.counter` is initialized to 1, the only way for `counter` to not be a unique
        // integer is for `self.counter` to overflow from u64::MAX to 0.
        // When `counter > MAXIMUM_AES_GCM_COUNTER`, `self.counter` is atomically decremented and
        // the counter is rejected.
        // Therefore, for `self.counter` to overflow, `2^64 - MAXIMUM_AES_GCM_COUNTER` threads must
        // execute the above increment but still be waiting to execute the below decrement.
        // That is absurd and is not physically possible.
        if counter > MAXIMUM_AES_GCM_COUNTER as u64 {
            self.counter.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        let counter = counter as u32;

        packet[SOCKET_ID_START..SOCKET_ID_END].copy_from_slice(&self.send_socket_id.to_be_bytes());
        packet[GCM_COUNTER_START..GCM_COUNTER_END].copy_from_slice(&counter.to_be_bytes());

        let tag_start = packet.len() - TAG_LEN;
        let (data, pad) = packet[DATA_START..].split_at_mut(tag_start);
        let tag = self.cipher.encrypt_in_place(to_data_nonce(counter), data);
        pad.copy_from_slice(&tag);
        true
    }
}

/*
/// A guard for a reserved socket id.
/// Reserved socket ids cannot receive packets and cannot be reserved twice simultaneously.
/// If this is dropped, the socket id is un-reserved, preventing a memory leak.
/// This does not hold any locks and cannot cause a deadlock.
pub(crate) struct SocketGuard<'a, S: SessionLayer> {
    ctx: &'a Context<S>,
    id: u32,
}

impl<'a, S: SessionLayer> SocketGuard<'a, S> {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn insert(self, state: SocketState<S>) {
        self.ctx.socket_table.insert(self.id, state);

        std::mem::forget(self);
    }
}

impl<'a, S: SessionLayer> Drop for SocketGuard<'a, S> {
    fn drop(&mut self) {
        self.ctx.socket_table.remove(&self.id);
    }
}
*/
