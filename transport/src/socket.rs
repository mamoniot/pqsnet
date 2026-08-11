use std::sync::{
    Arc, Mutex, RwLock, Weak,
    atomic::{AtomicU64, Ordering},
};

use rand_core::Rng;

use crate::{
    antireplay::Antireplay,
    context::{Context, InnerContext},
    desegmentation::{Desegmenter, Segmenter},
    initiator::InitializeState,
    responder::ReplyState,
    session_layer::SessionLayer,
};

pub(crate) struct SocketEntry<S: SessionLayer> {
    socket: Weak<Socket<S>>,
    socket_uid: usize,
}

pub struct Socket<S: SessionLayer> {
    pub(crate) state: RwLock<HandshakeState<S>>,
    /* START OF DROP RESOURCES */
    ctx: Weak<InnerContext<S>>,
    pub(crate) recv_socket_id: u32,
}

#[derive(Default)]
pub(crate) enum HandshakeState<S: SessionLayer> {
    #[default]
    Reserved,
    SendingInitialize {
        state: InitializeState<S>,
        segmenter: Segmenter,
        desegmenter: Mutex<Desegmenter>,
    },
    SendingReply {
        state: ReplyState<S>,
        segmenter: Segmenter,
        desegmenter: Mutex<Desegmenter>,
    },
    SendingResume {
        segmenter: Segmenter,
    },
    SendingConfirm {
        segmenter: Segmenter,
    },
    Active(ActiveSocket<S>),
}

pub struct ActiveSocket<S: SessionLayer> {
    local_bundle_uid: u128,
    send_socket_id: u32,
    cipher: S::HotPathDuplexCipherImpl,
    antireplay: Antireplay<128>,
    counter: AtomicU64,
}

impl<S: SessionLayer> Drop for Socket<S> {
    // When a socket is dropped its corresponding entries in the socket table need to be removed.
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.upgrade() {
            ctx.socket_table.remove(&self.recv_socket_id);
        }
    }
}

impl<S: SessionLayer> Context<S> {
    /// Reserves a socket in the socket table for use.
    /// Reserved sockets cannot receive packets and cannot be reserved twice simultaneously.
    /// If this socket is dropped, its socket id is unreserved, preventing a memory leak.
    /// This guard does not hold any locks and cannot cause a deadlock.
    pub(crate) fn reserve_socket(&self, sl: &mut S) -> Arc<Socket<S>> {
        let mut socket = Box::new(Socket {
            state: Default::default(),
            ctx: Arc::downgrade(&self.0),
            recv_socket_id: 0,
        });
        loop {
            // Rejection sample a unique socket id.
            let id = sl.rng().next_u32();
            if id != 0 {
                if let dashmap::Entry::Vacant(entry) = self.socket_table.entry(id) {
                    socket.recv_socket_id = id;
                    let socket = socket.into();
                    entry.insert(SocketEntry {
                        socket: Arc::downgrade(&socket),
                        socket_uid: self.socket_count.fetch_add(1, Ordering::Relaxed),
                    });
                    return socket;
                }
            }
        }
    }
    // pub(crate) fn new(cipher: S::HotPathDuplexCipherImpl, send_socket_id: u32, recv_socket_id: u32) -> Arc<Self> {
    //     Arc::new(Socket { ctx: todo!(), lock: todo!() })
    // }
}
