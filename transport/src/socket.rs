use std::sync::{Arc, RwLock, Weak, atomic::AtomicU64};

use crate::{antireplay::Antireplay, context::Context, session_layer::{ResumptionKey, ResumptionToken, SessionLayer}};

pub struct Socket<S: SessionLayer> {
    pub(crate) lock: RwLock<[Option<SocketCipher<S>>; 2]>,
}

pub struct SocketCipher<S: SessionLayer> {
    send_socket_id: u32,
    cipher: S::HotPathDuplexCipherImpl,
    antireplay: Antireplay<128>,
    counter: AtomicU64,
    pub(crate) resumption_key: ResumptionKey,
    /* START OF DROP RESOURCES */
    ctx: Weak<Context<S>>,
    recv_socket_id: u32,
    resumption_token: ResumptionToken,
}

impl<S: SessionLayer> Drop for SocketCipher<S> {
    // When a socket is dropped its corresponding entries in the socket table need to be removed.
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.upgrade() {
            ctx.socket_table.remove(&self.recv_socket_id);
            ctx.resumption_table.remove(&self.resumption_token);
        }
    }
}

impl<S: SessionLayer> Socket<S> {
    pub(crate) fn new(cipher: S::HotPathDuplexCipherImpl, send_socket_id: u32, recv_socket_id: u32) -> Arc<Self> {
        Arc::new(Socket {
            ctx: todo!(),
            lock: todo!(),
        })
    }

    pub(crate) fn resumption_key(&self, cipher_idx: bool) -> Option<ResumptionKey> {
        self.lock.read().unwrap()[cipher_idx as usize].as_ref().map(|s| s.resumption_key.clone())
    }
}
