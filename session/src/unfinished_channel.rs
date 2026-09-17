use std::{
    ops::{Deref, DerefMut},
    sync::atomic::Ordering,
};

use crate::{channel::Channel, protocol::*, session::Route};

pub struct UnfinishedChannel<R: Route> {
    channel: Channel<R>,
    doc_len: usize,
}

impl<R: Route> Deref for UnfinishedChannel<R> {
    type Target = Channel<R>;

    fn deref(&self) -> &Channel<R> {
        &self.channel
    }
}

impl<R: Route> DerefMut for UnfinishedChannel<R> {
    fn deref_mut(&mut self) -> &mut Channel<R> {
        &mut self.channel
    }
}

impl<R: Route> UnfinishedChannel<R> {
    pub(crate) fn new(doc_len: usize) -> Self {
        Self { channel: todo!() }
    }

    fn release_bytes(&self) {
        let session = &self.channel.session;
        session.recv_bytes_total.fetch_sub(self.doc_len, Ordering::SeqCst);
        session.schedule_send_control(VARIANT_CONTROL_FIN, self.channel.doc_no());
    }

    pub fn into_inner(self) -> Channel<R> {
        self.release_bytes();

        unsafe {
            // This read is valid, aligned and initialized. This semantically is a move.
            // There is no safe way to move out of a struct that implements drop unfortunately.
            let channel = core::ptr::read(&self.channel);
            core::mem::forget(self);
            channel
        }
    }
}

impl<R: Route> Drop for UnfinishedChannel<R> {
    fn drop(&mut self) {
        self.release_bytes();
    }
}
