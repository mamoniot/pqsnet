use std::sync::{Mutex, atomic::AtomicUsize};

use crate::session::{Route, Session};

const ACK_AGREGATOR_LEN: usize = 256;

pub struct AckAgregator {
    read_i: AtomicUsize,
    write_i: AtomicUsize,
    ring: [u32; ACK_AGREGATOR_LEN],
    backup: Mutex<Vec<u32>>,
}

impl<R: Route> Session<R> {
    pub(crate) fn reset(&self, ack_no: u32) {
        todo!()
    }

    pub(crate) fn insert_ack(&self, ack_no: u32) {
        todo!()
    }
}
