use std::sync::{Arc, atomic::{AtomicU64, AtomicUsize}};

use arc_swap::ArcSwapAny;
use arrayvec::ArrayVec;

use crate::core::{context::Context, crypto::RemoteBundle, runtime::Runtime};


pub struct SessionInner<R: Runtime> {
    pub(crate) ctx: Arc<Context<R>>,
    pub(crate) remote_key_bundle: ArcSwapAny<RemoteBundle>,
    pub(crate) routes: ArrayVec<R::Route, 8>,
    /// We explicitly track the total number of bytes we are receiving. The number of docs being
    /// received is tracked implicitly by the length of `recv_table`.
    ///
    pub(crate) recv_bytes_total: AtomicUsize,
    /// This number can only increase. To "decrease" the recv bytes max, a doc is finished with a
    /// fin-drain, and `recv_bytes_total` is not decreased by the full length of the doc.
    pub(crate) recv_bytes_max: AtomicUsize,
    /// It is the sender's responsibility to correctly memory manage the receiver's `recv_table`.
    /// When a new document comes in, if the slot its doc no maps to is occupied by a doc with a
    /// lower doc no, the receiver will only replace it with the incoming doc if it is in a `Fin` or
    /// `FinAck` state. The previous doc will be finished and closed if it was not already, but new
    /// fin or close control packets will not be sent to the sender.
    pub(crate) recv_table: Vec<RecvDocEntry>,

    pub(crate) send_bytes_total: AtomicU64,
    /// This is set to 0 if this session was abandoned.
    pub(crate) send_bytes_max: AtomicU64,
    pub(crate) send_total: AtomicUsize,
    pub(crate) send_doc_no: AtomicU64,
    pub(crate) send_table: Vec<SendDocEntry>,
}

impl<R: Runtime> SessionInner<R> {
    pub fn new(route: R::Route, mtu: usize) -> Self {
        todo!()
    }
}
