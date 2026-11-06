
pub trait Allocator {
    type Mem: Sized + DerefMut<Target = [u8]>;

    fn malloc(&self, len: usize, header: &[u8]) -> Option<Self::Mem>;
}

pub trait CopyAllocator {
    fn copy(&self, data: &[u8]) -> Bytes;
}

pub trait Runtime {
    type Route: PartialEq;

    fn send(&self, route: &Self::Route, data: &[u8]) -> Result<(), Error>;

    fn accept_session(&self, remote_key_bundle: &Arc<AuthenticBundle>) -> bool;
}

pub struct Context<R: Runtime> {}

pub struct Session<R: Runtime> {}

pub struct Sender<R: Runtime> {}

pub struct Receiver<R: Runtime> {}

pub struct UnboundSender<R: Runtime> {}

pub struct UnboundReceiver<R: Runtime, A: Allocator> {}

pub struct UnreliableSender<R: Runtime> {}

pub struct UnreliableReceiver<R: Runtime, A: CopyAllocator> {}

impl Context<R: Runtime> {
    pub fn recv(&self, packet: &mut [u8], route: R::Route) -> Option<(Session, Receiver)> {}

    pub async fn open(&self, remote_offline_hash: OfflineHash, route: R::Route) -> Option<(Session, Sender)> {}

    pub async fn main(&self) {}

    pub fn close_all(&self) {}
}

impl Session<R: Runtime> {
    pub fn remote_key_bundle(&self) -> Arc<AuthenticBundle> {}

    pub fn increase_data_limit(&self, increment: usize) {}

    pub fn close(&self) {}
}

impl Sender<R: Runtime> {
    pub fn no(&self) -> u64 {}

    pub async fn send(&self, doc: Bytes) -> Result<(), (Error, Bytes)> {}

    pub async fn open_sender(&self, doc: Bytes) -> Result<Sender, (Error, Bytes)> {}

    pub async fn open_receiver(&self, doc: Bytes) -> Result<Receiver, (Error, Bytes)> {}

    pub async fn open_unbounded<A: Allocator>(&self, doc: Bytes, allocator: A) -> Result<UnboundReceiver<A>, (Error, Bytes, A)> {}

    pub async fn open_unreliable<A: CopyAllocator>(&self, doc: Bytes, allocator: A) -> Result<UnreliableReceiver<A>, (Error, Bytes, A)> {}

    pub async fn flush(&self) {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn is_full(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

pub enum RecvData {
    Doc(Bytes),
    Receiver(Bytes, Receiver),
    Sender(Bytes, Sender),
    Unbound(Bytes, UnboundSender),
    Unreliable(Bytes, UnreliableSender),
}

impl Receiver<R: Runtime> {
    pub fn no(&self) -> u64 {}

    pub async fn recv(&self) -> Result<RecvData, Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn is_full(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl UnboundSender {
    pub fn no(&self) -> u64 {}

    pub async fn send(&self, doc: Bytes, header: Bytes) -> Result<(), (Error, Bytes, Bytes)> {}

    pub async fn flush(&self) {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl<A: Allocator> UnboundReceiver<A> {
    pub fn no(&self) -> u64 {}

    pub async fn recv(&self) -> Result<NonNull<u8>, Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl UnreliableSender {
    pub fn no(&self) -> u64 {}

    pub fn send(&self, doc: &[u8]) -> Result<(), Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn plpmtu(&self) -> usize {}
}

impl<A: CopyAllocator> UnreliableReceiver<A> {
    pub fn no(&self) -> u64 {}

    pub async fn recv(&self) -> Result<Bytes, Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn len(&self) -> usize {}
}
