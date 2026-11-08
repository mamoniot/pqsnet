
pub trait Allocator {
    type Mem: Sized + DerefMut<Target = [u8]>;

    fn malloc(&self, len: usize, header: &[u8]) -> Option<Self::Mem>;
}

pub trait PacketHandler {
    fn recv(&self, data: &[u8]);
}

pub struct Work();

pub type TimestampUs = u64;

pub type TimestampUnix = u64;

pub trait Runtime {
    type Route: PartialEq;

    type Timer;

    fn send(&self, route: &Self::Route, data: &[u8]) -> Result<(), RouteError>;

    fn spawn(&self, work: Work);

    fn now_microsec(&self) -> TimestampUs;

    fn secs_since_unix_epoch(&self) -> Option<TimestampUnix>;

    fn schedule(&self, ts_us: TimestampUs, work: Work) -> Self::Timer;

    fn reschedule(&self, timer: &Self::Timer, ts_us: TimestampUs);

    fn unschedule(&self, timer: Self::Timer);
}

pub type SecretBundle = Arc<transport::SecretBundle<C>>;

pub type RemoteBundle = Arc<transport::AuthenticBundle<C>>;

pub struct Context<R: Runtime> {
    pub runtime: R,
}

pub struct UnopenedSession<R: Runtime> {}

pub struct UnacceptedSession<R: Runtime> {}

pub struct Session<R: Runtime> {}

pub struct Sender<R: Runtime> {}

pub struct Receiver<R: Runtime> {}

pub struct UnboundSender<R: Runtime> {}

pub struct UnboundReceiver<R: Runtime, A: Allocator> {}

pub struct UnreliableSender<R: Runtime> {}

pub struct UnreliableReceiver<R: Runtime, H: PacketHandler> {}

impl Context<R: Runtime> {
    pub fn new(runtime: R, secret_key_bundle: SecretBundle, conn: Connection) -> Self {}

    pub fn current_secret_key(&self) -> SecretBundle {}

    pub fn replace_secret_key(&self, secret_key_bundle: SecretBundle) {}

    pub async fn open(&self, remote_offline_hash: Option<OfflineHash>, route: R::Route) -> Result<UnacceptedSender<R>, Error> {}

    pub fn recv(&self, packet: &mut [u8], route: R::Route) -> Option<UnacceptedReceiver<R>> {}

    pub fn submit_work(&self, work: Work) {}

    pub fn close_all(&self) {}
}

impl UnacceptedSender<R: Runtime> {
    pub fn remote_key_bundle(&self) -> RemoteBundle {}

    pub fn authenticate(self) -> Sender<R> {}
}

impl UnacceptedReceiver<R: Runtime> {
    pub fn remote_key_bundle(&self) -> RemoteBundle {}

    pub fn authenticate(self) -> Receiver<R> {}
}

pub trait Session<R: Runtime> {
    fn remote_key_bundle(&self) -> RemoteBundle;

    fn increase_data_limit(&self, todo: usize);

    fn add_route(&self, route: R::Route);

    fn end_session(&self);
}

impl Sender<R: Runtime> {
    pub fn no(&self) -> u64 {}

    pub async fn send(&self, doc: Bytes) -> Result<(), (Error, Bytes)> {}

    pub fn try_send(&self, doc: Bytes) -> Result<(), (Error, Bytes)> {}

    pub async fn open_sender(&self, doc: Bytes) -> Result<Sender, (Error, Bytes)> {}

    pub fn try_open_sender(&self, doc: Bytes) -> Result<Sender, (Error, Bytes)> {}

    pub async fn open_receiver(&self, doc: Bytes) -> Result<Receiver, (Error, Bytes)> {}

    pub fn try_open_receiver(&self, doc: Bytes) -> Result<Receiver, (Error, Bytes)> {}

    pub async fn open_unbounded<A: Allocator>(&self, doc: Bytes, allocator: A) -> Result<UnboundReceiver<A>, (Error, Bytes, A)> {}

    pub fn try_open_unbounded<A: Allocator>(&self, doc: Bytes, allocator: A) -> Result<UnboundReceiver<A>, (Error, Bytes, A)> {}

    pub async fn open_unreliable<H: PacketHandler>(&self, doc: Bytes, handler: H) -> Result<UnreliableReceiver<H>, (Error, Bytes, H)> {}

    pub fn try_open_unreliable<H: PacketHandler>(&self, doc: Bytes, handler: H) -> Result<UnreliableReceiver<H>, (Error, Bytes, H)> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn is_full(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl<R: Runtime> Session<R> for Sender<R> {}

pub enum RecvData {
    Doc(Bytes),
    Receiver(Bytes, Receiver),
    Sender(Bytes, Sender),
    Unbound(Bytes, UnboundSender),
    Unreliable(Bytes, UnreliableSender),
}

impl<R: Runtime> Receiver<R> {
    pub fn no(&self) -> u64 {}

    pub async fn recv(&self) -> Result<RecvData, Error> {}

    pub fn try_recv(&self) -> Result<RecvData, Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn is_full(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl<R: Runtime> Receiver<R> for Sender<R> {}

impl<R: Runtime> UnboundSender<R> {
    pub fn no(&self) -> u64 {}

    pub async fn send(&self, doc: Bytes, header: Bytes) -> Result<(), (Error, Bytes, Bytes)> {}

    pub fn try_send(&self, doc: Bytes, header: Bytes) -> Result<(), (Error, Bytes, Bytes)> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl<R: Runtime> Receiver<R> for UnboundSender<R> {}

impl<R: Runtime, A: Allocator> UnboundReceiver<R, A> {
    pub fn no(&self) -> u64 {}

    pub async fn recv(&self) -> Result<A::Mem, Error> {}

    pub fn try_recv(&self) -> Result<A::Mem, Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn is_empty(&self) -> bool {}

    pub fn len(&self) -> usize {}
}

impl<R: Runtime> Receiver<R> for UnboundReceiver<R> {}

impl<R: Runtime> UnreliableSender<R> {
    pub fn no(&self) -> u64 {}

    pub fn send(&self, doc: &[u8]) -> Result<(), Error> {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}

    pub fn plpmtu(&self) -> usize {}
}

impl<R: Runtime> Receiver<R> for UnreliableSender<R> {}

impl<R: Runtime, H: PacketHandler> UnreliableReceiver<R, H> {
    pub fn no(&self) -> u64 {}

    pub fn close(&self) {}

    pub fn is_closed(&self) -> bool {}
}

impl<R: Runtime> Receiver<R> for UnreliableReceiver<R> {}
