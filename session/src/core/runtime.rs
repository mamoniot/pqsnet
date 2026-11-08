use crate::core::work::WorkInner;


pub type TimestampUs = u64;

pub type TimestampUnix = u64;

pub struct Work(pub(crate) WorkInner);

pub enum RouteError {
    RouteClosed,
    RouteBusy,
    RouteFull,
    RouteMtuExceeded,
    Other,
}

pub trait Runtime {
    type Route: PartialEq;

    type Timer;

    fn send(&self, route: &Self::Route, data: &[u8]) -> Result<(), RouteError>;

    fn get_conservative_mtu(&self, route: &Self::Route) -> usize;

    fn spawn(&self, work: Work);

    fn now_microsec(&self) -> TimestampUs;

    fn secs_since_unix_epoch(&self) -> Option<TimestampUnix>;

    fn schedule(&self, ts_us: TimestampUs, work: Work) -> Self::Timer;

    fn reschedule(&self, timer: &Self::Timer, ts_us: TimestampUs);

    fn unschedule(&self, timer: Self::Timer);
}
