use crate::core::work::WorkInner;


pub type TimestampUs = u64;

pub type TimestampUnix = u64;

pub struct Work(WorkInner);

pub enum RouteError {
    RouteClosed,
    RouteBusy,
    RouteFull,
    RouteMtuExceeded,
    Other,
}

pub trait Runtime {
    type Route: PartialEq;

    type Scheduler;

    fn send(&self, route: &Self::Route, data: &[u8]) -> Result<(), RouteError>;

    fn spawn(&self, work: Work);

    fn now_microsec(&self) -> TimestampUs;

    fn secs_since_unix_epoch(&self) -> Option<TimestampUnix>;

    fn schedule(&self, ts_us: TimestampUs, work: Work) -> Self::Scheduler;

    fn reschedule(&self, scheduler: &Self::Scheduler, ts_us: TimestampUs);

    fn unschedule(&self, scheduler: Self::Scheduler);
}
