pub enum RouteError {
    RouteClosed,
    RouteBusy,
    RouteMtuExceeded,
    Other,
}

/// TODO: change the name of this.
pub trait Route {
    fn send(&self, packet: &[u8]) -> Result<(), RouteError>;
}
