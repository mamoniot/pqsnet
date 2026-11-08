use crate::core::{crypto::RemoteBundle, runtime::Runtime};


pub trait Session<R: Runtime> {
    fn remote_key_bundle(&self) -> RemoteBundle;

    fn increase_data_limit(&self, todo: usize);

    fn add_route(&self, route: R::Route);

    fn end_session(&self);
}
