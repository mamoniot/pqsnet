use std::sync::Arc;

use crate::core::{crypto::RemoteBundle, protocol::DocNo, runtime::Runtime, session::SessionInner};

pub struct UnacceptedReceiver<R: Runtime> {
    session: Arc<SessionInner<R>>,
}

pub struct Receiver<R: Runtime> {
    doc_no: DocNo,
    session: Arc<SessionInner<R>>,
}


impl<R: Runtime> UnacceptedReceiver<R> {
    pub fn remote_key_bundle(&self) -> RemoteBundle {
        self.session.remote_key_bundle.load_full()
    }

    pub fn authenticate(self) -> Receiver<R> {
        todo!()
    }
}
