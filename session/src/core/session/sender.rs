use std::sync::Arc;

use crate::core::{crypto::RemoteBundle, protocol::DocNo, runtime::Runtime, session::{Session, SessionInner}};


pub struct UnacceptedSender<R: Runtime> {
    session: Arc<SessionInner<R>>,
}

pub struct Sender<R: Runtime> {
    doc_no: DocNo,
    session: Arc<SessionInner<R>>,
}

impl<R: Runtime> UnacceptedSender<R> {
    pub fn remote_key_bundle(&self) -> RemoteBundle {
        self.session.remote_key_bundle.load_full()
    }

    pub fn authenticate(self) -> Sender<R> {
        todo!()
    }
}
