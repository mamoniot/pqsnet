use std::{io, sync::Arc};

use bytes::Buf;

use crate::session::{DocReceiver, DocSender, Route, Session};

pub struct ExceedsChannelLimit;

pub struct BatchChannelSender<'a, R: Route> {
    session: &'a DocSender<R>,
    data: Vec<u8>,
}

impl<'a, R: Route> BatchChannelSender<'a, R> {
    pub fn try_append(&mut self, src: &[u8]) -> usize {
        self.try_append_buf(src)
    }

    pub fn try_append_buf<B: Buf>(&mut self, src: B) -> usize {
        todo!()
    }

    pub fn try_append_send_channel(&mut self) -> Result<DocSender<R>, ExceedsChannelLimit> {
        todo!()
    }

    pub fn try_append_recv_channel(&mut self) -> Result<DocReceiver<R>, ExceedsChannelLimit> {
        todo!()
    }

    pub fn close(self) {
        todo!()
    }

    pub fn send(&mut self) {
        // Allow sending of all previously batched data and reset this `BatchSender` to batch a new set of data.
        todo!()
    }
}

impl<'a, R: Route> io::Write for BatchChannelSender<'a, R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.try_append(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send();
        Ok(())
    }
}

impl<'a, R: Route> Drop for BatchChannelSender<'a, R> {
    fn drop(&mut self) {
        todo!()
    }
}
