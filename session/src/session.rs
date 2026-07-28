use std::{io, sync::Arc};

use bytes::{Buf, BufMut};

pub struct Session<R: Route> {
    _a: std::marker::PhantomData<R>,
}

pub struct SendChannel<R: Route> {
    _a: Arc<Session<R>>,

}

pub struct RecvChannel<R: Route> {
    _a: Arc<Session<R>>,
}

pub enum RecvOk<R: Route> {
    RecvLossy(Vec<u8>),
    NewRecvChannel(RecvChannel<R>),
    NewSendChannel(SendChannel<R>),
    Nop,
}

pub enum RouteError {
    RouteClosed,
    RouteBusy,
    RouteMtuExceeded,
    Other,
}
pub trait Route {
    fn send(&self, packet: &[u8]) -> Result<(), RouteError>;
}

impl<R: Route> Session<R> {
    pub fn new(routes: impl Iterator<Item = R>, send_limit: Space, recv_limit: Space) {
        todo!()
    }

    pub async fn new_send_channel(&self) -> SendChannel<R> {
        todo!()
    }

    pub async fn new_recv_channel(&self) -> RecvChannel<R> {
        todo!()
    }

    pub fn send_lossy(&self) {
        todo!()
    }

    pub fn add_route(&self, route: R) -> Result<(), Error> {
        todo!()
    }

    pub async fn recv(&self, packet: Vec<u8>, route: R) -> Result<RecvOk<R>, Error> {
        todo!()
    }
}

pub struct BatchSender<'a, R: Route> {
    channel: &'a SendChannel<R>,
}

pub enum Error {
    Closed,
    Abandoned,
}

pub enum TryError {
    NoData,
    Closed,
    Abandoned,
}

/// This error may be returned in the event that this session gets unacceptably close to the
/// channel limit.
pub struct ExceedsChannelLimit;

impl<'a, R: Route> BatchSender<'a, R> {
    pub fn try_append_buf<B: Buf>(&self, src: B) -> usize {
        todo!()
    }

    pub fn try_append_send_channel(&self) -> Result<SendChannel<R>, ExceedsChannelLimit> {
        todo!()
    }

    pub fn try_append_recv_channel(&self) -> Result<RecvChannel<R>, ExceedsChannelLimit> {
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

impl<'a, R: Route> io::Write for BatchSender<'a, R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.try_append(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send();
        Ok(())
    }
}

impl<'a, R: Route> Drop for BatchSender<'a, R> {
    fn drop(&mut self) {
        todo!()
    }
}

pub struct Space {
    pub channels: usize,
    pub bytes: usize,
}

impl<R: Route> SendChannel<R> {
    pub fn start_batch_send<'a>(&'a self) -> Result<BatchSender<'a, R>, Error> {
        todo!()
    }

    pub async fn send_buf<B: Buf>(&self, src: &mut B) -> Result<(), Error> {
        todo!()
    }

    pub async fn send_send_channel(&self) -> Result<SendChannel<R>, Error> {
        todo!()
    }

    pub async fn send_recv_channel(&self) -> Result<RecvChannel<R>, Error> {
        todo!()
    }

    pub async fn wait_for_sufficient_space(&self, space: Space) -> Result<(), Error> {
        todo!()
    }

    pub fn close(&self) -> Result<(), Error> {
        todo!()
    }
}

impl<R: Route> Drop for SendChannel<R> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub enum RecvAny<B, R: Route> {
    SendChannel(SendChannel<R>),
    RecvChannel(RecvChannel<R>),
    Data(B),
}

pub enum PeakAny<B> {
    SendChannel,
    RecvChannel,
    Data(B),
}


pub struct RecvReader<'a, R: Route> {
    channel: &'a RecvChannel<R>,
}

impl<R: Route> RecvChannel<R> {
    pub fn try_recv_any_reader<'a>(&'a self) -> Result<RecvAny<RecvReader<'a, R>, R>, TryError> {
        todo!()
    }

    pub async fn recv_any_reader<'a>(&'a self) -> Result<RecvAny<RecvReader<'a, R>, R>, Error> {
        todo!()
    }

    pub fn try_peek_reader<'a>(&'a self) -> Result<PeakAny<RecvReader<'a, R>>, TryError> {
        todo!()
    }

    pub async fn peek_reader<'a>(&'a self) -> Result<PeakAny<RecvReader<'a, R>>, Error> {
        todo!()
    }

    pub fn remaining_recv_space(&self) -> Result<Space, Error> {
        todo!()
    }

    pub async fn wait_for_recv_space(&self, space: Space) -> Result<(), Error> {
        todo!()
    }
}

impl<'a, R: Route> io::Read for RecvReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
    }
}

/* START OF EXTENDED API */

impl<'a, R: Route> BatchSender<'a, R> {
    pub fn try_append(&self, src: &[u8]) -> usize  {
        self.try_append_buf(src)
    }
}

impl<R: Route> SendChannel<R> {
    pub fn try_recv_any_buf<B: BufMut>(&self, buf: &mut B) -> Result<RecvAny<usize, R>, TryError> {
        todo!()
    }

    pub async fn recv_any_buf<B: BufMut>(&self, buf: &mut B) -> Result<RecvAny<usize, R>, Error> {
        todo!()
    }

    pub async fn send(&self, mut src: &[u8]) -> Result<(), Error>  {
        self.send_buf(&mut src).await
    }

    pub async fn wait_for_sufficient_bytes(&self, bytes: usize) -> Result<(), Error> {
        self.wait_for_sufficient_space(Space { channels: 0, bytes }).await
    }

}

impl<R: Route> RecvChannel<R> {
    pub fn try_peek_buf<B: BufMut>(&self, buf: &mut B) -> Result<PeakAny<usize>, TryError> {
        todo!()
    }

    pub async fn peek_buf<B: BufMut>(&self, buf: &mut B) -> Result<PeakAny<usize>, Error> {
        todo!()
    }
}
