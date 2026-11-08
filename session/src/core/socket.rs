use std::{convert::Infallible, io, rc::Rc, sync::Arc};

use bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};

pub struct SendSocket {

}

pub struct RecvSocket {

}

impl Context {

}

pub enum RecvOk {
    RecvLossy(Vec<u8>),
    NewRecvChannel(RecvChannel),
    NewSendChannel(SendChannel),
    Nop,
}

impl Context {
    pub async fn new_send_channel(&self) -> SendChannel {
        todo!()
    }

    pub async fn new_recv_channel(&self) -> RecvChannel {
        todo!()
    }

    pub fn send_lossy(&self) {
        todo!()
    }

    pub async fn recv(&self, packet: Vec<u8>) -> Result<RecvOk, Error> {
        todo!()
    }
}

pub struct BatchSender<'a> {
    channel: &'a SendChannel,
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


pub struct WindowFull;

impl<'a> BatchSender<'a> {
    pub fn try_append_buf<B: Buf>(&self, src: B) -> usize {
        todo!()
    }

    pub fn try_append_send_channel(&self) -> Result<SendChannel, WindowFull> {
        todo!()
    }

    pub fn try_append_recv_channel(&self) -> Result<RecvChannel, WindowFull> {
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

impl<'a> io::Write for BatchSender<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.try_append(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send();
        Ok(())
    }
}

impl<'a> Drop for BatchSender<'a> {
    fn drop(&mut self) {
        todo!()
    }
}
pub struct Space {
    pub channels: usize,
    pub bytes: usize,
}

impl SendChannel {
    pub fn start_batch_send<'a>(&'a self) -> Result<BatchSender<'a>, Error> {
        todo!()
    }

    pub async fn send_buf<B: Buf>(&self, src: &mut B) -> Result<(), Error> {
        todo!()
    }

    pub async fn send_send_channel(&self) -> Result<SendChannel, Error> {
        todo!()
    }

    pub async fn send_recv_channel(&self) -> Result<RecvChannel, Error> {
        todo!()
    }

    pub async fn wait_for_sufficient_space(&self, space: Space) -> Result<(), Error> {
        todo!()
    }

    pub fn close(&self) -> Result<(), Error> {
        todo!()
    }
}

impl Drop for SendChannel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub enum RecvAny<B> {
    SendChannel(SendChannel),
    RecvChannel(RecvChannel),
    Data(B),
}

pub enum PeakAny<B> {
    SendChannel,
    RecvChannel,
    Data(B),
}


pub struct RecvReader<'a> {
    channel: &'a RecvChannel,
}

impl RecvChannel {
    pub fn try_recv_any_reader<'a>(&'a self) -> Result<RecvAny<RecvReader<'a>>, TryError> {
        todo!()
    }

    pub async fn recv_any_reader<'a>(&'a self) -> Result<RecvAny<RecvReader<'a>>, Error> {
        todo!()
    }

    pub fn try_peek_reader<'a>(&self) -> Result<PeakAny<RecvReader<'a>>, TryError> {
        todo!()
    }

    pub async fn peek_reader<'a>(&self) -> Result<PeakAny<RecvReader<'a>>, Error> {
        todo!()
    }

    pub fn remaining_recv_space(&self) -> Result<Space, Error> {
        todo!()
    }

    pub async fn wait_for_recv_space(&self, space: Space) -> Result<(), Error> {
        todo!()
    }
}

impl<'a> io::Read for RecvReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
    }
}

/* START OF EXTENDED API */

impl<'a> BatchSender<'a> {
    pub fn try_append(&self, src: &[u8]) -> usize  {
        self.try_append_buf(src)
    }
}

impl SendChannel {
    pub fn try_recv_any_buf<B: BufMut>(&self, buf: &mut B) -> Result<RecvAny<usize>, TryError> {
        todo!()
    }

    pub async fn recv_any_buf<B: BufMut>(&self, buf: &mut B) -> Result<RecvAny<usize>, Error> {
        todo!()
    }

    pub async fn send(&self, mut src: &[u8]) -> Result<(), Error>  {
        self.send_buf(&mut src).await
    }

    pub async fn wait_for_sufficient_bytes(&self, bytes: usize) -> Result<(), Error> {
        self.wait_for_sufficient_space(Space { channels: 0, bytes }).await
    }

}

impl RecvChannel {
    pub fn try_peek_buf<B: BufMut>(&self, buf: &mut B) -> Result<PeakAny<usize>, TryError> {
        todo!()
    }

    pub async fn peek_buf<B: BufMut>(&self, buf: &mut B) -> Result<PeakAny<usize>, Error> {
        todo!()
    }
}

// impl SendChannel {
//     pub async fn send_slice(&self, reader: &[u8]) {
//         todo!()
//     }

//     pub async fn send_slice_await_recv(&self, reader: &[u8]) -> RecvChannel {
//         todo!()
//     }

//     pub async fn open_new_send_channel(&self) -> SendChannel {
//         todo!()
//     }

//     pub async fn send<S: Serialize>(&self, data: &S) {
//         todo!()
//     }

//     pub async fn send_await_reply<'a, S: Serialize, D: Deserialize<'a>>(&'a self, data: &S) -> D {
//         todo!()
//     }

//     pub async fn send_await_channel<S: Serialize>(&self, data: &S) -> Channel {
//         todo!()
//     }

//     pub async fn send_await_reader<'a, S: Serialize>(&'a self, data: &S) -> ChannelReader {
//         todo!()
//     }

//     pub fn recv<'a, D: Deserialize<'a>>(&'a self) -> D {
//         todo!()
//     }
// }
