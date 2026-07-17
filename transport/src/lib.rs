
pub mod session_layer;

pub mod crypto;

pub mod messages;

pub mod desegmentation;

use bytemuck::from_bytes;

use crate::messages::*;

pub struct Context {}

pub struct Socket {}

pub enum RecvResult {
    NewSocket(Socket),
}
impl Context {
    pub fn recv(&self, packet: &mut [u8]) -> RecvResult {
        let key_id = u32::from_be_bytes(*from_bytes(&packet[KEY_ID_START..KEY_ID_END]));
    }

    pub fn send() {}
}
