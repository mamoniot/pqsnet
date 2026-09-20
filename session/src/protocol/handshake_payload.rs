use serde::{Deserialize, Serialize};

use crate::context::SocketId;

pub const HANDSHAKE_PAYLOAD_LEN_MAX: usize = 16;
pub const CUR_MAJOR_VERSION: u32 = 0;
pub const CUR_MINOR_VERSION: u32 = 1;

/// Serde ignores unrecognized fields by default, with `deny_unknown_fields` being absent.
/// This is the correct behavior as it allows for forward compatibility.
#[derive(Serialize, Deserialize)]
pub struct HandshakePayload {
    #[serde(rename = "v")]
    pub major_version: u32,
    #[serde(rename = "r")]
    pub minor_version: u32,
    #[serde(rename = "s")]
    pub socket_id: SocketId,
}

#[test]
fn test_max_len() {
    let mut mem = arrayvec::ArrayVec::<u8, HANDSHAKE_PAYLOAD_LEN_MAX>::new();
    let p = HandshakePayload {
        major_version: u32::MAX,
        minor_version: u32::MAX,
        socket_id: SocketId::MAX,
    };
    cbor4ii::serde::to_writer(&mut mem, &p);
}
