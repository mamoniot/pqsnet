/* HANDSHAKE PAYLOAD */

use crate::{context::SocketId, varint::VARINT_U8_MAX};

pub const HANDSHAKE_PAYLOAD_LEN_MAX: usize = 64;
pub const HANDSHAKE_HEADER_LEN: usize = 8;

/* FRAME VARIANTS */

pub const VARIANT_NULL_TERMINATOR: u8 = 0x0;
pub const VARIANT_PADDING: u8 = 0xFF;

/// Document Segment Frame {
/// Segment length type (2),
/// Segment is first (1),
/// Single segment document (1),
/// Document has retransmission (1),
/// Document expects reply buffer (1),
/// Document has reply buffer (1),
/// Reseverved (1) = 0,
/// Document number (i),
/// [Document length (i)],
/// [Document parent (i)],
/// [Segment offset (i)],
/// [Segment length (i)],
/// Segment data (..)
/// }
///
/// Ack eliciting.
pub const VARIANT_SEG_HAS_LEN: u8 = 0x01;
pub const VARIANT_SEG_IS_TERMINATOR: u8 = 0x02;
pub const VARIANT_SEG_HAS_TERMINATOR: u8 = 0x03;
pub const VARIANT_SEG_FLAG_IS_FIRST: u8 = 0x04;
pub const VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT: u8 = 0x08;
pub const VARIANT_SEG_FLAG_HAS_DOC_LEN: u8 = 0x10;
pub const VARIANT_SEG_FLAG_IS_SINGLE_SEG: u8 = 0x20;
pub const VARIANT_SEG_FLAG_IS_CLOSED: u8 = 0x40;

pub const VARIANT_SEG_LEN_MASK: u8 = 0x03;
pub const VARIANT_SEG_ALLOC_MASK: u8 = 0x30;
pub const VARIANT_SEG_MIN: u8 = 0x01;
pub const VARIANT_SEG_MAX: u8 = 0x7F;

/// Has priority over `VARIANT_RESET_DOC`
///
/// Ack eliciting.
pub const VARIANT_CONTROL_FIN: u8 = 0x82;
pub const VARIANT_CONTROL_FIN_DRAIN: u8 = 0x82;
pub const VARIANT_CONTROL_FIN_PARENT_CLOSED: u8 = 0x82;
pub const VARIANT_CONTROL_CLOSE: u8 = 0x84;

pub const VARIANT_ACK_SINGLE: u8 = 0x80;
pub const VARIANT_ACK_RUN: u8 = 0x81;

pub const VARIANT_BYTES_MAX_INC: u8 = 0x81;

/* MISC */

pub const SOCKET_ID_NEW_SESSION_V1: SocketId = 0;
pub const SOCKET_ID_RESERVED_MAX: SocketId = VARINT_U8_MAX as SocketId;

// TODO: Keep alive, explicit congestion, data blocked, connection close.

pub const MIN_FRAME_APPEND_LEN: usize = 16;
pub const MAX_SEG_HEADER_LEN: usize = 1 + 8 + 8 + 8 + 8 + 4;
pub const MIN_SEG_HEADER_LEN: usize = 1 + 1 + 1;
pub const MIN_SEG_DATA_LEN: usize = 16;
pub const MIN_MTU: usize = MAX_SEG_HEADER_LEN + MIN_SEG_DATA_LEN;

pub const HEADER_LEN: usize = 8;
pub const FOOTER_LEN: usize = 16;

pub const fn resend_ratio(mtu: u32) -> u32 {
    mtu * 2 / 3
}
