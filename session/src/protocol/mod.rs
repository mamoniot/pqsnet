use std::ops::Range;

pub const VARIANT_NULL_TERMINATOR: u8 = 0x0;
pub const VARIANT_PADDING: u8 = 0xFF;

pub const VARIANT_SEGMENT: u8 = 0x01;
pub const VARIANT_SEGMENT_IS_TERMINATOR: u8 = 0x02;
pub const VARIANT_SEGMENT_HAS_TERMINATOR: u8 = 0x03;
pub const VARIANT_SEGMENT_FLAG_CLOSE_SEND: u8 = 0x04;
pub const VARIANT_SEGMENT_FLAG_CLOSE_RECV: u8 = 0x08;
pub const VARIANT_SEGMENT_BASE_MASK: u8 = 0x0C;
pub const VARIANT_SEGMENT_MAX: u8 = 0x10;

pub const VARIANT_ACK_SINGLE: u8 = 0x10;
pub const VARIANT_ACK_RUN: u8 = 0x11;

// TODO: Keep alive, explicit congestion, data blocked, connection close.

pub const MIN_FRAME_APPEND_LEN: usize = 20;
pub const MIN_MTU: usize = 128;

pub const MAX_DOC_HEADER_LEN: usize = 8 * 2;
