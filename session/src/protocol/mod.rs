/* PAYLOAD FRAME VARIANTS */

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
pub const VARIANT_SEG_MAX: u8 = 0x7F;

pub const VARIANT_ACK_SINGLE: u8 = 0x80;
pub const VARIANT_ACK_RUN: u8 = 0x81;

/// Has priority over `VARIANT_RESET_DOC`
///
/// Ack eliciting.
pub const VARIANT_CONTROL_CLOSE: u8 = 0x82;
pub const VARIANT_CONTROL_FIN: u8 = 0x82;

/// Has priority over `VARIANT_RESET`
///
/// Ack eliciting.
pub const VARIANT_REJECT: u8 = 0x83;
pub const VARIANT_SKIP_DOC_NO: u8 = 0x82;

/// The length and contents of a document must not change after a reset.
///
/// Ack eliciting.
pub const VARIANT_RESET: u8 = 0x84;

/* MISC */

// TODO: Keep alive, explicit congestion, data blocked, connection close.

pub const MIN_FRAME_APPEND_LEN: usize = 16;
pub const MAX_SEG_HEADER_LEN: usize = 1 + 8 + 8 + 8 + 8 + 4;
pub const MIN_SEG_HEADER_LEN: usize = 1 + 1 + 1;
pub const MIN_SEG_DATA_LEN: usize = 16;
pub const MIN_MTU: usize = MAX_SEG_HEADER_LEN + MIN_SEG_DATA_LEN;
