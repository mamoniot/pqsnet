pub const VARIANT_NULL_TERMINATOR: u8 = 0;
pub const VARIANT_PADDING: u8 = 1;
pub const VARIANT_SEGMENT: u8 = 2;
pub const VARIANT_SEGMENT_TERMINATOR: u8 = 3;
pub const VARIANT_METADATA: u8 = 4;
pub const VARIANT_METADATA_RECV: u8 = 5;
pub const VARIANT_METADATA_SEND: u8 = 6;
pub const VARIANT_ACK_SINGLE: u8 = 7;
pub const VARIANT_ACK_RUN: u8 = 8;
pub const VARIANT_DOC_FIN: u8 = 9;
// pub const VARIANT_DOC_ACK: u8 = 6;

pub const MIN_VARIANT_APPEND_LEN: usize = 20;
pub const MIN_DATA_APPEND_LEN: usize = 16;
pub const MIN_MTU: usize = 128;
