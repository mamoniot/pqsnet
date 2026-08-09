
pub const VARIANT_NULL: u8 = 0;
pub const VARIANT_PACKET_END: u8 = 1;
pub const VARIANT_DOC_DATA: u8 = 2;
pub const VARIANT_DOC_HEAD: u8 = 3;
pub const VARIANT_DOC_HEAD_RECV: u8 = 4;
pub const VARIANT_DOC_HEAD_SEND: u8 = 5;
// pub const VARIANT_DOC_DATA_ACK: u8 = 5;
// pub const VARIANT_DOC_ACK: u8 = 6;
// pub const VARIANT_DOC_FIN: u8 = 7;

pub const MIN_APPEND_LEN: usize = 16;
pub const MIN_MTU: usize = 128;
