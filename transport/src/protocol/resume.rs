use std::ops::Range;

use super::*;

/* START OF MESSAGE DEFINITION */

pub const HANDSHAKE_FLAGS_START: usize = reply::HANDSHAKE_FLAGS_START;
pub const HANDSHAKE_FLAGS_LEN: usize = reply::HANDSHAKE_FLAGS_LEN;
pub const HANDSHAKE_FLAGS_END: usize = reply::HANDSHAKE_FLAGS_END;
pub const HANDSHAKE_FLAGS_IDX: usize = reply::HANDSHAKE_FLAGS_IDX;

pub const EPHEMERAL_CIPHERTEXT_START: usize = reply::EPHEMERAL_CIPHERTEXT_START;
pub const EPHEMERAL_CIPHERTEXT_LEN: usize = reply::EPHEMERAL_CIPHERTEXT_LEN;
pub const EPHEMERAL_CIPHERTEXT_END: usize = reply::EPHEMERAL_CIPHERTEXT_END;
pub const EPHEMERAL_CIPHERTEXT_RANGE: Range<usize> = reply::EPHEMERAL_CIPHERTEXT_RANGE;

pub const PAYLOAD_LEN_START: usize = reply::PAYLOAD_LEN_START;
pub const PAYLOAD_LEN_LEN: usize = reply::PAYLOAD_LEN_LEN;
pub const PAYLOAD_LEN_END: usize = reply::PAYLOAD_LEN_END;
pub const PAYLOAD_LEN_RANGE: Range<usize> = reply::PAYLOAD_LEN_RANGE;

pub const PAYLOAD_START: usize = PAYLOAD_LEN_END;

pub const PREMESSAGE_RANGE: Range<usize> = reply::PREMESSAGE_RANGE;

/* START OF MESSAGE TAIL DEFINITION */

pub const PAYLOAD_REV_START: usize = PAYLOAD_TAG_REV_END;

pub const PAYLOAD_TAG_REV_END: usize = reply::PAYLOAD_TAG_REV_END;
pub const PAYLOAD_TAG_LEN: usize = reply::PAYLOAD_TAG_LEN;
pub const PAYLOAD_TAG_REV_START: usize = reply::PAYLOAD_TAG_REV_START;

pub const ONLINE_SIGN_REV_END: usize = reply::ONLINE_SIGN_REV_END;
pub const ONLINE_SIGN_LEN: usize = reply::ONLINE_SIGN_LEN;
pub const ONLINE_SIGN_REV_START: usize = reply::ONLINE_SIGN_REV_START;

pub const ONLINE_SIGN_TAG_REV_END: usize = reply::ONLINE_SIGN_TAG_REV_END;
pub const ONLINE_SIGN_TAG_LEN: usize = reply::ONLINE_SIGN_TAG_LEN;
pub const ONLINE_SIGN_TAG_REV_START: usize = reply::ONLINE_SIGN_REV_START;

/* START OF MISC CONSTANTS */

pub const MESSAGE_TAIL_LEN: usize = reply::MESSAGE_TAIL_LEN;
pub const MESSAGE_MIN_LEN: usize = reply::MESSAGE_MIN_LEN;

pub const MESSAGE_GCM_TOTAL: u32 = 2;
