use super::*;
use crate::crypto;

/* START OF MESSAGE DEFINITION */

#[allow(unused)]
pub const EPHEMERAL_CIPHERTEXT_START: usize = reply::EPHEMERAL_CIPHERTEXT_START;
#[allow(unused)]
pub const EPHEMERAL_CIPHERTEXT_LEN: usize = reply::EPHEMERAL_CIPHERTEXT_LEN;
#[allow(unused)]
pub const EPHEMERAL_CIPHERTEXT_END: usize = reply::EPHEMERAL_CIPHERTEXT_END;

#[allow(unused)]
pub const EPHEMERAL_CIPHERTEXT_TAG_START: usize = reply::EPHEMERAL_CIPHERTEXT_TAG_START;
#[allow(unused)]
pub const EPHEMERAL_CIPHERTEXT_TAG_LEN: usize = reply::EPHEMERAL_CIPHERTEXT_TAG_LEN;
pub const EPHEMERAL_CIPHERTEXT_TAG_END: usize = reply::EPHEMERAL_CIPHERTEXT_TAG_END;

pub const NEW_SOCKET_ID_START: usize = EPHEMERAL_CIPHERTEXT_TAG_END;
pub const NEW_SOCKET_ID_LEN: usize = 4;
pub const NEW_SOCKET_ID_END: usize = NEW_SOCKET_ID_START + NEW_SOCKET_ID_LEN;

pub const PAYLOAD_TAG_START: usize = NEW_SOCKET_ID_END;
pub const PAYLOAD_TAG_LEN: usize = crypto::aes256::TAG_LEN;
pub const PAYLOAD_TAG_END: usize = PAYLOAD_TAG_START + PAYLOAD_TAG_LEN;

/* START OF GENERAL CONSTANTS */

#[allow(unused)]
pub const HEADER_LEN: usize = shared::SEGMENT_HEADER_END;
pub const MESSAGE_LEN: usize = PAYLOAD_TAG_END;

pub const MESSAGE_MIN_LEN: usize = PAYLOAD_TAG_END;
pub const MESSAGE_MAX_LEN: usize = PAYLOAD_TAG_END;

pub const MESSAGE_GCM_TOTAL: u32 = 2;
pub const COUNTER_SKIP: u32 = reply::MESSAGE_GCM_TOTAL + confirm::MESSAGE_GCM_TOTAL;
