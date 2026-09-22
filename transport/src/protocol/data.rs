use std::ops::Range;

use crate::crypto::*;

/* START OF MESSAGE DEFINITION */

pub const GCM_COUNTER_START: usize = 0;
pub const GCM_COUNTER_LEN: usize = 4;
pub const GCM_COUNTER_END: usize = GCM_COUNTER_START + GCM_COUNTER_LEN;
pub const GCM_COUNTER_RANGE: Range<usize> = GCM_COUNTER_START..GCM_COUNTER_END;

pub const DATA_START: usize = GCM_COUNTER_END;

/* START OF GENERAL CONSTANTS */

pub const TAG_LEN: usize = aes256::TAG_LEN;
pub const MAXIMUM_AES_GCM_COUNTER: u32 = u32::MAX;

pub const REKEY_AES_GCM_COUNTER: u32 = 1 << 30;
pub const REKEY_WAIT_MS: u64 = 1000 * 60 * 60;
