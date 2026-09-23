use std::ops::Range;

use crate::crypto::*;

/* BUNDLE DEFINITION */

pub const VERSION_START: usize = 0;
pub const VERSION_LEN: usize = 1;
pub const VERSION_END: usize = VERSION_START + VERSION_LEN;
pub const VERSION_IDX: usize = VERSION_START;
pub const VERSION_VALUE: u8 = 0;

pub const OFFLINE_KEY_START: usize = VERSION_END;
pub const OFFLINE_KEY_LEN: usize = mldsa87::PUBLIC_KEY_LEN;
pub const OFFLINE_KEY_END: usize = OFFLINE_KEY_START + OFFLINE_KEY_LEN;
pub const OFFLINE_KEY_RANGE: Range<usize> = OFFLINE_KEY_START..OFFLINE_KEY_END;

pub const ONLINE_KEY_START: usize = OFFLINE_KEY_END;
pub const ONLINE_KEY_LEN: usize = mldsa87::PUBLIC_KEY_LEN;
pub const ONLINE_KEY_END: usize = ONLINE_KEY_START + ONLINE_KEY_LEN;
pub const ONLINE_KEY_RANGE: Range<usize> = ONLINE_KEY_START..ONLINE_KEY_END;

pub const NOT_BEFORE_START: usize = ONLINE_KEY_END;
pub const NOT_BEFORE_LEN: usize = u64::BITS as usize / 8;
pub const NOT_BEFORE_END: usize = NOT_BEFORE_START + NOT_BEFORE_LEN;
pub const NOT_BEFORE_RANGE: Range<usize> = NOT_BEFORE_START..NOT_BEFORE_END;

pub const NOT_AFTER_START: usize = NOT_BEFORE_END;
pub const NOT_AFTER_LEN: usize = u64::BITS as usize / 8;
pub const NOT_AFTER_END: usize = NOT_AFTER_START + NOT_AFTER_LEN;
pub const NOT_AFTER_RANGE: Range<usize> = NOT_AFTER_START..NOT_AFTER_END;

pub const COUNTER_START: usize = NOT_AFTER_END;
pub const COUNTER_LEN: usize = u32::BITS as usize / 8;
pub const COUNTER_END: usize = COUNTER_START + COUNTER_LEN;
pub const COUNTER_RANGE: Range<usize> = COUNTER_START..COUNTER_END;

pub const FLAGS_START: usize = COUNTER_END;
pub const FLAGS_LEN: usize = u32::BITS as usize / 8;
pub const FLAGS_END: usize = FLAGS_START + FLAGS_LEN;
pub const FLAGS_RANGE: Range<usize> = FLAGS_START..FLAGS_END;

pub const EXTENSIONS_LEN_START: usize = FLAGS_END;
pub const EXTENSIONS_LEN_LEN: usize = u32::BITS as usize / 8;
pub const EXTENSIONS_LEN_END: usize = EXTENSIONS_LEN_START + EXTENSIONS_LEN_LEN;
pub const EXTENSIONS_LEN_RANGE: Range<usize> = EXTENSIONS_LEN_START..EXTENSIONS_LEN_END;

pub const EXTENSIONS_START: usize = EXTENSIONS_LEN_END;

/* BUNDLE TAIL DEFINITION */

pub const EXTENSIONS_REV_START: usize = OFFLINE_SIGN_REV_END;

pub const OFFLINE_SIGN_REV_END: usize = OFFLINE_SIGN_REV_START + OFFLINE_SIGN_LEN;
pub const OFFLINE_SIGN_LEN: usize = mldsa87::SIGN_LEN;
pub const OFFLINE_SIGN_REV_START: usize = 0;

/* MISC CONSTANTS */

pub const FLAG_RELIABLE_STORAGE: u32 = 0b1;

pub const OFFLINE_HASH_LEN: usize = 48;
pub const BUNDLE_HASH_LEN: usize = 32;

pub const MIN_LEN: usize = EXTENSIONS_START + EXTENSIONS_REV_START;
