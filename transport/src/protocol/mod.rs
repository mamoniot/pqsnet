// TODO: segmentation, version, payload

pub(crate) mod domain;

pub(crate) mod shared;

pub(crate) mod initialize;

pub(crate) mod reply;

pub(crate) mod resume;

pub(crate) mod confirm;

pub(crate) mod data;

pub const HEADER_LEN: usize = 8;
pub const FOOTER_LEN: usize = 16;
pub const OVERHEAD_LEN: usize = HEADER_LEN + FOOTER_LEN;
