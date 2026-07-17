// TODO: segmentation, version, payload
pub const KEY_ID_START: usize = 0;
pub const KEY_ID_LEN: usize = 4;
pub const KEY_ID_END: usize = KEY_ID_START + KEY_ID_LEN;

pub const SEGMENT_NO_IDX: usize = 4;
pub const SEGMENT_TOTAL_IDX: usize = 5;
pub const SEGMENT_REMAINDER_IDX: usize = 6;
pub const EXCHANGE_MESSAGE_START: usize = 8;

/// struct Initialize {
///     pub null: u32,
///     pub segment_number: u8,
///     pub segment_total: u8,
///     pub segment_remainder: u8,
///     pub reserved: u8,
///     pub resumption_token: [u8; 32],
///     pub ephemeral_encapsulation_key: [u8; 1088],
///     pub ephemeral_encapsulation_key_tag: [u8; 16],
///     pub new_key_id: u32,
///
///     pub payload_tag: [u8; 16],
/// }
pub mod initialize;

/// struct Reply {
///     pub key_id: u32,
///     pub segment_number: u8,
///     pub segment_total: u8,
///     pub segment_remainder: u8,
///     pub reserved: u8,
///     pub ephemeral_ciphertext: [u8; 1088],
///     pub ephemeral_ciphertext_tag: [u8; 16],
///     pub static_offline_public_key: [u8; 1952],
///     pub static_online_public_key: [u8; 1952],
///     pub static_offline_signature: [u8; 3309], <- Not word aligned.
///     pub new_key_id: u32,
///
///     pub payload_tag: [u8; 16],
///     pub static_online_signature: [u8; 3309], <- Not word aligned.
///     pub static_online_signature_tag: [u8; 16],
/// }
pub mod reply;

/// struct Resume {
///     pub key_id: u32,
///     pub segment_number: u8,
///     pub segment_total: u8,
///     pub segment_remainder: u8,
///     pub reserved: u8,
///     pub ephemeral_ciphertext: [u8; 1088],
///     pub ephemeral_ciphertext_tag: [u8; 16],
///     pub new_key_id: u32,
///
///     pub payload_tag: [u8; 16],
/// }
pub mod resume;

/// struct Confirm {
///     pub key_id: u32,
///     pub segment_number: u8,
///     pub segment_total: u8,
///     pub segment_remainder: u8,
///     pub reserved: u8,
///     pub static_offline_public_key: [u8; 1952],
///     pub static_online_public_key: [u8; 1952],
///     pub static_offline_signature: [u8; 3309], <- Not word aligned.
///
///     pub payload_tag: [u8; 16],
///     pub static_online_signature: [u8; 3309], <- Not word aligned.
///     pub static_online_signature_tag: [u8; 16],
/// }
pub mod confirm;

/// struct Data {
///     pub key_id: u32,
///     pub counter: u64,
///     pub session_data: [u8; ...]
///     pub payload_tag: [u8; 16],
/// }
pub mod data;
