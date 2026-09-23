use crate::crypto::aes256::NONCE_LEN;

/* CRYPTOGRAPHIC DOMAINS */

pub const OFFLINE_KEY_CERTIFICATION: &[u8] = b"PQSNET_MLDSA87_CERTIFICATION";

pub const OFFLINE_SALT: &[u8] = b"PQSNET_SHAKE256_OFFLINE_SALT\0";

pub const BUNDLE_SALT: &[u8] = b"PQSNET_SHAKE256_BUNDLE_SALT\0";

pub const HANDSHAKE_SALT: &[u8] = b"PQSNET_TRANSPORT_AESGCM_SHAKE256_MLKEM1024_MLDSA87";

pub const INITIALIZE_BINDING: &[u8] = b"PQSNET_AESGCM256_SHAKE256_MLKEM1024_MLDSA87_INIT";

pub const REPLY_BINDING: &[u8] = b"PQSNET_AESGCM256_SHAKE256_MLKEM1024_MLDSA87_REPLY";

pub const CONFIRM_BINDING: &[u8] = b"PQSNET_AESGCM256_SHAKE256_MLKEM1024_MLDSA87_CONFIRM";

/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
pub const AES_GCM_FIXED_FIELD_HANDSHAKE: [u8; NONCE_LEN] = *b"PQSH\0\0\0\0\0\0\0\0";
pub const AES_GCM_FIXED_FIELD_DATA: [u8; NONCE_LEN] = *b"PQSD\0\0\0\0\0\0\0\0";

pub fn to_data_nonce(counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = AES_GCM_FIXED_FIELD_DATA;
    nonce[NONCE_LEN - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn to_handshake_nonce(step_no: u8) -> [u8; NONCE_LEN] {
    let mut nonce = AES_GCM_FIXED_FIELD_HANDSHAKE;
    nonce[NONCE_LEN - 1] = step_no;
    nonce
}
