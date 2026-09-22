/* START OF CRYPTOGRAPHIC DOMAINS */

use crate::{crypto::aes256, protocol::shared::CHAINING_KEY_LEN};

/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
pub const AES_GCM_FIXED_FIELD_HANDSHAKE: &[u8; aes256::NONCE_LEN] = b"PQSH\0\0\0\0\0\0\0\0";
pub const AES_GCM_FIXED_FIELD_DATA: &[u8; aes256::NONCE_LEN] = b"PQSD\0\0\0\0\0\0\0\0";

#[allow(unused)]
pub const TRANSPORT_PROTOCOL: &[u8] = b"PQSNET_TRANSPORT_AESGCM_SHAKE256_MLKEM1024_MLDSA87";
pub const TRANSPORT_PROTOCOL_SHAKE256: [u8; CHAINING_KEY_LEN] = hex_literal::hex!(
    "7918e89439ee4adbfe8a3e0c5907149b3da2f07b7dc2c3b1e05c1666295a0a9216205ced1444fcbbe3a48d52e630ea1dec26d276c754d0e1de2ac51a6241ac58"
);

pub const OFFLINE_KEY_CERTIFICATION: &[u8] = b"PQSNET_STATIC_OFFLINE_KEY_ONLINE_KEY_CERTIFICATION";

pub const INITIALIZE_BINDING: &[u8] = b"PQSNET_TRANSPORT_AESGCM_SHAKE256_MLKEM1024_INIT";

pub const REPLY_BINDING: &[u8] = b"PQSNET_TRANSPORT_AESGCM_SHAKE256_MLKEM1024_REPLY";

pub const RESUME_BINDING: &[u8] = b"PQSNET_TRANSPORT_AESGCM_SHAKE256_MLKEM1024_RESUME";

pub const CONFIRM_BINDING: &[u8] = b"PQSNET_TRANSPORT_AESGCM_SHAKE256_MLKEM1024_CONFIRM";

pub(crate) fn to_handshake_nonce(counter: u32) -> [u8; aes256::NONCE_LEN] {
    let mut nonce = *AES_GCM_FIXED_FIELD_HANDSHAKE;
    nonce[aes256::NONCE_LEN - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub(crate) fn to_data_nonce(counter: u32) -> [u8; aes256::NONCE_LEN] {
    let mut nonce = *AES_GCM_FIXED_FIELD_DATA;
    nonce[aes256::NONCE_LEN - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
