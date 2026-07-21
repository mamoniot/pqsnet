pub const PUBLIC_KEY_LEN: usize = 2592;
pub const SIGNATURE_LEN: usize = 4627;

/* START OF KEY BUNDLE DEFINITION */

pub const STATIC_OFFLINE_PUBKEY_START: usize = 0;
pub const STATIC_OFFLINE_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const STATIC_OFFLINE_PUBKEY_END: usize = STATIC_OFFLINE_PUBKEY_START + STATIC_OFFLINE_PUBKEY_LEN;

pub const STATIC_ONLINE_PUBKEY_START: usize = STATIC_OFFLINE_PUBKEY_END;
pub const STATIC_ONLINE_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const STATIC_ONLINE_PUBKEY_END: usize = STATIC_ONLINE_PUBKEY_START + STATIC_ONLINE_PUBKEY_LEN;

pub const STATIC_OFFLINE_SIGN_START: usize = STATIC_ONLINE_PUBKEY_END;
pub const STATIC_OFFLINE_SIGN_LEN: usize = SIGNATURE_LEN;
pub const STATIC_OFFLINE_SIGN_END: usize = STATIC_OFFLINE_SIGN_START + STATIC_OFFLINE_SIGN_LEN;

pub const STATIC_KEY_BUNDLE_LEN: usize = STATIC_OFFLINE_SIGN_END;

pub trait PublicKeyBundle {
    fn sign_with_online(&mut self, ctx: &[u8], data: &[u8]) -> [u8; SIGNATURE_LEN];

    fn encode_key_bundle(&mut self) -> [u8; STATIC_KEY_BUNDLE_LEN];

    #[must_use]
    fn verify(
        public_key: &[u8; PUBLIC_KEY_LEN],
        ctx: &[u8],
        data: &[u8],
        signature: &[u8; STATIC_OFFLINE_SIGN_LEN],
    ) -> bool;
}
