/// The size in bytes of a ML-DSA-87 Public Key.
pub const PUBLIC_KEY_LEN: usize = 2592;
/// The size in bytes of a ML-DSA-87 Public Key.
pub const SIGN_LEN: usize = 4627;

pub trait SecretSigningKey {
    fn sign(&self, ctx: &[u8], data: &[u8]) -> [u8; SIGN_LEN];
}

pub trait PublicSigningKey {
    fn decode(public_key: [u8; PUBLIC_KEY_LEN]) -> Self;

    fn encode(&self) -> [u8; PUBLIC_KEY_LEN];

    #[must_use]
    fn verify(&self, ctx: &[u8], data: &[u8], signature: &[u8; SIGN_LEN]) -> bool;
}
