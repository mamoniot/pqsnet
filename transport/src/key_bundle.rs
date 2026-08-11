use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand_core::CryptoRng;
use smallvec::SmallVec;

use crate::{
    crypto::{mldsa87::*, shake256::Shake256},
    protocol::domain::OFFLINE_KEY_CERTIFICATION,
    session_layer::SessionLayer,
};

pub const OFFLINE_HASH_LEN: usize = 48;
pub const BUNDLE_UID_LEN: usize = 16;

pub const KEY_BUNDLE_MIN_LEN: usize = 2 * PUBLIC_KEY_LEN + SIGNATURE_LEN + BUNDLE_UID_LEN + 6;

pub fn get_secs_since_unix_epoch() -> u64 {
    // An `Err` is only returned if the systen time is set before unix epoch. In this case we
    // will only attempt signature verification if `self.not_before == 0`.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .as_ref()
        .map_or(0, Duration::as_secs)
}

pub struct AuthenticBundle<P: PublicSigningKey> {
    pub offline_hash: [u8; OFFLINE_HASH_LEN],
    pub online_key: P,
    pub counter: u64,
    pub uid: u128,
    pub not_before: u64,
    pub not_after: u64,
    pub flags: u32,
    extensions: SmallVec<[Extension; 4]>,
}

/// TODO: implement creation, serialization and deserialization.
pub struct PrivateBundle<P: PublicSigningKey, S: PrivateSigningKey> {
    private_online_key: S,
    public_bundle_bytes: Box<[u8]>,
    public_bundle: AuthenticBundle<P>,
}

pub type PrivateBundleSL<S: SessionLayer> = Arc<PrivateBundle<S::PublicSigningKeyImpl, S::PrivateSigningKeyImpl>>;

impl<P: PublicSigningKey, S: PrivateSigningKey> std::ops::Deref for PrivateBundle<P, S> {
    type Target = AuthenticBundle<P>;

    fn deref(&self) -> &Self::Target {
        &self.public_bundle
    }
}

#[derive(Debug, Clone, Copy, Hash)]
pub enum AuthError {
    Inauthentic,
    ExpiredKey,
    PostdatedKey,
}

impl std::error::Error for AuthError {}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Inauthentic => write!(f, "inauthentic"),
            AuthError::ExpiredKey => write!(f, "expired key"),
            AuthError::PostdatedKey => write!(f, "postdated key"),
        }
    }
}

impl<P: PublicSigningKey, S: PrivateSigningKey> PrivateBundle<P, S> {
    /// This function does not check
    pub fn sign(&self, ctx: &[u8], data: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.private_online_key.sign(ctx, data)
    }

    pub fn private_online_key(&self) -> &S {
        &self.private_online_key
    }

    pub fn public_bundle_bytes(&self) -> &[u8] {
        &self.public_bundle_bytes
    }
}

impl<P: PublicSigningKey> AuthenticBundle<P> {
    pub fn new<W: std::io::Write, R: CryptoRng, K: PrivateSigningKey>(
        writer: W,
        rng: &mut R,
        offline_private_key: K,
        offline_public_key: [u8; PUBLIC_KEY_LEN],
        online_public_key: [u8; PUBLIC_KEY_LEN],
        counter: u64,
        not_before: u64,
        not_after: u64,
        flags: u32,
    ) -> Result<Self, std::io::Error> {
        let bundle = RawKeyBundle {
            offline_key: offline_public_key,
            online_key: online_public_key,
            counter: todo!(),
            uid: todo!(),
            not_before,
            not_after: todo!(),
            flags: todo!(),
            extensions: todo!(),
        };
        cbor4ii::serde::to_writer(&mut writer, &bundle);
        todo!()
    }

    pub fn authenticate_and_get_end<H: Shake256>(bundle_bytes: &[u8]) -> Result<(Arc<Self>, usize), AuthError> {
        Self::authenticate_and_get_end_with_time::<H>(bundle_bytes, get_secs_since_unix_epoch())
    }

    pub fn authenticate_and_get_end_with_time<'a, H: Shake256>(
        bundle_bytes: &'a [u8],
        secs_since_unix_epoch: u64,
    ) -> Result<(Arc<Self>, usize), AuthError> {
        let mut reader = bundle_bytes;

        let bundle: RawKeyBundle = cbor4ii::serde::from_reader(&mut reader).map_err(|_| AuthError::Inauthentic)?;

        let signature_start = reader.as_ptr() as usize - bundle_bytes.as_ptr() as usize;
        let signature_end = signature_start + SIGNATURE_LEN;

        if signature_end > bundle_bytes.len() {
            return Err(AuthError::Inauthentic);
        } else if secs_since_unix_epoch < bundle.not_before {
            return Err(AuthError::PostdatedKey);
        } else if secs_since_unix_epoch > bundle.not_after {
            return Err(AuthError::ExpiredKey);
        }

        let offline_key = P::decode(bundle.offline_key.try_into().unwrap());
        let online_key = P::decode(bundle.online_key.try_into().unwrap());

        offline_key.verify(
            OFFLINE_KEY_CERTIFICATION,
            &bundle_bytes[..signature_start],
            (&bundle_bytes[signature_start..signature_end]).try_into().unwrap(),
        );

        let mut hasher = H::new();

        hasher.update(&bundle.offline_key);
        let mut offline_hash = [0; OFFLINE_HASH_LEN];
        hasher.finish(&mut offline_hash);

        Ok((
            Arc::new(AuthenticBundle {
                offline_hash,
                online_key,
                counter: bundle.counter,
                uid: u128::from_be_bytes(bundle.uid),
                not_before: bundle.not_before,
                not_after: bundle.not_after,
                flags: bundle.flags,
                extensions: bundle.extensions,
            }),
            signature_end,
        ))
    }

    /// `secs_since_unix_epoch` must be clamped to zero in the event that this system reports a
    /// time which is earlier than unix epoch.
    #[must_use]
    pub fn verify_with_time(
        &self,
        ctx: &[u8],
        data: &[u8],
        signature: &[u8; SIGNATURE_LEN],
        secs_since_unix_epoch: u64,
    ) -> Result<(), AuthError> {
        if secs_since_unix_epoch < self.not_before {
            Err(AuthError::PostdatedKey)
        } else if secs_since_unix_epoch > self.not_after {
            Err(AuthError::ExpiredKey)
        } else if !self.online_key.verify(ctx, data, signature) {
            Err(AuthError::Inauthentic)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn verify(&self, ctx: &[u8], data: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), AuthError> {
        self.verify_with_time(ctx, data, signature, get_secs_since_unix_epoch())
    }

    /// The first 8 bits of the key bundle flags are the handshake variant flags.
    /// Every handshake must use a handshake variant that is at least as strong as the handshake
    /// variant flags on both party's key bundles.
    pub(crate) fn check_handshake_flags(&self, handshake_flags: u8) -> bool {
        check_handshake_flags(self.flags as u8, handshake_flags)
    }
}

pub(crate) fn check_handshake_flags(required_flags: u8, handshake_flags: u8) -> bool {
    /* If a flag in either our or their key bundle is true, then the corresponding
    flag in `reply_handshake_flags` must be true. If not, then this handshake is not
    approved by one of the key bundles and we must abort. */
    required_flags & handshake_flags == required_flags
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtensionContents {}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Extension(bool, SmallVec<[u8; 4]>, ExtensionContents);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SerdeKeyBundle(
    #[serde(with = "serde_bytes")] [u8; PUBLIC_KEY_LEN],
    #[serde(with = "serde_bytes")] [u8; PUBLIC_KEY_LEN],
    #[serde(with = "serde_bytes")] [u8; BUNDLE_UID_LEN],
    u64,
    u64,
    u64,
    u32,
    SmallVec<[Extension; 4]>,
);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(from = "SerdeKeyBundle")]
#[serde(into = "SerdeKeyBundle")]
pub struct RawKeyBundle {
    offline_key: [u8; PUBLIC_KEY_LEN],
    online_key: [u8; PUBLIC_KEY_LEN],
    uid: [u8; BUNDLE_UID_LEN],
    counter: u64,
    not_before: u64,
    not_after: u64,
    flags: u32,
    extensions: SmallVec<[Extension; 4]>,
}

impl From<SerdeKeyBundle> for RawKeyBundle {
    fn from(v: SerdeKeyBundle) -> Self {
        Self {
            offline_key: v.0,
            online_key: v.1,
            uid: v.2,
            counter: v.3,
            not_before: v.4,
            not_after: v.5,
            flags: v.6,
            extensions: v.7,
        }
    }
}
impl From<RawKeyBundle> for SerdeKeyBundle {
    fn from(v: RawKeyBundle) -> Self {
        Self(
            v.offline_key,
            v.online_key,
            v.uid,
            v.counter,
            v.not_before,
            v.not_after,
            v.flags,
            v.extensions,
        )
    }
}
