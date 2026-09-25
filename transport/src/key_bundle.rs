use std::time::{Duration, SystemTime, UNIX_EPOCH};

use constant_time_eq::{constant_time_eq_32, constant_time_eq_n};

use crate::{
    crypto::{mldsa87::*, shake256::Hasher},
    protocol::{domain, key_bundle::*},
};

pub mod constants {
    pub use crate::protocol::key_bundle::*;
}

pub fn get_secs_since_unix_epoch() -> u64 {
    // An `Err` is only returned if the systen time is set before unix epoch. In this case we
    // will only attempt signature verification if `self.not_before == 0`.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .as_ref()
        .map_or(0, Duration::as_secs)
}

pub type OfflineHash = [u8; OFFLINE_HASH_LEN];

pub type BundleHash = [u8; BUNDLE_HASH_LEN];

pub struct AuthenticBundle<P: PublicSigningKey> {
    offline_hash: OfflineHash,
    bundle_hash: BundleHash,
    online_key: P,
    not_before: u64,
    not_after: u64,
    counter: u32,
    flags: u32,
    extensions: Box<[u8]>,
}

pub struct SecretBundle<P: PublicSigningKey, S: SecretSigningKey> {
    online_secret_key: S,
    public_bundle_bytes: Box<[u8]>,
    public_bundle: AuthenticBundle<P>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum AuthError {
    Invalid,
    Inauthentic,
    ExpiredKey,
    PostdatedKey,
    UnrecognizedVersion,
}

impl std::error::Error for AuthError {}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Invalid => write!(f, "invalid"),
            AuthError::Inauthentic => write!(f, "inauthentic"),
            AuthError::ExpiredKey => write!(f, "expired key"),
            AuthError::PostdatedKey => write!(f, "postdated key"),
            AuthError::UnrecognizedVersion => write!(f, "unrecognized key version"),
        }
    }
}

fn hash_bundle<H: Hasher>(buf: &[u8]) -> (OfflineHash, BundleHash) {
    let mut hasher = H::new();
    hasher.update(domain::OFFLINE_SALT);
    hasher.update(&buf[OFFLINE_KEY_RANGE]);

    let mut offline_hash = [0; OFFLINE_HASH_LEN];
    hasher.finish(&mut offline_hash);

    let mut hasher = H::new();
    hasher.update(domain::BUNDLE_SALT);
    hasher.update(buf);

    let mut bundle_hash = [0; BUNDLE_HASH_LEN];
    hasher.finish(&mut bundle_hash);

    (offline_hash, bundle_hash)
}

impl<P: PublicSigningKey, S: SecretSigningKey> std::ops::Deref for SecretBundle<P, S> {
    type Target = AuthenticBundle<P>;

    fn deref(&self) -> &Self::Target {
        &self.public_bundle
    }
}

impl<P: PublicSigningKey, S: SecretSigningKey> SecretBundle<P, S> {
    pub fn update<K: SecretSigningKey, H: Hasher>(
        &self,
        offline_secret_key: K,
        online_secret_key: S,
        online_key: P,
        not_before: u64,
        not_after: u64,
        flags: u32,
        extensions: Box<[u8]>,
    ) -> Self {
        Self::new::<K, H>(
            offline_secret_key,
            online_secret_key,
            self.public_bundle_bytes[OFFLINE_KEY_RANGE].try_into().unwrap(),
            online_key,
            not_before,
            not_after,
            self.counter + 1,
            flags,
            extensions,
        )
    }

    pub fn new<K: SecretSigningKey, H: Hasher>(
        offline_secret_key: K,
        online_secret_key: S,
        offline_public_key: [u8; PUBLIC_KEY_LEN],
        online_key: P,
        not_before: u64,
        not_after: u64,
        counter: u32,
        flags: u32,
        extensions: Box<[u8]>,
    ) -> Self {
        let offline_sign_start = EXTENSIONS_START + extensions.len();
        let offline_sign_end = offline_sign_start + OFFLINE_SIGN_LEN;

        let mut buf = vec![0; offline_sign_end];

        buf[VERSION_IDX] = VERSION_VALUE;
        buf[OFFLINE_KEY_RANGE].copy_from_slice(&offline_public_key);
        buf[ONLINE_KEY_RANGE].copy_from_slice(&online_key.encode());
        buf[NOT_BEFORE_RANGE].copy_from_slice(&not_before.to_be_bytes());
        buf[NOT_AFTER_RANGE].copy_from_slice(&not_after.to_be_bytes());
        buf[COUNTER_RANGE].copy_from_slice(&counter.to_be_bytes());
        buf[FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        buf[EXTENSIONS_LEN_RANGE].copy_from_slice(&(extensions.len() as u32).to_be_bytes());

        buf[EXTENSIONS_START..offline_sign_start].copy_from_slice(&extensions);

        let sign = offline_secret_key.sign(domain::OFFLINE_KEY_CERTIFICATION, &buf[..offline_sign_start]);
        buf[offline_sign_start..offline_sign_end].copy_from_slice(&sign);

        let (offline_hash, bundle_hash) = hash_bundle::<H>(&buf[..]);

        Self {
            online_secret_key,
            public_bundle_bytes: buf.into(),
            public_bundle: AuthenticBundle {
                offline_hash,
                bundle_hash,
                online_key,
                counter,
                not_before,
                not_after,
                flags,
                extensions,
            },
        }
    }

    /// This function does not check if this key bundle is expired or post-dated.
    pub fn sign(&self, ctx: &[u8], data: &[u8]) -> [u8; SIGN_LEN] {
        self.online_secret_key.sign(ctx, data)
    }

    pub fn online_secret_key(&self) -> &S {
        &self.online_secret_key
    }

    pub fn public_bundle_bytes(&self) -> &[u8] {
        &self.public_bundle_bytes
    }
}

impl<P: PublicSigningKey> AuthenticBundle<P> {
    pub fn authenticate<H: Hasher>(buf: &[u8]) -> Result<(Self, usize), AuthError> {
        Self::authenticate_with_time::<H>(buf, get_secs_since_unix_epoch())
    }

    pub fn authenticate_with_time<H: Hasher>(
        buf: &[u8],
        secs_since_unix_epoch: u64,
    ) -> Result<(Self, usize), AuthError> {
        if buf[VERSION_IDX] != VERSION_VALUE {
            return Err(AuthError::UnrecognizedVersion);
        }

        let not_before = u64::from_be_bytes(buf[NOT_BEFORE_RANGE].try_into().unwrap());
        let not_after = u64::from_be_bytes(buf[NOT_AFTER_RANGE].try_into().unwrap());
        let counter = u32::from_be_bytes(buf[COUNTER_RANGE].try_into().unwrap());
        let flags = u32::from_be_bytes(buf[FLAGS_RANGE].try_into().unwrap());
        let extensions_len = u32::from_be_bytes(buf[EXTENSIONS_LEN_RANGE].try_into().unwrap()) as usize;
        let offline_sign_start = EXTENSIONS_START + extensions_len;
        let offline_sign_end = offline_sign_start + OFFLINE_SIGN_LEN;

        if secs_since_unix_epoch < not_before {
            return Err(AuthError::PostdatedKey);
        } else if secs_since_unix_epoch > not_after {
            return Err(AuthError::ExpiredKey);
        }

        let offline_key = P::decode(buf[OFFLINE_KEY_RANGE].try_into().unwrap());

        let auth = offline_key.verify(
            domain::OFFLINE_KEY_CERTIFICATION,
            &buf[..offline_sign_start],
            (&buf[offline_sign_start..offline_sign_end]).try_into().unwrap(),
        );
        if !auth {
            return Err(AuthError::Inauthentic);
        }

        let online_key = P::decode(buf[ONLINE_KEY_RANGE].try_into().unwrap());

        let extensions = Box::from(&buf[EXTENSIONS_START..offline_sign_start]);

        let (offline_hash, bundle_hash) = hash_bundle::<H>(&buf[..offline_sign_end]);

        Ok((
            AuthenticBundle {
                offline_hash,
                bundle_hash,
                online_key,
                counter,
                not_before,
                not_after,
                flags,
                extensions,
            },
            offline_sign_end,
        ))
    }

    /// `secs_since_unix_epoch` must be clamped to zero in the event that this system reports a
    /// time which is earlier than unix epoch.
    pub fn verify_with_time(
        &self,
        ctx: &[u8],
        data: &[u8],
        signature: &[u8; SIGN_LEN],
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

    pub fn verify(&self, ctx: &[u8], data: &[u8], signature: &[u8; SIGN_LEN]) -> Result<(), AuthError> {
        self.verify_with_time(ctx, data, signature, get_secs_since_unix_epoch())
    }

    pub fn offline_eq_raw(&self, other: &OfflineHash) -> bool {
        constant_time_eq_n(&self.offline_hash, other)
    }
    pub fn bundle_eq_raw(&self, other: &BundleHash) -> bool {
        constant_time_eq_32(&self.bundle_hash, other)
    }

    pub fn offline_eq(&self, other: &Self) -> bool {
        self.offline_eq_raw(other.offline_hash())
    }
    pub fn bundle_eq(&self, other: &Self) -> bool {
        self.bundle_eq_raw(other.bundle_hash())
    }

    pub fn offline_hash(&self) -> &OfflineHash {
        &self.offline_hash
    }
    pub fn bundle_hash(&self) -> &BundleHash {
        &self.bundle_hash
    }
    pub fn online_key(&self) -> &P {
        &self.online_key
    }
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    pub fn counter(&self) -> u32 {
        self.counter
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn extensions(&self) -> &[u8] {
        &self.extensions
    }
}
