use core::ops::Deref;

use crate::{
    crypto::{mldsa87::*, prelude::*}, error::AuthError, protocol::{domain, key_bundle::*},
};
use constant_time_eq::{constant_time_eq_32, constant_time_eq_n};

pub mod constants {
    pub use crate::protocol::key_bundle::*;
}

pub type OfflineHash = [u8; OFFLINE_HASH_LEN];

pub type BundleHash = [u8; BUNDLE_HASH_LEN];

pub struct AuthenticBundle<C: CryptoAndMem> {
    offline_hash: OfflineHash,
    bundle_hash: BundleHash,
    online_key: C::PublicKey,
    not_before: u64,
    not_after: u64,
    counter: u32,
    flags: u32,
    public_bytes: C::BundleMem,
}

pub struct SecretBundle<C: CryptoAndMem> {
    online_secret_key: C::SecretKey,
    public_bundle: AuthenticBundle<C>,
}

pub fn hash_bundle<H: Xof>(buf: &[u8]) -> (OfflineHash, BundleHash) {
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

impl<C: CryptoAndMem> Deref for SecretBundle<C> {
    type Target = AuthenticBundle<C>;

    fn deref(&self) -> &Self::Target {
        &self.public_bundle
    }
}

impl<C: CryptoAndMem> SecretBundle<C> {
    pub fn new<K: SecretKey>(
        offline_secret_key: K,
        online_secret_key: C::SecretKey,
        offline_public_key_bytes: [u8; PUBLIC_KEY_LEN],
        online_public_key: C::PublicKey,
        online_public_key_bytes: [u8; PUBLIC_KEY_LEN],
        not_before: u64,
        not_after: u64,
        counter: u32,
        flags: u32,
        extensions: &[u8],
        alloc: <C::BundleMem as Mem>::Alloc
    ) -> Self {
        let offline_sign_start = EXTENSIONS_START + extensions.len();
        let offline_sign_end = offline_sign_start + OFFLINE_SIGN_LEN;

        let mut buf = C::BundleMem::malloc(alloc, offline_sign_end).expect("memory allocation failed");

        buf[VERSION_IDX] = VERSION_VALUE;
        buf[OFFLINE_KEY_RANGE].copy_from_slice(&offline_public_key_bytes);
        buf[ONLINE_KEY_RANGE].copy_from_slice(&online_public_key_bytes);
        buf[NOT_BEFORE_RANGE].copy_from_slice(&not_before.to_be_bytes());
        buf[NOT_AFTER_RANGE].copy_from_slice(&not_after.to_be_bytes());
        buf[COUNTER_RANGE].copy_from_slice(&counter.to_be_bytes());
        buf[FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        buf[EXTENSIONS_LEN_RANGE].copy_from_slice(&(extensions.len() as u32).to_be_bytes());

        buf[EXTENSIONS_START..offline_sign_start].copy_from_slice(extensions);

        let sign = offline_secret_key.sign(domain::OFFLINE_KEY_CERTIFICATION, &buf[..offline_sign_start]);
        buf[offline_sign_start..offline_sign_end].copy_from_slice(&sign);

        let (offline_hash, bundle_hash) = hash_bundle::<C::Xof>(&buf[..]);

        Self {
            online_secret_key,
            public_bundle: AuthenticBundle {
                offline_hash,
                bundle_hash,
                online_key: online_public_key,
                counter,
                not_before,
                not_after,
                flags,
                public_bytes: buf,
            },
        }
    }

    /// This function does not check if this key bundle is expired or post-dated.
    pub fn sign(&self, ctx: &[u8], data: &[u8]) -> [u8; SIGN_LEN] {
        self.online_secret_key.sign(ctx, data)
    }

    pub fn online_secret_key(&self) -> &C::SecretKey {
        &self.online_secret_key
    }
}

impl<C: CryptoAndMem> AuthenticBundle<C> {
    pub fn authenticate(buf: &[u8], secs_since_unix_epoch: u64, alloc: <C::BundleMem as Mem>::Alloc) -> Result<Self, AuthError> {
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

        let offline_key =
            C::PublicKey::decode(buf[OFFLINE_KEY_RANGE].try_into().unwrap()).ok_or(AuthError::Inauthentic)?;

        let auth = offline_key.verify(
            domain::OFFLINE_KEY_CERTIFICATION,
            &buf[..offline_sign_start],
            (&buf[offline_sign_start..offline_sign_end]).try_into().unwrap(),
        );
        if !auth {
            return Err(AuthError::Inauthentic);
        }

        let online_key =
            C::PublicKey::decode(buf[ONLINE_KEY_RANGE].try_into().unwrap()).ok_or(AuthError::Inauthentic)?;

        let (offline_hash, bundle_hash) = hash_bundle::<C::Xof>(&buf[..offline_sign_end]);

        let mut bundle_bytes = C::BundleMem::malloc(alloc, offline_sign_end).ok_or(AuthError::AllocFailure)?;
        bundle_bytes.copy_from_slice(&buf[..offline_sign_end]);

        Ok(AuthenticBundle {
            offline_hash,
            bundle_hash,
            online_key,
            counter,
            not_before,
            not_after,
            flags,
            public_bytes: bundle_bytes,
        })
    }

    /// `secs_since_unix_epoch` must be clamped to zero in the event that this system reports a
    /// time which is earlier than unix epoch.
    pub fn verify(
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
    pub fn online_key(&self) -> &C::PublicKey {
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
    pub fn public_bytes(&self) -> &[u8] {
        &self.public_bytes[..]
    }
    pub fn extensions(&self) -> &[u8] {
        &self.public_bytes[EXTENSIONS_START..]
    }
}
