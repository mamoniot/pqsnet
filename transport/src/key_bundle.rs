use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::CryptoRng;

use crate::{crypto::mldsa87::*, protocol::{domains::OFFLINE_KEY_CERTIFICATION_DOMAIN_NAME, key_bundle::*}};

pub struct AuthenticOnlineKey<P: PublicSigningKey> {
    online_key: P,
    variant: u8,
    uid: u128,
    not_before: u64,
    not_after: u64,
}

pub enum AuthError {
    InvalidSignature,
    ExpiredKey,
    PostDatedKey,
}

impl<P: PublicSigningKey> AuthenticOnlineKey<P> {
    pub fn authenticate(bundle_bytes: &[u8]) -> Result<Self, AuthError> {
        let secs_since_unix_epoch = SystemTime::now().duration_since(UNIX_EPOCH).as_ref().map_or(0, Duration::as_secs);
        Self::authenticate_with_time(bundle_bytes, secs_since_unix_epoch)
    }
    pub fn authenticate_with_time(bundle_bytes: &[u8], secs_since_unix_epoch: u64) -> Result<Self, AuthError> {
        if bundle_bytes.len() < KEY_BUNDLE_LEN {
            return Err(AuthError::InvalidSignature);
        }

        let not_before = u64::from_be_bytes(bundle_bytes[NOT_BEFORE_SECS_RANGE].try_into().unwrap());
        let not_after = u64::from_be_bytes(bundle_bytes[NOT_AFTER_SECS_RANGE].try_into().unwrap());

        let variant = bundle_bytes[HANDSHAKE_VARIANT_IDX];
        let uid = u128::from_be_bytes(bundle_bytes[UID_RANGE].try_into().unwrap());

        if secs_since_unix_epoch < not_before {
            return Err(AuthError::PostDatedKey);
        } else if secs_since_unix_epoch > not_after {
            return Err(AuthError::ExpiredKey);
        }

        let offline_key = P::decode((&bundle_bytes[OFFLINE_PUBLIC_KEY_RANGE]).try_into().unwrap());
        let online_key = P::decode((&bundle_bytes[ONLINE_PUBLIC_KEY_RANGE]).try_into().unwrap());

        offline_key.verify(OFFLINE_KEY_CERTIFICATION_DOMAIN_NAME, &bundle_bytes[SIGNED_DATA_RANGE], (&bundle_bytes[OFFLINE_SIGNATURE_RANGE]).try_into().unwrap());

        Ok(Self {
            online_key,
            variant,
            uid,
            not_before,
            not_after,
        })
    }

    pub fn encode_online_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.online_key.encode()
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
            Err(AuthError::PostDatedKey)
        } else if secs_since_unix_epoch > self.not_after {
            Err(AuthError::ExpiredKey)
        } else if !self.online_key.verify(ctx, data, signature) {
            Err(AuthError::InvalidSignature)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn verify(
        &self,
        ctx: &[u8],
        data: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<(), AuthError> {
        // An `Err` is only returned if the systen time is set before unix epoch. In this case we
        // will only attempt signature verification if `self.not_before == 0`.
        let secs_since_unix_epoch = SystemTime::now().duration_since(UNIX_EPOCH).as_ref().map_or(0, Duration::as_secs);
        self.verify_with_time(ctx, data, signature, secs_since_unix_epoch)
    }

    pub fn uid(&self) -> u128 {
        self.uid
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

pub fn create_bundle_bytes<R: CryptoRng, K: PrivateSigningKey>(
    rng: &mut R,
    offline_private_key: K,
    offline_public_key: [u8; PUBLIC_KEY_LEN],
    online_public_key: [u8; PUBLIC_KEY_LEN],
    require_full_auth: bool,
    disallow_fallback: bool,
    not_before: u64,
    not_after: u64,
) -> [u8; KEY_BUNDLE_LEN] {
    let mut bundle_bytes = [0; KEY_BUNDLE_LEN];
    bundle_bytes[OFFLINE_PUBLIC_KEY_RANGE].copy_from_slice(&offline_public_key);
    bundle_bytes[ONLINE_PUBLIC_KEY_RANGE].copy_from_slice(&online_public_key);

    rng.fill_bytes(&mut bundle_bytes[UID_RANGE]);
    bundle_bytes[NOT_BEFORE_SECS_RANGE].copy_from_slice(&not_before.to_be_bytes());
    bundle_bytes[NOT_AFTER_SECS_RANGE].copy_from_slice(&not_after.to_be_bytes());

    // TODO: Constant
    bundle_bytes[HANDSHAKE_VARIANT_IDX] = (disallow_fallback as u8) << 1 | (require_full_auth as u8);

    let signature = offline_private_key.sign(
        OFFLINE_KEY_CERTIFICATION_DOMAIN_NAME,
        &bundle_bytes[OFFLINE_PUBLIC_KEY_RANGE]
    );
    bundle_bytes[OFFLINE_SIGNATURE_RANGE].copy_from_slice(&signature);
    bundle_bytes
}
