//! X-Wing, the hybrid KEM of suite `0x0001` (ML-KEM-768 + X25519).
//!
//! A thin, array-typed wrapper around the RustCrypto `x-wing` crate. Secret
//! keys are 32-byte seeds; encapsulation is deterministic in 64 bytes of
//! caller-supplied randomness, which must be fresh and uniform every time.

use x_wing::{
    DecapsulationKeyRejectNonContrib, Decapsulator, EncapsulationKey, KeyExport, TryDecapsulate,
};

use crate::{Error, Result};

pub const PUBLIC_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
pub const CIPHERTEXT_LEN: usize = x_wing::CIPHERTEXT_SIZE;
pub const SEED_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
pub const ENTROPY_LEN: usize = x_wing::ENCAPSULATION_RANDOMNESS_SIZE;
pub const SHARED_LEN: usize = 32;

/// A decapsulation key, expanded from its seed, with its public half cached.
///
/// Decapsulation rejects X25519 points that contribute nothing to the shared
/// secret, so a sender cannot quietly disable the classical half.
pub struct SecretKey {
    inner: DecapsulationKeyRejectNonContrib,
    public: [u8; PUBLIC_LEN],
}

impl SecretKey {
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let inner = DecapsulationKeyRejectNonContrib::from(*seed);
        let mut public = [0u8; PUBLIC_LEN];
        public.copy_from_slice(&inner.encapsulation_key().to_bytes());
        Self { inner, public }
    }

    pub fn public(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }

    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_LEN]) -> Result<[u8; SHARED_LEN]> {
        let ciphertext = x_wing::Ciphertext::from(*ciphertext);
        let shared = self
            .inner
            .try_decapsulate(&ciphertext)
            .map_err(|_| Error::Decrypt)?;
        Ok(shared.into())
    }
}

/// Encapsulate to `public` using 64 bytes of fresh randomness.
pub fn encapsulate(
    public: &[u8; PUBLIC_LEN],
    entropy: &[u8; ENTROPY_LEN],
) -> Result<([u8; CIPHERTEXT_LEN], [u8; SHARED_LEN])> {
    let key = EncapsulationKey::try_from(public.as_slice()).map_err(|_| Error::BadKey)?;
    let (ciphertext, shared) = key.encapsulate_deterministic(&(*entropy).into());
    Ok((ciphertext.into(), shared.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_then_decapsulate_agree() {
        let secret = SecretKey::from_seed(&[1; 32]);
        let (ct, sent) = encapsulate(secret.public(), &[2; 64]).unwrap();
        assert_eq!(secret.decapsulate(&ct).unwrap(), sent);
    }

    #[test]
    fn other_key_gets_a_different_secret() {
        let secret = SecretKey::from_seed(&[1; 32]);
        let other = SecretKey::from_seed(&[3; 32]);
        let (ct, sent) = encapsulate(secret.public(), &[2; 64]).unwrap();
        assert_ne!(other.decapsulate(&ct).unwrap(), sent);
    }

    #[test]
    fn rejects_non_contributory_x25519_share() {
        let secret = SecretKey::from_seed(&[1; 32]);
        let (mut ct, _) = encapsulate(secret.public(), &[2; 64]).unwrap();
        ct[CIPHERTEXT_LEN - 32..].fill(0);
        assert_eq!(secret.decapsulate(&ct), Err(Error::Decrypt));
    }

    #[test]
    fn sizes_match_the_suite_table() {
        let secret = SecretKey::from_seed(&[0; 32]);
        let (ct, shared) = encapsulate(secret.public(), &[0; 64]).unwrap();
        assert_eq!(
            (secret.public().len(), ct.len(), shared.len()),
            (1216, 1120, 32)
        );
    }

    #[test]
    fn rejects_a_malformed_public_key() {
        // An ML-KEM encoding with every coefficient out of range.
        assert_eq!(
            encapsulate(&[0xff; PUBLIC_LEN], &[0; 64]).err(),
            Some(Error::BadKey)
        );
    }
}
