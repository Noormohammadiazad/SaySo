//! Key hierarchy (spec section 2).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use crate::kdf::kdf;
use crate::xwing;
use crate::{Error, Result};

pub const ID_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const THREAD_ID_LEN: usize = 16;

/// The owner's long-term keys, all derived from `root`.
///
/// Epoch secrets are deliberately absent: they are random, stored separately
/// and destroyed on schedule.
pub struct OwnerKeys {
    signing: SigningKey,
    oik: [u8; ID_LEN],
    store_key: [u8; 32],
}

impl OwnerKeys {
    pub fn from_root(root: &[u8; 32]) -> Self {
        let mut seed = kdf("sayso/v1/owner/ident", &[root]);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self {
            oik: signing.verifying_key().to_bytes(),
            signing,
            store_key: kdf("sayso/v1/owner/store", &[root]),
        }
    }

    /// The owner identity key: the public trust anchor senders pin.
    pub fn oik(&self) -> &[u8; ID_LEN] {
        &self.oik
    }

    /// Wraps epoch secrets and the local archive at rest.
    pub fn store_key(&self) -> &[u8; 32] {
        &self.store_key
    }

    /// Secret key of the transport endpoint for receiver slot `slot`
    /// (0 is the dashboard). It authenticates a receiver, never a payload.
    pub fn wire_secret(root: &[u8; 32], slot: u32) -> [u8; 32] {
        kdf("sayso/v1/owner/wire", &[root, &slot.to_be_bytes()])
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

impl Drop for OwnerKeys {
    fn drop(&mut self) {
        self.store_key.zeroize();
    }
}

/// Everything a sender needs for one owner, derived from one 32-byte seed.
pub struct SenderKeys {
    signing: SigningKey,
    sid: [u8; ID_LEN],
    reply: xwing::SecretKey,
    tag_key: [u8; 32],
    local_key: [u8; 32],
    oik: [u8; ID_LEN],
}

impl SenderKeys {
    pub fn derive(seed: &[u8; 32], oik: &[u8; ID_LEN]) -> Self {
        let mut ident = kdf("sayso/v1/sender/ident", &[seed, oik]);
        let mut reply = kdf("sayso/v1/sender/reply", &[seed, oik]);
        let signing = SigningKey::from_bytes(&ident);
        let keys = Self {
            sid: signing.verifying_key().to_bytes(),
            signing,
            reply: xwing::SecretKey::from_seed(&reply),
            tag_key: kdf("sayso/v1/sender/tag", &[seed, oik]),
            local_key: kdf("sayso/v1/sender/local", &[seed, oik]),
            oik: *oik,
        };
        ident.zeroize();
        reply.zeroize();
        keys
    }

    /// The sender's pseudonymous identity towards this owner.
    pub fn sid(&self) -> &[u8; ID_LEN] {
        &self.sid
    }

    pub fn oik(&self) -> &[u8; ID_LEN] {
        &self.oik
    }

    pub fn reply_public(&self) -> &[u8; xwing::PUBLIC_LEN] {
        self.reply.public()
    }

    pub(crate) fn reply_secret(&self) -> &xwing::SecretKey {
        &self.reply
    }

    /// Derives the reply mailbox addresses; shared with the owner in `hello`.
    pub fn tag_key(&self) -> &[u8; 32] {
        &self.tag_key
    }

    /// Encrypts the sender's own history in browser storage.
    pub fn local_key(&self) -> &[u8; 32] {
        &self.local_key
    }

    pub fn thread_id(&self) -> [u8; THREAD_ID_LEN] {
        thread_id(&self.sid, &self.oik)
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

impl Drop for SenderKeys {
    fn drop(&mut self) {
        self.tag_key.zeroize();
        self.local_key.zeroize();
    }
}

/// `KeyId(pk)`: names a KEM public key without revealing it.
pub fn key_id(public: &[u8]) -> [u8; 32] {
    kdf("sayso/v1/key-id", &[public])
}

/// The thread between one sender identity and one owner.
pub fn thread_id(sid: &[u8; ID_LEN], oik: &[u8; ID_LEN]) -> [u8; THREAD_ID_LEN] {
    let mut out = [0u8; THREAD_ID_LEN];
    out.copy_from_slice(&kdf("sayso/v1/thread", &[sid, oik])[..THREAD_ID_LEN]);
    out
}

/// A short form of an identity key for people to compare out of band:
/// eight groups of four hex digits.
pub fn fingerprint(identity: &[u8; ID_LEN]) -> String {
    let digest = kdf("sayso/v1/fingerprint", &[identity]);
    let hex = crate::to_hex(&digest[..16]);
    hex.as_bytes()
        .chunks(4)
        .map(|group| core::str::from_utf8(group).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Strict Ed25519 verification: rejects non-canonical and small-order inputs.
pub(crate) fn verify(public: &[u8; ID_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::BadKey)?;
    key.verify_strict(message, &Signature::from_bytes(sig))
        .map_err(|_| Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_keys_are_bound_to_the_owner() {
        let seed = [9u8; 32];
        let a = SenderKeys::derive(&seed, &[1; 32]);
        let b = SenderKeys::derive(&seed, &[2; 32]);
        assert_ne!(a.sid(), b.sid());
        assert_ne!(a.tag_key(), b.tag_key());
        assert_ne!(a.reply_public(), b.reply_public());
        assert_ne!(a.thread_id(), b.thread_id());
    }

    #[test]
    fn derivation_is_stable() {
        let a = SenderKeys::derive(&[9; 32], &[1; 32]);
        let b = SenderKeys::derive(&[9; 32], &[1; 32]);
        assert_eq!(a.sid(), b.sid());
        assert_eq!(a.reply_public(), b.reply_public());
        assert_eq!(
            OwnerKeys::from_root(&[4; 32]).oik(),
            OwnerKeys::from_root(&[4; 32]).oik()
        );
    }

    #[test]
    fn owner_keys_are_independent_of_each_other() {
        let root = [4u8; 32];
        let owner = OwnerKeys::from_root(&root);
        assert_ne!(owner.oik(), owner.store_key());
        assert_ne!(
            OwnerKeys::wire_secret(&root, 0),
            OwnerKeys::wire_secret(&root, 1)
        );
    }

    #[test]
    fn signatures_verify_strictly() {
        let owner = OwnerKeys::from_root(&[4; 32]);
        let sig = owner.sign(b"hello");
        assert!(verify(owner.oik(), b"hello", &sig).is_ok());
        assert_eq!(
            verify(owner.oik(), b"hellp", &sig),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn fingerprint_is_eight_groups() {
        let text = fingerprint(&[7; 32]);
        assert_eq!(text.split(' ').count(), 8);
        assert_eq!(text.len(), 39);
    }
}
