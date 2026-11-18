//! The signed owner document on the data branch (spec section 10).
//!
//! The core signs and verifies the exact body bytes; parsing the JSON inside
//! them is the caller's job, after verification.

use crate::Result;
use crate::keys::{self, ID_LEN, OwnerKeys, SIG_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocKind {
    /// `owner.json`: who the owner is, the inbox parameters, the receivers
    /// and the epoch public keys senders seal to.
    Owner,
}

impl DocKind {
    fn context(self) -> &'static [u8] {
        match self {
            DocKind::Owner => b"sayso/v1/doc/owner",
        }
    }
}

pub fn sign(owner: &OwnerKeys, kind: DocKind, body: &[u8]) -> [u8; SIG_LEN] {
    owner.sign(&[kind.context(), body].concat())
}

pub fn verify(key: &[u8; ID_LEN], kind: DocKind, body: &[u8], sig: &[u8; SIG_LEN]) -> Result<()> {
    keys::verify(key, &[kind.context(), body].concat(), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn a_signature_covers_the_exact_body() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let body = br#"{"v":1}"#;
        let sig = sign(&owner, DocKind::Owner, body);
        assert!(verify(owner.oik(), DocKind::Owner, body, &sig).is_ok());
        assert_eq!(
            verify(owner.oik(), DocKind::Owner, br#"{"v":2}"#, &sig),
            Err(Error::BadSignature)
        );
        let other = OwnerKeys::from_root(&[2; 32]);
        assert_eq!(
            verify(other.oik(), DocKind::Owner, body, &sig),
            Err(Error::BadSignature)
        );
    }
}
