//! Verified senders (spec section 8): a credential the owner signs for one
//! sender identity, at any time after that sender first wrote. It says "the
//! owner knows `sid` as `label`" and is sent to that sender inside a reply.

use minicbor::bytes::ByteArray;
use minicbor::{Decode, Encode};

use crate::keys::{self, ID_LEN, OwnerKeys, SIG_LEN};
use crate::{Error, Result};

pub const MAX_LABEL: usize = 64;
const CONTEXT: &[u8] = b"sayso/v1/verified";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Verification {
    /// The sender identity the owner vouches for.
    #[n(1)]
    pub sid: ByteArray<ID_LEN>,
    /// The owner's name for that sender.
    #[n(2)]
    pub label: String,
    /// Unix seconds when the owner issued it.
    #[n(3)]
    pub issued: u64,
}

/// Sign a verification of `sid` under `label`.
pub fn mint(owner: &OwnerKeys, sid: &[u8; ID_LEN], label: &str, issued: u64) -> Result<Vec<u8>> {
    if label.len() > MAX_LABEL {
        return Err(Error::TooLarge);
    }
    let body = minicbor::to_vec(Verification {
        sid: (*sid).into(),
        label: label.into(),
        issued,
    })
    .expect("encoding to a Vec cannot fail");
    let sig = owner.sign(&[CONTEXT, &body].concat());
    Ok([&sig[..], &body].concat())
}

/// Check a verification against the owner identity and the sender it must name.
pub fn verify(oik: &[u8; ID_LEN], credential: &[u8], sid: &[u8; ID_LEN]) -> Result<Verification> {
    let (sig, body) = credential
        .split_first_chunk::<SIG_LEN>()
        .ok_or(Error::Malformed("verification"))?;
    keys::verify(oik, &[CONTEXT, body].concat(), sig)?;
    let mut decoder = minicbor::Decoder::new(body);
    let parsed: Verification = decoder
        .decode()
        .map_err(|_| Error::Malformed("verification"))?;
    if decoder.position() != body.len() || parsed.label.len() > MAX_LABEL {
        return Err(Error::Malformed("verification"));
    }
    if &*parsed.sid != sid {
        return Err(Error::Invalid("verification is for another sender"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_and_verify_for_one_sender_only() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let cred = mint(&owner, &[5; 32], "Ada", 1_794_300_000).unwrap();
        let parsed = verify(owner.oik(), &cred, &[5; 32]).unwrap();
        assert_eq!(parsed.label, "Ada");
        assert_eq!(parsed.issued, 1_794_300_000);
        assert_eq!(
            verify(owner.oik(), &cred, &[6; 32]),
            Err(Error::Invalid("verification is for another sender"))
        );
        let other = OwnerKeys::from_root(&[2; 32]);
        assert_eq!(
            verify(other.oik(), &cred, &[5; 32]),
            Err(Error::BadSignature)
        );
        assert!(mint(&owner, &[5; 32], &"x".repeat(MAX_LABEL + 1), 1).is_err());
    }
}
