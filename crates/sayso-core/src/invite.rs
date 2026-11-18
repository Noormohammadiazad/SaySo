//! Invites (spec section 8): bearer credentials the owner hands out so a
//! sender's thread shows as verified.

use minicbor::bytes::ByteArray;
use minicbor::{Decode, Encode};

use crate::keys::{self, ID_LEN, OwnerKeys, SIG_LEN};
use crate::{Error, Result};

pub const INVITE_ID_LEN: usize = 16;
pub const MAX_LABEL: usize = 64;

const CONTEXT: &[u8] = b"sayso/v1/invite";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Invite {
    #[n(1)]
    pub id: ByteArray<INVITE_ID_LEN>,
    /// The owner's name for whoever holds this invite.
    #[n(2)]
    pub label: String,
    /// Unix seconds after which the invite is refused.
    #[n(3)]
    pub not_after: u64,
}

/// Sign an invite. `id` must be 16 fresh random bytes.
pub fn mint(
    owner: &OwnerKeys,
    id: [u8; INVITE_ID_LEN],
    label: &str,
    not_after: u64,
) -> Result<Vec<u8>> {
    if label.len() > MAX_LABEL {
        return Err(Error::TooLarge);
    }
    let body = minicbor::to_vec(Invite {
        id: id.into(),
        label: label.into(),
        not_after,
    })
    .expect("encoding to a Vec cannot fail");
    let sig = owner.sign(&[CONTEXT, &body].concat());
    Ok([&sig[..], &body].concat())
}

/// Check an invite presented at `now` against the owner identity.
pub fn verify(oik: &[u8; ID_LEN], invite: &[u8], now: u64) -> Result<Invite> {
    let (sig, body) = invite
        .split_first_chunk::<SIG_LEN>()
        .ok_or(Error::Malformed("invite"))?;
    keys::verify(oik, &[CONTEXT, body].concat(), sig)?;
    let mut decoder = minicbor::Decoder::new(body);
    let parsed: Invite = decoder.decode().map_err(|_| Error::Malformed("invite"))?;
    if decoder.position() != body.len() || parsed.label.len() > MAX_LABEL {
        return Err(Error::Malformed("invite"));
    }
    if now > parsed.not_after {
        return Err(Error::Expired);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_and_verify() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let invite = mint(&owner, [2; 16], "Ada from the lab", 2_000).unwrap();
        let parsed = verify(owner.oik(), &invite, 1_999).unwrap();
        assert_eq!(parsed.label, "Ada from the lab");
        assert_eq!(*parsed.id, [2; 16]);
        assert!(
            verify(owner.oik(), &invite, 2_000).is_ok(),
            "valid through its last second"
        );
        assert_eq!(verify(owner.oik(), &invite, 2_001), Err(Error::Expired));
    }

    #[test]
    fn forged_or_altered_invites_fail() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let other = OwnerKeys::from_root(&[9; 32]);
        let invite = mint(&owner, [2; 16], "Ada", 2_000).unwrap();
        assert_eq!(verify(other.oik(), &invite, 1), Err(Error::BadSignature));
        let mut altered = invite.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(verify(owner.oik(), &altered, 1), Err(Error::BadSignature));
        assert!(verify(owner.oik(), &invite[..40], 1).is_err());
        assert!(mint(&owner, [2; 16], &"x".repeat(MAX_LABEL + 1), 1).is_err());
    }
}
