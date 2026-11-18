//! Stamps (spec section 7): proof of work a receiver can demand before it
//! stores anything.

use crate::envelope::EID_LEN;
use crate::kdf::kdf;
use crate::{Error, Result};

pub const STAMP_LEN: usize = 10;
/// Plain BLAKE3 hashing. The field exists so a memory-hard function can
/// replace it without changing the frame.
pub const ALG_BLAKE3: u8 = 1;
/// Above this a stamp is not a realistic demand on a browser.
pub const MAX_BITS: u8 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Leading zero bits the stamp claims.
    pub bits: u8,
    pub nonce: u64,
}

impl Stamp {
    pub fn encode(&self) -> [u8; STAMP_LEN] {
        let mut out = [0u8; STAMP_LEN];
        out[0] = ALG_BLAKE3;
        out[1] = self.bits;
        out[2..].copy_from_slice(&self.nonce.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; STAMP_LEN] = bytes.try_into().map_err(|_| Error::Malformed("stamp"))?;
        if bytes[0] != ALG_BLAKE3 {
            return Err(Error::Unsupported("stamp algorithm"));
        }
        Ok(Self {
            bits: bytes[1],
            nonce: u64::from_be_bytes(bytes[2..].try_into().expect("8 bytes")),
        })
    }

    /// Is this stamp valid for `eid` and at least as strong as `required`?
    pub fn verify(&self, eid: &[u8; EID_LEN], required: u8) -> bool {
        self.bits >= required && zero_bits(eid, self.nonce) >= self.bits as u32
    }
}

fn zero_bits(eid: &[u8; EID_LEN], nonce: u64) -> u32 {
    let digest = kdf("sayso/v1/stamp", &[eid, &nonce.to_be_bytes()]);
    let head = u64::from_be_bytes(digest[..8].try_into().expect("8 of 32"));
    head.leading_zeros()
}

/// Try `attempts` nonces starting at `start`. Returns the stamp if one of
/// them works; otherwise the caller continues from `start + attempts`, which
/// lets a browser yield between batches.
pub fn search(eid: &[u8; EID_LEN], bits: u8, start: u64, attempts: u64) -> Result<Option<Stamp>> {
    if bits > MAX_BITS {
        return Err(Error::Invalid("stamp difficulty"));
    }
    for nonce in start..start.saturating_add(attempts) {
        if zero_bits(eid, nonce) >= bits as u32 {
            return Ok(Some(Stamp { bits, nonce }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_stamp_verifies_for_its_envelope_only() {
        let eid = [3u8; 32];
        let stamp = search(&eid, 12, 0, 1 << 20)
            .unwrap()
            .expect("12 bits within a million tries");
        assert!(stamp.verify(&eid, 12));
        assert!(
            stamp.verify(&eid, 8),
            "a stronger stamp satisfies a weaker demand"
        );
        assert!(!stamp.verify(&eid, 13));
        assert!(!stamp.verify(&[4u8; 32], 12));
    }

    #[test]
    fn claimed_bits_must_be_real() {
        let eid = [3u8; 32];
        let stamp = search(&eid, 8, 0, 1 << 16).unwrap().unwrap();
        let inflated = Stamp {
            bits: 30,
            nonce: stamp.nonce,
        };
        assert!(!inflated.verify(&eid, 8));
    }

    #[test]
    fn search_resumes_in_batches() {
        let eid = [5u8; 32];
        let whole = search(&eid, 10, 0, 1 << 20).unwrap().unwrap();
        let mut start = 0;
        let batched = loop {
            if let Some(stamp) = search(&eid, 10, start, 64).unwrap() {
                break stamp;
            }
            start += 64;
        };
        assert_eq!(whole, batched);
    }

    #[test]
    fn encoding_round_trips_and_is_strict() {
        let stamp = Stamp {
            bits: 16,
            nonce: 0x0102030405060708,
        };
        assert_eq!(stamp.encode(), [1, 16, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(Stamp::decode(&stamp.encode()).unwrap(), stamp);
        assert!(Stamp::decode(&[2, 16, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(Stamp::decode(&[1, 16]).is_err());
        assert!(search(&[0; 32], MAX_BITS + 1, 0, 1).is_err());
    }
}
