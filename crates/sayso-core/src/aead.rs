//! ChaCha20-Poly1305, in the two shapes the protocol uses.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::{Error, Result};

pub const TAG_LEN: usize = 16;

/// RFC 8439 AEAD. The caller guarantees `(key, nonce)` is never reused.
pub(crate) fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(nonce.into(), Payload { msg, aad })
        .expect("message length is far below the cipher's limit")
}

pub(crate) fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), Payload { msg: sealed, aad })
        .map_err(|_| Error::Decrypt)
}

/// Encrypt a record for storage on the device that holds `key`: the owner's
/// keystore and archive, or a sender's history.
///
/// `nonce` must be 24 fresh random bytes; with that size a long-lived key can
/// seal an unbounded number of records. Output is `nonce || ciphertext`.
pub fn wrap(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let sealed = XChaCha20Poly1305::new(key.into())
        .encrypt(nonce.into(), Payload { msg, aad })
        .expect("message length is far below the cipher's limit");
    let mut out = Vec::with_capacity(24 + sealed.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    out
}

/// Inverse of [`wrap`].
pub fn unwrap(key: &[u8; 32], aad: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 24 + TAG_LEN {
        return Err(Error::Malformed("wrapped record"));
    }
    let (nonce, sealed) = wrapped.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().expect("split at 24");
    XChaCha20Poly1305::new(key.into())
        .decrypt((&nonce).into(), Payload { msg: sealed, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_matches_rfc_8439_vector() {
        // RFC 8439 section 2.8.2.
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = [
            0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let msg = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = seal(&key, &nonce, &aad, msg);
        assert_eq!(
            crate::to_hex(&sealed[sealed.len() - 16..]),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(crate::to_hex(&sealed[..8]), "d31a8d34648e60db");
        assert_eq!(open(&key, &nonce, &aad, &sealed).unwrap(), msg);
    }

    #[test]
    fn any_change_fails_to_open() {
        let sealed = seal(&[1; 32], &[2; 12], b"aad", b"message");
        let mut flipped = sealed.clone();
        flipped[0] ^= 1;
        assert_eq!(
            open(&[1; 32], &[2; 12], b"aad", &flipped),
            Err(Error::Decrypt)
        );
        assert_eq!(
            open(&[1; 32], &[2; 12], b"aae", &sealed),
            Err(Error::Decrypt)
        );
        assert_eq!(
            open(&[9; 32], &[2; 12], b"aad", &sealed),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn wrap_round_trips_and_binds_its_label() {
        let wrapped = wrap(&[1; 32], &[2; 24], b"epoch:7", b"secret seed");
        assert_eq!(
            unwrap(&[1; 32], b"epoch:7", &wrapped).unwrap(),
            b"secret seed"
        );
        assert_eq!(unwrap(&[1; 32], b"epoch:8", &wrapped), Err(Error::Decrypt));
        assert!(unwrap(&[1; 32], b"epoch:7", &wrapped[..30]).is_err());
    }
}
