//! Key derivation and keyed hashing, both BLAKE3.
//!
//! Inputs are concatenated without length prefixes. That is sound here because
//! every call site passes fixed-length parts, with at most one variable-length
//! part in last position.

/// `KDF(ctx, ikm)` from the spec: BLAKE3 `derive_key` over the concatenated parts.
pub fn kdf(ctx: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ctx);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// `MAC(key, msg)` from the spec: BLAKE3 keyed hash over the concatenated parts.
pub fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Plain BLAKE3.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_separate_domains() {
        let a = kdf("sayso/v1/test/a", &[b"same"]);
        let b = kdf("sayso/v1/test/b", &[b"same"]);
        assert_ne!(a, b);
        assert_eq!(a, kdf("sayso/v1/test/a", &[b"sa", b"me"]));
    }
}
