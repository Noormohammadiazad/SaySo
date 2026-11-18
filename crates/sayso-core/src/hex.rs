use crate::{Error, Result};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Strict lower-case hex: no prefix, no upper case, even length.
pub fn from_hex(text: &str) -> Result<Vec<u8>> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(Error::Malformed("hex"));
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::Malformed("hex")),
    };
    raw.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abff").unwrap(), vec![0x00, 0xab, 0xff]);
        assert!(from_hex("0").is_err());
        assert!(from_hex("AB").is_err());
        assert!(from_hex("zz").is_err());
    }
}
