use core::fmt;

/// Everything that can go wrong in the core. Variants are deliberately coarse:
/// a caller facing an attacker should not learn which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bytes do not parse as the expected structure.
    Malformed(&'static str),
    /// A version, kind or suite this implementation does not speak.
    Unsupported(&'static str),
    /// A public key is invalid, or the envelope was sealed to a different key.
    BadKey,
    /// Authenticated decryption failed.
    Decrypt,
    /// A signature does not verify.
    BadSignature,
    /// The signature is valid but from someone other than the expected signer.
    WrongSigner,
    /// The value exceeds a protocol limit.
    TooLarge,
    /// A credential is past its validity.
    Expired,
    /// A value is well-formed but breaks a protocol rule.
    Invalid(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::Unsupported(what) => write!(f, "unsupported {what}"),
            Error::BadKey => f.write_str("wrong or invalid key"),
            Error::Decrypt => f.write_str("decryption failed"),
            Error::BadSignature => f.write_str("signature does not verify"),
            Error::WrongSigner => f.write_str("signed by an unexpected key"),
            Error::TooLarge => f.write_str("too large"),
            Error::Expired => f.write_str("expired"),
            Error::Invalid(what) => write!(f, "invalid {what}"),
        }
    }
}

impl core::error::Error for Error {}
