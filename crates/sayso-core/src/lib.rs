//! Sayso formats and cryptography.
//!
//! This crate is the reference implementation of `docs/PROTOCOL.md`. It does
//! no I/O, reads no clock and draws no randomness: callers pass in the time
//! and the random bytes, which keeps every function deterministic and lets the
//! same code run in a browser, in the courier and in tests.

#![forbid(unsafe_code)]

pub mod aead;
pub mod buffer;
pub mod doc;
pub mod envelope;
pub mod epoch;
pub mod error;
pub mod file;
pub mod invite;
pub mod kdf;
pub mod keys;
pub mod mailbox;
pub mod payload;
pub mod stamp;
pub mod verified;
pub mod xwing;

mod hex;

pub use error::{Error, Result};
pub use hex::{from_hex, to_hex};
