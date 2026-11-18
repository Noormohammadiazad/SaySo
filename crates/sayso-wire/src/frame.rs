//! Framing: `type (1) || u32(len) || body`.

use core::fmt;

use iroh::endpoint::{ReadExactError, RecvStream, SendStream};
use sayso_core::envelope::MAX_ENVELOPE;
use sayso_core::file::{HASH_LEN, MAX_CIPHER_CHUNK};
use sayso_core::stamp::STAMP_LEN;

use crate::Result;

pub(crate) const DROP: u8 = 0x01;
pub(crate) const PUT: u8 = 0x02;
pub(crate) const GET: u8 = 0x03;
pub(crate) const LISTEN: u8 = 0x04;
pub(crate) const CHUNK: u8 = 0x10;
pub(crate) const FIN: u8 = 0x11;
pub(crate) const REPLY: u8 = 0x20;
pub(crate) const SEEN: u8 = 0x21;
pub(crate) const ACK: u8 = 0x81;
pub(crate) const HAVE: u8 = 0x82;
pub(crate) const STORED: u8 = 0x83;
pub(crate) const META: u8 = 0x84;
pub(crate) const ERR: u8 = 0xFF;

/// The most chunks one file may have: 256 GiB at 1 MiB per chunk. Bounds the
/// leaf list a receiver has to hold in memory to 8 MiB.
pub const MAX_FILE_CHUNKS: u64 = 1 << 18;

/// Root, chunk count, total length.
pub(crate) const FILE_HEAD: usize = HASH_LEN + 8 + 8;
pub(crate) const MAX_DROP: usize = STAMP_LEN + MAX_ENVELOPE;
pub(crate) const MAX_FILE_META: usize = FILE_HEAD + MAX_FILE_CHUNKS as usize * HASH_LEN;
pub(crate) const MAX_CHUNK_FRAME: usize = 8 + MAX_CIPHER_CHUNK;
/// Small fixed-size answers: an id, an index, an error code.
pub(crate) const MAX_SHORT: usize = 64;

/// Why a receiver refused a request (`0xFF ERR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrCode {
    Malformed = 1,
    WeakStamp = 2,
    EpochNotAccepted = 3,
    TooLarge = 4,
    NotFound = 5,
    Busy = 6,
}

impl ErrCode {
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Malformed,
            2 => Self::WeakStamp,
            3 => Self::EpochNotAccepted,
            4 => Self::TooLarge,
            5 => Self::NotFound,
            6 => Self::Busy,
            _ => return None,
        })
    }
}

impl fmt::Display for ErrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed request",
            Self::WeakStamp => "stamp too weak",
            Self::EpochNotAccepted => "epoch not accepted",
            Self::TooLarge => "too large",
            Self::NotFound => "not found",
            Self::Busy => "receiver busy",
        })
    }
}

#[derive(Debug)]
pub enum WireError {
    /// The receiver could not be reached.
    Connect(String),
    /// The receiver did not answer in time: for a dialer, "not online".
    Timeout,
    /// The connection or stream ended.
    Closed(String),
    /// The peer broke the protocol.
    Protocol(&'static str),
    /// The receiver understood the request and said no.
    Refused(ErrCode),
    /// Data failed a check in the core.
    Core(sayso_core::Error),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(why) => write!(f, "could not connect: {why}"),
            Self::Timeout => f.write_str("no answer from the receiver"),
            Self::Closed(why) => write!(f, "connection closed: {why}"),
            Self::Protocol(what) => write!(f, "protocol error: {what}"),
            Self::Refused(code) => write!(f, "refused: {code}"),
            Self::Core(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for WireError {}

impl From<sayso_core::Error> for WireError {
    fn from(err: sayso_core::Error) -> Self {
        Self::Core(err)
    }
}

pub(crate) fn closed(err: impl fmt::Display) -> WireError {
    WireError::Closed(err.to_string())
}

pub(crate) async fn write_frame(send: &mut SendStream, kind: u8, body: &[u8]) -> Result<()> {
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&(body.len() as u32).to_be_bytes());
    send.write_all(&head).await.map_err(closed)?;
    send.write_all(body).await.map_err(closed)
}

/// Read one frame, refusing bodies over `max`. `None` means the peer finished
/// the stream cleanly between frames.
pub(crate) async fn read_frame(recv: &mut RecvStream, max: usize) -> Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match recv.read_exact(&mut head).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(err) => return Err(closed(err)),
    }
    let len = u32::from_be_bytes(head[1..].try_into().expect("4 bytes")) as usize;
    if len > max {
        return Err(WireError::Protocol("frame too large"));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.map_err(closed)?;
    Ok(Some((head[0], body)))
}

/// Read a frame that must be there.
pub(crate) async fn expect_frame(recv: &mut RecvStream, max: usize) -> Result<(u8, Vec<u8>)> {
    read_frame(recv, max)
        .await?
        .ok_or(WireError::Closed("stream ended mid-exchange".into()))
}

/// Turn an `ERR` frame into its error; anything else unexpected is a
/// protocol violation.
pub(crate) fn unexpected(kind: u8, body: &[u8]) -> WireError {
    match (kind, body) {
        (ERR, [code]) => match ErrCode::from_byte(*code) {
            Some(code) => WireError::Refused(code),
            None => WireError::Protocol("unknown error code"),
        },
        _ => WireError::Protocol("unexpected frame"),
    }
}

pub(crate) fn file_head(root: &[u8; HASH_LEN], chunks: u64, total: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(FILE_HEAD);
    out.extend_from_slice(root);
    out.extend_from_slice(&chunks.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}
