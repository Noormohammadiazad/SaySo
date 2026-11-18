//! The plaintext inside an envelope (spec section 4, "Payload").

use minicbor::bytes::{ByteArray, ByteVec};
use minicbor::{Decode, Encode};

use crate::xwing;
use crate::{Error, Result};

pub const MSG_ID_LEN: usize = 16;
pub const MAX_FILES: usize = 32;
pub const MAX_NAME: usize = 255;
pub const MAX_MIME: usize = 127;
pub const MAX_CREDS: usize = 4;
pub const MAX_CRED_LEN: usize = 512;

/// Control value: binds a live connection to a thread, carries no message.
pub const CTL_PRESENCE: u8 = 1;
/// Control value: delete, on the receiving side, the message `reply_to`
/// names, or with no `reply_to` the whole thread. Either party may send it;
/// it only ever reaches the one thread it was sealed for.
pub const CTL_DELETE: u8 = 2;
/// Control value: the drop `reply_to` names reached the owner.
pub const CTL_ACK: u8 = 3;
/// Control value: the owner verified this sender. `creds` holds the
/// credential (see `verified`), or is absent when the owner withdrew it.
pub const CTL_VERIFIED: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Payload {
    /// Random message id.
    #[n(1)]
    pub id: ByteArray<MSG_ID_LEN>,
    /// Sender clock, Unix milliseconds.
    #[n(2)]
    pub ts: u64,
    #[n(3)]
    pub text: Option<String>,
    #[n(4)]
    pub files: Option<Vec<FileRef>>,
    /// Drops only: how the owner can answer.
    #[n(5)]
    pub hello: Option<Hello>,
    #[n(6)]
    pub reply_to: Option<ByteArray<MSG_ID_LEN>>,
    /// Invites or proofs presented by the sender.
    #[n(7)]
    pub creds: Option<Vec<ByteVec>>,
    #[n(8)]
    pub ctl: Option<u8>,
}

/// What the owner needs to reply to a sender.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Hello {
    /// The sender's X-Wing reply key.
    #[n(1)]
    pub reply_pk: ByteVec,
    /// Derives the sender's mailbox addresses.
    #[n(2)]
    pub tag_key: ByteArray<32>,
}

/// A file attached to a message: everything needed to fetch, verify and
/// decrypt its chunks.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct FileRef {
    #[n(1)]
    pub name: String,
    #[n(2)]
    pub mime: String,
    /// True size in bytes.
    #[n(3)]
    pub size: u64,
    /// Merkle root over the encrypted chunks; the file's identity.
    #[n(4)]
    pub root: ByteArray<32>,
    #[n(5)]
    pub key: ByteArray<32>,
    /// Size after padding.
    #[n(6)]
    pub padded_size: u64,
}

impl Payload {
    pub fn new(id: [u8; MSG_ID_LEN], ts: u64) -> Self {
        Self {
            id: id.into(),
            ts,
            text: None,
            files: None,
            hello: None,
            reply_to: None,
            creds: None,
            ctl: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        minicbor::to_vec(self).expect("encoding to a Vec cannot fail")
    }

    /// Decode and check every protocol limit. The whole input must be consumed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let payload: Self = decoder.decode().map_err(|_| Error::Malformed("payload"))?;
        if decoder.position() != bytes.len() {
            return Err(Error::Malformed("payload"));
        }
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(files) = &self.files {
            if files.len() > MAX_FILES {
                return Err(Error::TooLarge);
            }
            for file in files {
                file.validate()?;
            }
        }
        if let Some(hello) = &self.hello
            && hello.reply_pk.len() != xwing::PUBLIC_LEN
        {
            return Err(Error::Malformed("reply key"));
        }
        if let Some(creds) = &self.creds
            && (creds.len() > MAX_CREDS || creds.iter().any(|c| c.len() > MAX_CRED_LEN))
        {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}

impl FileRef {
    pub fn validate(&self) -> Result<()> {
        if self.name.len() > MAX_NAME || self.mime.len() > MAX_MIME {
            return Err(Error::TooLarge);
        }
        crate::file::FilePlan::from_parts(self.size, self.padded_size)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Payload {
        let mut payload = Payload::new([7; 16], 1_794_300_000_123);
        payload.text = Some("hello, owner".into());
        payload.files = Some(vec![FileRef {
            name: "report.pdf".into(),
            mime: "application/pdf".into(),
            size: 5000,
            root: [1; 32].into(),
            key: [2; 32].into(),
            padded_size: crate::file::FilePlan::for_size(5000).padded,
        }]);
        payload.hello = Some(Hello {
            reply_pk: vec![3; xwing::PUBLIC_LEN].into(),
            tag_key: [4; 32].into(),
        });
        payload.reply_to = Some([5; 16].into());
        payload.creds = Some(vec![vec![6; 80].into()]);
        payload
    }

    #[test]
    fn round_trip() {
        let payload = sample();
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn minimal_payload_is_small_and_round_trips() {
        let payload = Payload::new([0; 16], 1);
        let bytes = payload.encode();
        assert!(bytes.len() < 32, "{} bytes", bytes.len());
        assert_eq!(Payload::decode(&bytes).unwrap(), payload);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert_eq!(Payload::decode(&bytes), Err(Error::Malformed("payload")));
    }

    #[test]
    fn limits_are_enforced_on_decode() {
        let mut payload = sample();
        payload.hello.as_mut().unwrap().reply_pk = vec![3; 100].into();
        assert_eq!(
            Payload::decode(&payload.encode()),
            Err(Error::Malformed("reply key"))
        );

        let mut payload = sample();
        payload.files.as_mut().unwrap()[0].name = "x".repeat(MAX_NAME + 1);
        assert_eq!(Payload::decode(&payload.encode()), Err(Error::TooLarge));

        let mut payload = sample();
        payload.files.as_mut().unwrap()[0].padded_size = 10;
        assert!(Payload::decode(&payload.encode()).is_err());

        let mut payload = sample();
        payload.creds = Some(vec![vec![0; MAX_CRED_LEN + 1].into()]);
        assert_eq!(Payload::decode(&payload.encode()), Err(Error::TooLarge));
    }

    #[test]
    fn garbage_does_not_decode() {
        assert!(Payload::decode(&[]).is_err());
        assert!(Payload::decode(&[0xff; 40]).is_err());
    }
}
