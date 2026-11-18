//! The sealed envelope (spec section 4): the only thing a transport or a
//! store ever sees.

use crate::kdf::{hash, kdf};
use crate::keys::{self, ID_LEN, OwnerKeys, SIG_LEN, SenderKeys};
use crate::payload::{Hello, Payload};
use crate::xwing::{self, CIPHERTEXT_LEN, ENTROPY_LEN, PUBLIC_LEN};
use crate::{Error, Result, aead};

pub const MAGIC: [u8; 4] = *b"SYSO";
pub const VERSION: u8 = 1;
pub const SUITE: u16 = 0x0001;
pub const HEADER_LEN: usize = 20;
pub const EID_LEN: usize = 32;

/// Padded plaintext is a power of two between these bounds.
pub const MIN_PADDED: usize = 1 << 11;
pub const MAX_PADDED: usize = 1 << 17;

/// The largest envelope there can be.
pub const MAX_ENVELOPE: usize = HEADER_LEN + CIPHERTEXT_LEN + MAX_PADDED + aead::TAG_LEN;

const SIG_CONTEXT: &[u8] = b"sayso/v1/envelope/sig";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Sender to owner, sealed to an epoch key.
    Drop = 1,
    /// Owner to sender, sealed to the sender's reply key.
    Reply = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    /// Owner epoch the envelope belongs to.
    pub epoch: u32,
    /// Drops: first 8 bytes of the epoch key's id. Replies: zero.
    pub key_hint: [u8; 8],
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind as u8;
        out[6..8].copy_from_slice(&SUITE.to_be_bytes());
        out[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        out[12..20].copy_from_slice(&self.key_hint);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; HEADER_LEN] = bytes
            .get(..HEADER_LEN)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Malformed("envelope"))?;
        if bytes[0..4] != MAGIC {
            return Err(Error::Malformed("envelope"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Unsupported("envelope version"));
        }
        let kind = match bytes[5] {
            1 => Kind::Drop,
            2 => Kind::Reply,
            _ => return Err(Error::Unsupported("envelope kind")),
        };
        if u16::from_be_bytes([bytes[6], bytes[7]]) != SUITE {
            return Err(Error::Unsupported("suite"));
        }
        Ok(Self {
            kind,
            epoch: u32::from_be_bytes(bytes[8..12].try_into().expect("4 bytes")),
            key_hint: bytes[12..20].try_into().expect("8 bytes"),
        })
    }
}

/// An envelope that was opened and whose signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub header: Header,
    pub eid: [u8; EID_LEN],
    /// Who signed it: the sender identity for a drop, the owner for a reply.
    pub signer: [u8; ID_LEN],
    pub payload: Payload,
}

/// `eid`: the name of an envelope in every store and on every transport.
pub fn envelope_id(envelope: &[u8]) -> [u8; EID_LEN] {
    kdf("sayso/v1/envelope/id", &[envelope])
}

/// Check that bytes have the shape of an envelope, without any key.
///
/// This is all a courier or a buffer can verify, and what a receiver checks
/// before spending effort on decapsulation.
pub fn peek(envelope: &[u8]) -> Result<Header> {
    let header = Header::decode(envelope)?;
    let padded = envelope
        .len()
        .checked_sub(HEADER_LEN + CIPHERTEXT_LEN + aead::TAG_LEN)
        .ok_or(Error::Malformed("envelope"))?;
    if !padded.is_power_of_two() || !(MIN_PADDED..=MAX_PADDED).contains(&padded) {
        return Err(Error::Malformed("envelope"));
    }
    Ok(header)
}

/// Seal a message from a sender to the owner's epoch key.
///
/// `entropy` must be 64 fresh random bytes. The `hello` field is filled in
/// from the sender's keys, replacing whatever the caller put there.
pub fn seal_drop(
    sender: &SenderKeys,
    epoch: u32,
    epoch_public: &[u8; PUBLIC_LEN],
    entropy: &[u8; ENTROPY_LEN],
    mut payload: Payload,
) -> Result<Vec<u8>> {
    payload.hello = Some(Hello {
        reply_pk: sender.reply_public().to_vec().into(),
        tag_key: (*sender.tag_key()).into(),
    });
    payload.validate()?;
    seal(
        Kind::Drop,
        epoch,
        epoch_public,
        entropy,
        sender.sid(),
        sender.oik(),
        &payload.encode(),
        |message| sender.sign(message),
    )
}

/// Open a drop with the secret of the epoch it names.
///
/// Returns [`Error::BadKey`] when the envelope was sealed to a different
/// epoch key, so a caller holding several keys can tell "not mine" from
/// "tampered".
pub fn open_drop(
    epoch_secret: &xwing::SecretKey,
    oik: &[u8; ID_LEN],
    envelope: &[u8],
) -> Result<Opened> {
    let opened = open(Kind::Drop, epoch_secret, true, oik, envelope)?;
    if opened.payload.hello.is_none() {
        return Err(Error::Invalid("drop without hello"));
    }
    Ok(opened)
}

/// Seal a reply from the owner to a sender's reply key.
pub fn seal_reply(
    owner: &OwnerKeys,
    sid: &[u8; ID_LEN],
    reply_public: &[u8; PUBLIC_LEN],
    epoch: u32,
    entropy: &[u8; ENTROPY_LEN],
    payload: &Payload,
) -> Result<Vec<u8>> {
    if payload.hello.is_some() {
        return Err(Error::Invalid("reply with hello"));
    }
    payload.validate()?;
    seal(
        Kind::Reply,
        epoch,
        reply_public,
        entropy,
        owner.oik(),
        sid,
        &payload.encode(),
        |message| owner.sign(message),
    )
}

/// Open a reply. Fails with [`Error::WrongSigner`] unless the pinned owner
/// identity signed it for this sender.
pub fn open_reply(sender: &SenderKeys, envelope: &[u8]) -> Result<Opened> {
    let opened = open(
        Kind::Reply,
        sender.reply_secret(),
        false,
        sender.sid(),
        envelope,
    )?;
    if &opened.signer != sender.oik() {
        return Err(Error::WrongSigner);
    }
    if opened.payload.hello.is_some() {
        return Err(Error::Invalid("reply with hello"));
    }
    Ok(opened)
}

#[allow(clippy::too_many_arguments)]
fn seal(
    kind: Kind,
    epoch: u32,
    recipient: &[u8; PUBLIC_LEN],
    entropy: &[u8; ENTROPY_LEN],
    signer: &[u8; ID_LEN],
    peer: &[u8; ID_LEN],
    payload: &[u8],
    sign: impl FnOnce(&[u8]) -> [u8; SIG_LEN],
) -> Result<Vec<u8>> {
    let recipient_id = keys::key_id(recipient);
    let mut key_hint = [0u8; 8];
    if kind == Kind::Drop {
        key_hint.copy_from_slice(&recipient_id[..8]);
    }
    let header = Header {
        kind,
        epoch,
        key_hint,
    }
    .encode();
    let (kem_ct, shared) = xwing::encapsulate(recipient, entropy)?;

    let sig = sign(&signed_message(&header, &kem_ct, peer, signer, payload));
    let mut inner = Vec::with_capacity(SIG_LEN + ID_LEN + payload.len());
    inner.extend_from_slice(&sig);
    inner.extend_from_slice(signer);
    inner.extend_from_slice(payload);
    let padded = pad(&inner)?;

    let (key, nonce) = schedule(&shared, &header, &recipient_id);
    let mut out = Vec::with_capacity(HEADER_LEN + CIPHERTEXT_LEN + padded.len() + aead::TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&kem_ct);
    let sealed = aead::seal(&key, &nonce, &out, &padded);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open(
    kind: Kind,
    secret: &xwing::SecretKey,
    hinted: bool,
    peer: &[u8; ID_LEN],
    envelope: &[u8],
) -> Result<Opened> {
    let header = peek(envelope)?;
    if header.kind != kind {
        return Err(Error::Invalid("envelope kind"));
    }
    let recipient_id = keys::key_id(secret.public());
    let expected_hint: &[u8] = if hinted {
        &recipient_id[..8]
    } else {
        &[0u8; 8]
    };
    if header.key_hint != expected_hint {
        return Err(Error::BadKey);
    }

    let (associated, sealed) = envelope.split_at(HEADER_LEN + CIPHERTEXT_LEN);
    let header_bytes: &[u8; HEADER_LEN] = associated[..HEADER_LEN].try_into().expect("split");
    let kem_ct: &[u8; CIPHERTEXT_LEN] = associated[HEADER_LEN..].try_into().expect("split");

    let shared = secret.decapsulate(kem_ct)?;
    let (key, nonce) = schedule(&shared, header_bytes, &recipient_id);
    let padded = aead::open(&key, &nonce, associated, sealed)?;
    let inner = unpad(&padded)?;
    if inner.len() < SIG_LEN + ID_LEN {
        return Err(Error::Malformed("envelope"));
    }
    let sig: &[u8; SIG_LEN] = inner[..SIG_LEN].try_into().expect("checked");
    let signer: [u8; ID_LEN] = inner[SIG_LEN..SIG_LEN + ID_LEN]
        .try_into()
        .expect("checked");
    let payload = &inner[SIG_LEN + ID_LEN..];

    keys::verify(
        &signer,
        &signed_message(header_bytes, kem_ct, peer, &signer, payload),
        sig,
    )?;

    Ok(Opened {
        header,
        eid: envelope_id(envelope),
        signer,
        payload: Payload::decode(payload)?,
    })
}

/// The AEAD key and nonce for one envelope. Each envelope has its own
/// encapsulation, so the pair is used exactly once.
fn schedule(
    shared: &[u8; 32],
    header: &[u8; HEADER_LEN],
    recipient_id: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
    let key = kdf("sayso/v1/envelope/key", &[shared, header, recipient_id]);
    let wide = kdf("sayso/v1/envelope/nonce", &[shared, header, recipient_id]);
    (key, wide[..12].try_into().expect("12 of 32"))
}

/// What the signer signs. Covering the header and the encapsulation pins the
/// payload to this recipient and epoch: it cannot be re-sealed elsewhere.
fn signed_message(
    header: &[u8; HEADER_LEN],
    kem_ct: &[u8; CIPHERTEXT_LEN],
    peer: &[u8; ID_LEN],
    signer: &[u8; ID_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SIG_CONTEXT.len() + HEADER_LEN + 32 + 2 * ID_LEN + payload.len());
    message.extend_from_slice(SIG_CONTEXT);
    message.extend_from_slice(header);
    message.extend_from_slice(&hash(kem_ct));
    message.extend_from_slice(peer);
    message.extend_from_slice(signer);
    message.extend_from_slice(payload);
    message
}

fn pad(inner: &[u8]) -> Result<Vec<u8>> {
    let needed = inner.len().checked_add(4).ok_or(Error::TooLarge)?;
    if needed > MAX_PADDED {
        return Err(Error::TooLarge);
    }
    let size = needed.next_power_of_two().max(MIN_PADDED);
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    out.extend_from_slice(inner);
    out.resize(size, 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let (len, rest) = padded
        .split_first_chunk::<4>()
        .ok_or(Error::Malformed("padding"))?;
    let len = u32::from_be_bytes(*len) as usize;
    if len > rest.len() || rest[len..].iter().any(|&b| b != 0) {
        return Err(Error::Malformed("padding"));
    }
    Ok(&rest[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct World {
        owner: OwnerKeys,
        sender: SenderKeys,
        epoch: xwing::SecretKey,
    }

    fn world() -> World {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let sender = SenderKeys::derive(&[2; 32], owner.oik());
        World {
            owner,
            sender,
            epoch: xwing::SecretKey::from_seed(&[3; 32]),
        }
    }

    fn text(body: &str) -> Payload {
        let mut payload = Payload::new([7; 16], 1_794_300_000_000);
        payload.text = Some(body.into());
        payload
    }

    fn drop_of(w: &World, body: &str) -> Vec<u8> {
        seal_drop(&w.sender, 2966, w.epoch.public(), &[4; 64], text(body)).unwrap()
    }

    #[test]
    fn drop_round_trip() {
        let w = world();
        let envelope = drop_of(&w, "hello");
        let opened = open_drop(&w.epoch, w.owner.oik(), &envelope).unwrap();
        assert_eq!(opened.payload.text.as_deref(), Some("hello"));
        assert_eq!(&opened.signer, w.sender.sid());
        assert_eq!(opened.header.epoch, 2966);
        assert_eq!(opened.eid, envelope_id(&envelope));
        let hello = opened.payload.hello.unwrap();
        assert_eq!(&hello.reply_pk[..], &w.sender.reply_public()[..]);
        assert_eq!(&*hello.tag_key, w.sender.tag_key());
    }

    #[test]
    fn reply_round_trip() {
        let w = world();
        let envelope = seal_reply(
            &w.owner,
            w.sender.sid(),
            w.sender.reply_public(),
            2966,
            &[5; 64],
            &text("hi back"),
        )
        .unwrap();
        let opened = open_reply(&w.sender, &envelope).unwrap();
        assert_eq!(opened.payload.text.as_deref(), Some("hi back"));
        assert_eq!(&opened.signer, w.owner.oik());
        assert_eq!(opened.header.key_hint, [0; 8], "replies carry no key hint");
    }

    #[test]
    fn layout_matches_the_spec() {
        let w = world();
        let envelope = drop_of(&w, "hello");
        assert_eq!(&envelope[0..4], b"SYSO");
        assert_eq!(envelope[4], 1);
        assert_eq!(envelope[5], 1);
        assert_eq!(&envelope[6..8], &[0, 1]);
        assert_eq!(&envelope[8..12], &2966u32.to_be_bytes());
        assert_eq!(&envelope[12..20], &keys::key_id(w.epoch.public())[..8]);
        // A short message with its 1216-byte reply key lands in the 2 KiB bucket.
        assert_eq!(envelope.len(), 20 + 1120 + 2048 + 16);
    }

    #[test]
    fn padding_buckets_hide_length_within_a_power_of_two() {
        let w = world();
        let short = drop_of(&w, "a");
        let longer = drop_of(&w, &"a".repeat(500));
        assert_eq!(short.len(), longer.len());
        let big = drop_of(&w, &"a".repeat(3000));
        assert_eq!(big.len(), 20 + 1120 + 8192 + 16);
    }

    #[test]
    fn oversized_payload_is_refused() {
        let w = world();
        let result = seal_drop(
            &w.sender,
            1,
            w.epoch.public(),
            &[4; 64],
            text(&"a".repeat(MAX_PADDED)),
        );
        assert_eq!(result, Err(Error::TooLarge));
    }

    #[test]
    fn every_byte_is_authenticated() {
        let w = world();
        let envelope = drop_of(&w, "hello");
        // One position in each region: header epoch, KEM ciphertext, body, tag.
        for position in [9, 100, HEADER_LEN + CIPHERTEXT_LEN + 5, envelope.len() - 1] {
            let mut tampered = envelope.clone();
            tampered[position] ^= 0x01;
            assert!(
                open_drop(&w.epoch, w.owner.oik(), &tampered).is_err(),
                "flip at {position} went unnoticed"
            );
        }
    }

    #[test]
    fn wrong_epoch_key_is_reported_as_bad_key() {
        let w = world();
        let other = xwing::SecretKey::from_seed(&[9; 32]);
        assert_eq!(
            open_drop(&other, w.owner.oik(), &drop_of(&w, "hello")),
            Err(Error::BadKey)
        );
    }

    #[test]
    fn a_drop_is_bound_to_the_owner_it_was_signed_for() {
        // Another owner who somehow holds the same epoch secret still cannot
        // accept the drop as addressed to them.
        let w = world();
        let impostor = OwnerKeys::from_root(&[8; 32]);
        assert_eq!(
            open_drop(&w.epoch, impostor.oik(), &drop_of(&w, "hello")),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn reply_from_anyone_but_the_owner_is_rejected() {
        let w = world();
        let impostor = OwnerKeys::from_root(&[8; 32]);
        let forged = seal_reply(
            &impostor,
            w.sender.sid(),
            w.sender.reply_public(),
            1,
            &[5; 64],
            &text("trust me"),
        )
        .unwrap();
        assert_eq!(open_reply(&w.sender, &forged), Err(Error::WrongSigner));
    }

    #[test]
    fn reply_cannot_be_redirected_to_another_sender() {
        let w = world();
        let other = SenderKeys::derive(&[6; 32], w.owner.oik());
        // Sealed to `other`'s key but signed as if for `w.sender`.
        let envelope = seal_reply(
            &w.owner,
            w.sender.sid(),
            other.reply_public(),
            1,
            &[5; 64],
            &text("for w"),
        )
        .unwrap();
        assert_eq!(open_reply(&other, &envelope), Err(Error::BadSignature));
    }

    #[test]
    fn kinds_do_not_cross() {
        let w = world();
        let reply = seal_reply(
            &w.owner,
            w.sender.sid(),
            w.sender.reply_public(),
            1,
            &[5; 64],
            &text("x"),
        )
        .unwrap();
        assert_eq!(
            open_drop(&w.epoch, w.owner.oik(), &reply),
            Err(Error::Invalid("envelope kind"))
        );
        assert_eq!(
            open_reply(&w.sender, &drop_of(&w, "x")),
            Err(Error::Invalid("envelope kind"))
        );
    }

    #[test]
    fn peek_accepts_only_envelope_shapes() {
        let w = world();
        let envelope = drop_of(&w, "hello");
        assert_eq!(peek(&envelope).unwrap().kind, Kind::Drop);
        assert!(peek(&envelope[..envelope.len() - 1]).is_err());
        assert!(peek(&envelope[..HEADER_LEN]).is_err());
        assert!(peek(&[]).is_err());
        let mut wrong_version = envelope.clone();
        wrong_version[4] = 2;
        assert_eq!(
            peek(&wrong_version),
            Err(Error::Unsupported("envelope version"))
        );
        let mut wrong_suite = envelope;
        wrong_suite[7] = 9;
        assert_eq!(peek(&wrong_suite), Err(Error::Unsupported("suite")));
    }

    #[test]
    fn fresh_entropy_gives_unlinkable_envelopes() {
        let w = world();
        let a = seal_drop(&w.sender, 1, w.epoch.public(), &[4; 64], text("same")).unwrap();
        let b = seal_drop(&w.sender, 1, w.epoch.public(), &[5; 64], text("same")).unwrap();
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
        assert_ne!(envelope_id(&a), envelope_id(&b));
    }

    #[test]
    fn padding_is_strict() {
        assert_eq!(unpad(&pad(b"abc").unwrap()).unwrap(), b"abc");
        assert_eq!(pad(b"abc").unwrap().len(), MIN_PADDED);
        let mut dirty = pad(b"abc").unwrap();
        *dirty.last_mut().unwrap() = 1;
        assert!(unpad(&dirty).is_err());
        let mut overlong = pad(b"abc").unwrap();
        overlong[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(unpad(&overlong).is_err());
    }
}
