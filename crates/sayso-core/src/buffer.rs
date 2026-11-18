//! The buffer lane (spec section 11): how an envelope waits on a public
//! store-and-forward network until the owner, or the harvest job, collects it.
//!
//! A buffer is public and writable by anyone, so everything read from one is
//! untrusted. An *item* is a stamp followed by an envelope; [`check`] is the
//! gate every reader applies before keeping one. Networks that cap message
//! size get the item as text *parts*, split by [`split`] and put back
//! together by [`Assembler`].

use std::collections::{HashMap, VecDeque};

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::envelope::{self, MAX_ENVELOPE};
use crate::kdf::kdf;
use crate::stamp::{STAMP_LEN, Stamp};
use crate::{Error, Result, to_hex};

/// The largest item there can be.
pub const MAX_ITEM: usize = STAMP_LEN + MAX_ENVELOPE;
/// Base64 characters of item data per part. With the part header this stays
/// under the 4096-byte message limit of ntfy.
pub const PART_DATA: usize = 3600;
/// More parts than the largest item needs are never accepted.
pub const MAX_PARTS: usize = MAX_ITEM.div_ceil(3).div_ceil(PART_DATA / 4) + 1;
/// How many half-received items an [`Assembler`] holds before it forgets the
/// oldest. Bounds memory when a topic is flooded with fragments.
pub const MAX_PENDING: usize = 256;

const PART_TAG: &str = "S1";
const ID_HEX: usize = 16;

/// Where an owner's buffered items are published: a name derived from the
/// owner identity, usable as an ntfy topic or inside a Waku content topic.
/// It is not secret; it only keeps unrelated inboxes apart.
pub fn topic(oik: &[u8; 32]) -> String {
    to_hex(&kdf("sayso/v1/buffer/topic", &[oik])[..20])
}

/// Build the item for an envelope and its stamp.
pub fn item(stamp: &Stamp, envelope: &[u8]) -> Vec<u8> {
    [&stamp.encode()[..], envelope].concat()
}

/// Accept bytes read from a buffer only if they are a drop-shaped envelope
/// under a stamp of at least `required_bits`. Returns the stamp and the
/// envelope.
pub fn check(item: &[u8], required_bits: u8) -> Result<(Stamp, &[u8])> {
    if item.len() > MAX_ITEM {
        return Err(Error::TooLarge);
    }
    let (stamp, envelope) = item
        .split_at_checked(STAMP_LEN)
        .ok_or(Error::Malformed("buffer item"))?;
    let stamp = Stamp::decode(stamp)?;
    let header = envelope::peek(envelope)?;
    if header.kind != envelope::Kind::Drop {
        return Err(Error::Invalid("envelope kind"));
    }
    if !stamp.verify(&envelope::envelope_id(envelope), required_bits) {
        return Err(Error::Invalid("stamp"));
    }
    Ok((stamp, envelope))
}

fn item_id(item: &[u8]) -> String {
    to_hex(&kdf("sayso/v1/buffer/item", &[item])[..ID_HEX / 2])
}

/// Split an item into text parts of the form `S1.<id>.<index>.<count>.<data>`.
pub fn split(item: &[u8]) -> Result<Vec<String>> {
    if item.len() > MAX_ITEM {
        return Err(Error::TooLarge);
    }
    let id = item_id(item);
    let encoded = Base64UrlUnpadded::encode_string(item);
    let chunks: Vec<&str> = encoded
        .as_bytes()
        .chunks(PART_DATA)
        .map(|chunk| core::str::from_utf8(chunk).expect("base64 is ascii"))
        .collect();
    let count = chunks.len();
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(index, data)| format!("{PART_TAG}.{id}.{index}.{count}.{data}"))
        .collect())
}

struct Partial {
    parts: Vec<Option<String>>,
    missing: usize,
}

/// Reassembles items from parts arriving in any order, interleaved with
/// other items and with junk.
#[derive(Default)]
pub struct Assembler {
    pending: HashMap<String, Partial>,
    order: VecDeque<String>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one message read from the buffer. Returns an item when this part
    /// completed it and its bytes match the id its parts claimed. Anything
    /// that is not a well-formed part is ignored.
    pub fn push(&mut self, text: &str) -> Option<Vec<u8>> {
        let mut fields = text.splitn(5, '.');
        let (tag, id, index, count, data) = (
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
        );
        if tag != PART_TAG
            || id.len() != ID_HEX
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || data.is_empty()
            || data.len() > PART_DATA
        {
            return None;
        }
        let index: usize = index.parse().ok()?;
        let count: usize = count.parse().ok()?;
        if count == 0 || count > MAX_PARTS || index >= count {
            return None;
        }

        if !self.pending.contains_key(id) {
            if self.order.len() >= MAX_PENDING
                && let Some(oldest) = self.order.pop_front()
            {
                self.pending.remove(&oldest);
            }
            self.order.push_back(id.to_owned());
            self.pending.insert(
                id.to_owned(),
                Partial {
                    parts: vec![None; count],
                    missing: count,
                },
            );
        }
        let partial = self.pending.get_mut(id)?;
        if partial.parts.len() != count {
            return None;
        }
        if partial.parts[index].is_none() {
            partial.parts[index] = Some(data.to_owned());
            partial.missing -= 1;
        }
        if partial.missing > 0 {
            return None;
        }

        let partial = self.pending.remove(id)?;
        self.order.retain(|known| known != id);
        let encoded: String = partial.parts.into_iter().flatten().collect();
        let item = Base64UrlUnpadded::decode_vec(&encoded).ok()?;
        // The id is a claim made by whoever posted the parts; hold it to the bytes.
        (item_id(&item) == id).then_some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{OwnerKeys, SenderKeys};
    use crate::payload::Payload;
    use crate::{stamp, xwing};

    fn sealed(text: &str) -> Vec<u8> {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let sender = SenderKeys::derive(&[2; 32], owner.oik());
        let epoch = xwing::SecretKey::from_seed(&[3; 32]);
        let mut payload = Payload::new([7; 16], 1);
        payload.text = Some(text.into());
        envelope::seal_drop(&sender, 9, epoch.public(), &[4; 64], payload).unwrap()
    }

    fn stamped(envelope: &[u8], bits: u8) -> Vec<u8> {
        let stamp = stamp::search(&envelope::envelope_id(envelope), bits, 0, u64::MAX)
            .unwrap()
            .unwrap();
        item(&stamp, envelope)
    }

    #[test]
    fn topic_is_stable_and_per_owner() {
        assert_eq!(topic(&[1; 32]), topic(&[1; 32]));
        assert_ne!(topic(&[1; 32]), topic(&[2; 32]));
        assert_eq!(topic(&[1; 32]).len(), 40);
    }

    #[test]
    fn check_accepts_a_stamped_drop_and_nothing_else() {
        let envelope = sealed("hello");
        let good = stamped(&envelope, 8);
        let (stamp, inner) = check(&good, 8).unwrap();
        assert!(stamp.bits >= 8);
        assert_eq!(inner, &envelope[..]);

        assert!(check(&good, 20).is_err(), "a weaker stamp than demanded");
        assert!(
            check(&good[..good.len() - 1], 8).is_err(),
            "not envelope-shaped"
        );
        assert!(check(b"junk", 0).is_err());
        let mut other = good.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(
            check(&other, 8).is_err(),
            "the stamp belongs to a different envelope"
        );
        assert!(check(&vec![0; MAX_ITEM + 1], 0).is_err());
    }

    #[test]
    fn a_reply_envelope_is_not_a_buffer_item() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let sender = SenderKeys::derive(&[2; 32], owner.oik());
        let reply = envelope::seal_reply(
            &owner,
            sender.sid(),
            sender.reply_public(),
            9,
            &[5; 64],
            &Payload::new([1; 16], 1),
        )
        .unwrap();
        assert_eq!(
            check(&stamped(&reply, 4), 4).err(),
            Some(Error::Invalid("envelope kind"))
        );
    }

    #[test]
    fn split_parts_fit_the_message_limit_and_reassemble() {
        let big = stamped(&sealed(&"x".repeat(50_000)), 4);
        let parts = split(&big).unwrap();
        assert!(parts.len() > 10);
        assert!(
            parts.iter().all(|p| p.len() <= 4096),
            "every part fits an ntfy message"
        );

        let mut assembler = Assembler::new();
        let mut out = None;
        for part in &parts {
            assert!(out.is_none(), "complete only on the last part");
            out = assembler.push(part);
        }
        assert_eq!(out.unwrap(), big);
    }

    #[test]
    fn the_smallest_envelope_needs_two_parts() {
        let parts = split(&stamped(&sealed("hi"), 4)).unwrap();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn parts_may_arrive_shuffled_duplicated_and_interleaved() {
        let a = stamped(&sealed("first"), 4);
        let b = stamped(&sealed(&"second ".repeat(900)), 4);
        let (pa, pb) = (split(&a).unwrap(), split(&b).unwrap());
        let mut feed: Vec<&String> = pa.iter().chain(pb.iter()).collect();
        feed.reverse();
        feed.insert(1, &pa[0]);
        feed.insert(3, &pb[1]);

        let mut assembler = Assembler::new();
        let mut done: Vec<Vec<u8>> = feed.into_iter().filter_map(|p| assembler.push(p)).collect();
        done.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(done, expected);
    }

    #[test]
    fn junk_and_forged_parts_are_ignored() {
        let mut assembler = Assembler::new();
        for junk in [
            "",
            "hello",
            "S1.zz.0.1.AAAA",
            "S2.0123456789abcdef.0.1.AAAA",
            "S1.0123456789abcdef.1.1.AAAA",
            "S1.0123456789abcdef.0.0.AAAA",
            "S1.0123456789abcdef.0.9999.AAAA",
            "S1.0123456789abcdef.0.1.!!!!",
        ] {
            assert!(assembler.push(junk).is_none(), "{junk:?}");
        }
        // Well-formed parts whose bytes do not hash to the id they claim.
        assert!(assembler.push("S1.0123456789abcdef.0.1.AAAA").is_none());

        // A forged fragment claiming a real item's id cannot poison that item
        // once the real parts are in...
        let real = stamped(&sealed("real"), 4);
        let parts = split(&real).unwrap();
        let id = parts[0].split('.').nth(1).unwrap().to_owned();
        let mut assembler = Assembler::new();
        assert!(assembler.push(&parts[0]).is_none());
        assert!(
            assembler.push(&format!("S1.{id}.0.2.AAAA")).is_none(),
            "first writer wins the slot"
        );
        assert_eq!(assembler.push(&parts[1]).unwrap(), real);
    }

    #[test]
    fn a_flood_of_fragments_does_not_grow_without_bound() {
        let mut assembler = Assembler::new();
        for n in 0..(MAX_PENDING * 3) {
            assembler.push(&format!("S1.{n:016x}.0.2.AAAA"));
        }
        assert!(assembler.pending.len() <= MAX_PENDING);
        assert_eq!(assembler.pending.len(), assembler.order.len());
    }
}
