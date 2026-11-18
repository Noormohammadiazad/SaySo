//! Reply mailboxes (spec section 6): where a sender with no account finds
//! replies that could not be delivered live.

use crate::envelope;
use crate::kdf::{kdf, mac};
use crate::{Error, Result, to_hex};

pub const ADDR_LEN: usize = 16;

/// The mailbox address of one thread in one epoch. Addresses in different
/// epochs cannot be linked without the tag key.
pub fn address(tag_key: &[u8; 32], epoch: u32) -> [u8; ADDR_LEN] {
    let digest = mac(tag_key, &[b"sayso/v1/mbox", &epoch.to_be_bytes()]);
    digest[..ADDR_LEN].try_into().expect("16 of 32")
}

/// Path of that mailbox on the data branch.
pub fn path(tag_key: &[u8; 32], epoch: u32) -> String {
    format!("mail/e{epoch}/{}.bin", to_hex(&address(tag_key, epoch)))
}

/// The live mailbox of one thread: a name on a store-and-forward relay where
/// the owner's replies are pushed the moment they are sealed. Derived from
/// the tag key, so it is as unlinkable to the sender as the files are, and
/// stable across epochs so a sender subscribes once.
pub fn topic(tag_key: &[u8; 32]) -> String {
    to_hex(&kdf("sayso/v1/mbox-topic", &[tag_key])[..20])
}

/// Append one reply envelope to the bytes of a mailbox file.
pub fn append(file: &mut Vec<u8>, envelope: &[u8]) -> Result<()> {
    envelope::peek(envelope)?;
    file.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    file.extend_from_slice(envelope);
    Ok(())
}

/// Split a mailbox file into its envelopes.
pub fn split(file: &[u8]) -> Result<Vec<&[u8]>> {
    let mut rest = file;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest
            .split_first_chunk::<4>()
            .ok_or(Error::Malformed("mailbox"))?;
        let len = u32::from_be_bytes(*len) as usize;
        if len > envelope::MAX_ENVELOPE || len > tail.len() {
            return Err(Error::Malformed("mailbox"));
        }
        let (item, tail) = tail.split_at(len);
        out.push(item);
        rest = tail;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{OwnerKeys, SenderKeys};
    use crate::payload::Payload;

    #[test]
    fn addresses_differ_by_epoch_and_by_thread() {
        assert_ne!(address(&[1; 32], 5), address(&[1; 32], 6));
        assert_ne!(address(&[1; 32], 5), address(&[2; 32], 5));
        assert_eq!(address(&[1; 32], 5), address(&[1; 32], 5));
    }

    #[test]
    fn path_has_the_documented_form() {
        let path = path(&[1; 32], 2966);
        assert!(path.starts_with("mail/e2966/"));
        assert!(path.ends_with(".bin"));
        assert_eq!(path.len(), "mail/e2966/".len() + 32 + 4);
    }

    #[test]
    fn append_and_split() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let sender = SenderKeys::derive(&[2; 32], owner.oik());
        let reply = |n: u8| {
            let mut payload = Payload::new([n; 16], 1);
            payload.text = Some(format!("reply {n}"));
            envelope::seal_reply(
                &owner,
                sender.sid(),
                sender.reply_public(),
                9,
                &[n; 64],
                &payload,
            )
            .unwrap()
        };
        let (first, second) = (reply(1), reply(2));
        let mut file = Vec::new();
        append(&mut file, &first).unwrap();
        append(&mut file, &second).unwrap();
        assert_eq!(split(&file).unwrap(), vec![&first[..], &second[..]]);
        assert_eq!(split(&[]).unwrap().len(), 0);
        assert!(split(&file[..file.len() - 1]).is_err());
        assert!(append(&mut file, b"not an envelope").is_err());
    }
}
