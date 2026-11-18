//! The logic of the scheduled jobs that run in the owner's repository.
//!
//! These jobs hold no decryption key. They read what is public (the signed
//! owner document, the buffers), keep what passes the checks any outsider
//! could make, and file it in the vault. Network and git are left to the
//! workflow that calls the binary; everything here is plain functions over
//! bytes and a directory, so it can be tested without either.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use sayso_core::buffer::{self, Assembler};
use sayso_core::doc::{self, DocKind};
use sayso_core::envelope;
use sayso_core::epoch::{EpochParams, EpochState};
use sayso_core::to_hex;
use serde::Deserialize;

/// What one harvest run may add to the vault. A buffer is writable by anyone
/// who can mint a stamp, so a run is capped; when more arrives than fits, the
/// items with the strongest stamps are kept.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_items: usize,
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_items: 200,
            max_bytes: 4 << 20,
        }
    }
}

#[derive(Debug)]
pub enum OpsError {
    /// The owner document is not valid JSON of the expected shape.
    Manifest(String),
    /// The owner document's signature does not verify under its own key.
    Signature,
    Io(io::Error),
}

impl fmt::Display for OpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(why) => write!(f, "invalid owner.json: {why}"),
            Self::Signature => f.write_str("the owner.json signature does not verify"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for OpsError {}

impl From<io::Error> for OpsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// `owner.json`: the body is the signed JSON text itself, kept as a string
/// so its bytes are exactly what was signed.
#[derive(Deserialize)]
struct SignedDoc {
    key: String,
    sig: String,
    body: String,
}

#[derive(Deserialize)]
struct OwnerBody {
    v: u32,
    epoch_len: u64,
    grace: u64,
    ttl: u64,
    pow: Pow,
    #[serde(default)]
    buffers: Vec<BufferEntry>,
}

#[derive(Deserialize)]
struct Pow {
    bits: u8,
}

#[derive(Deserialize)]
struct BufferEntry {
    kind: String,
    url: Option<String>,
}

/// What the jobs need from the owner document.
#[derive(Debug, Clone)]
pub struct Config {
    pub oik: [u8; 32],
    pub params: EpochParams,
    pub pow_bits: u8,
    /// Base URLs of the ntfy-protocol buffers the owner listed.
    pub ntfy: Vec<String>,
}

impl Config {
    /// Parse `owner.json` from the data branch and verify its signature.
    ///
    /// The document is checked against the key it carries. That is sound
    /// here: the job reads the manifest from its own repository, and whoever
    /// can write there can change the job as well.
    pub fn from_owner(bytes: &[u8]) -> Result<Self, OpsError> {
        let bad = |why: &str| OpsError::Manifest(why.to_owned());
        let doc: SignedDoc =
            serde_json::from_slice(bytes).map_err(|e| OpsError::Manifest(e.to_string()))?;
        let decode = |text: &str| Base64UrlUnpadded::decode_vec(text).map_err(|_| bad("base64"));
        let oik: [u8; 32] = decode(&doc.key)?
            .try_into()
            .map_err(|_| bad("key length"))?;
        let sig: [u8; 64] = decode(&doc.sig)?
            .try_into()
            .map_err(|_| bad("signature length"))?;
        let payload = doc.body.as_bytes();
        doc::verify(&oik, DocKind::Owner, payload, &sig).map_err(|_| OpsError::Signature)?;

        let body: OwnerBody =
            serde_json::from_slice(payload).map_err(|e| OpsError::Manifest(e.to_string()))?;
        if body.v != 1 {
            return Err(bad("unsupported version"));
        }
        let params = EpochParams::new(body.epoch_len, body.grace, body.ttl)
            .map_err(|e| OpsError::Manifest(e.to_string()))?;
        let ntfy = body
            .buffers
            .into_iter()
            .filter(|b| b.kind == "ntfy")
            .filter_map(|b| b.url)
            // Only fetch from where an owner could plausibly mean: an https
            // origin, no credentials, no query.
            .filter(|url| url.starts_with("https://") && !url.contains(['@', '?', '#', ' ']))
            .map(|url| url.trim_end_matches('/').to_owned())
            .collect();
        Ok(Self {
            oik,
            params,
            pow_bits: body.pow.bits,
            ntfy,
        })
    }

    /// The URLs to poll: one per ntfy buffer, each returning the last twelve
    /// hours of the owner's topic as one JSON object per line.
    pub fn poll_urls(&self) -> Vec<String> {
        let topic = buffer::topic(&self.oik);
        self.ntfy
            .iter()
            .map(|base| format!("{base}/sy{topic}/json?poll=1&since=12h"))
            .collect()
    }
}

#[derive(Deserialize)]
struct NtfyLine {
    event: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HarvestReport {
    /// New drops written to the vault.
    pub stored: usize,
    /// Drops that were already there.
    pub duplicate: usize,
    /// Complete items that failed a check: weak stamp, wrong shape, or an
    /// epoch that no longer accepts deliveries.
    pub rejected: usize,
    /// Valid items left out because the run's limits were reached.
    pub deferred: usize,
}

impl fmt::Display for HarvestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stored={} duplicate={} rejected={} deferred={}",
            self.stored, self.duplicate, self.rejected, self.deferred
        )
    }
}

/// Read the output of an ntfy poll (one JSON object per line) and file every
/// acceptable drop under `vault/drops/e<epoch>/<eid>.bin`.
///
/// Running it again over the same input changes nothing: drops are named by
/// their hash.
pub fn harvest(
    config: &Config,
    ndjson: impl BufRead,
    vault: &Path,
    now: u64,
    limits: Limits,
) -> io::Result<HarvestReport> {
    let mut report = HarvestReport::default();
    let mut assembler = Assembler::new();
    let mut seen = HashSet::new();
    // (stamp bits, epoch, eid, envelope)
    let mut fresh: Vec<(u8, u32, [u8; 32], Vec<u8>)> = Vec::new();

    for line in ndjson.lines() {
        let line = line?;
        let Ok(parsed) = serde_json::from_str::<NtfyLine>(&line) else {
            continue;
        };
        if parsed.event.as_deref() != Some("message") {
            continue;
        }
        let Some(item) = parsed.message.and_then(|text| assembler.push(&text)) else {
            continue;
        };
        let Ok((stamp, envelope)) = buffer::check(&item, config.pow_bits) else {
            report.rejected += 1;
            continue;
        };
        let header = envelope::peek(envelope).expect("checked above");
        if !config.params.receiver_accepts(header.epoch, now) {
            report.rejected += 1;
            continue;
        }
        let eid = envelope::envelope_id(envelope);
        if !seen.insert(eid) {
            continue;
        }
        if drop_path(vault, header.epoch, &eid).exists() {
            report.duplicate += 1;
        } else {
            fresh.push((stamp.bits, header.epoch, eid, envelope.to_vec()));
        }
    }

    // Strongest stamps first, so that under a flood honest senders can still
    // get through by working harder than the flooder.
    fresh.sort_by_key(|item| std::cmp::Reverse(item.0));
    let mut bytes = 0;
    for (_, epoch, eid, envelope) in fresh {
        if report.stored >= limits.max_items || bytes + envelope.len() > limits.max_bytes {
            report.deferred += 1;
            continue;
        }
        let path = drop_path(vault, epoch, &eid);
        fs::create_dir_all(path.parent().expect("has a parent"))?;
        // Write beside the target and rename, so a crash never leaves a
        // half-written file under a name that claims a hash.
        let partial = path.with_extension("part");
        fs::write(&partial, &envelope)?;
        fs::rename(&partial, &path)?;
        bytes += envelope.len();
        report.stored += 1;
    }
    Ok(report)
}

fn drop_path(vault: &Path, epoch: u32, eid: &[u8; 32]) -> std::path::PathBuf {
    vault
        .join("drops")
        .join(format!("e{epoch}"))
        .join(format!("{}.bin", to_hex(eid)))
}

/// Delete `drops/e<epoch>/` for every epoch whose secret no longer exists:
/// nobody can open those drops any more. Returns the epochs removed.
pub fn expire(config: &Config, vault: &Path, now: u64) -> io::Result<Vec<u32>> {
    let drops = vault.join("drops");
    let mut removed = Vec::new();
    let entries = match fs::read_dir(&drops) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(removed),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(epoch) = name
            .to_str()
            .and_then(|n| n.strip_prefix('e'))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if config.params.state(epoch, now) == EpochState::Shredded {
            fs::remove_dir_all(entry.path())?;
            removed.push(epoch);
        }
    }
    removed.sort_unstable();
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sayso_core::keys::{OwnerKeys, SenderKeys};
    use sayso_core::payload::Payload;
    use sayso_core::{stamp, xwing};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    const NOW: u64 = 1_794_500_000;
    const BITS: u8 = 8;

    struct World {
        owner: OwnerKeys,
        config: Config,
        epoch_key: xwing::SecretKey,
        vault: PathBuf,
    }

    impl Drop for World {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.vault);
        }
    }

    fn manifest(owner: &OwnerKeys, body: &str) -> Vec<u8> {
        let sig = doc::sign(owner, DocKind::Owner, body.as_bytes());
        let b64 = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
        serde_json::to_vec(&serde_json::json!({
            "key": b64(owner.oik()),
            "sig": b64(&sig),
            "body": body,
        }))
        .unwrap()
    }

    fn body(buffers: &str) -> String {
        format!(
            r#"{{"v":1,"issued":1,"name":"t","epoch_len":604800,"grace":172800,"ttl":2592000,"receivers":[],"pow":{{"alg":1,"bits":{BITS}}},"buffers":{buffers}}}"#
        )
    }

    fn world() -> World {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let owner = OwnerKeys::from_root(&[1; 32]);
        let config = Config::from_owner(&manifest(
            &owner,
            &body(r#"[{"kind":"waku"},{"kind":"ntfy","url":"https://ntfy.example/"}]"#),
        ))
        .unwrap();
        let vault = std::env::temp_dir().join(format!(
            "sayso-ops-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        World {
            owner,
            config,
            epoch_key: xwing::SecretKey::from_seed(&[3; 32]),
            vault,
        }
    }

    /// A stamped drop from a distinct sender, sealed to `epoch`.
    fn drop_item(w: &World, n: u8, epoch: u32, bits: u8) -> Vec<u8> {
        let sender = SenderKeys::derive(&[n; 32], w.owner.oik());
        let mut payload = Payload::new([n; 16], 1);
        payload.text = Some(format!("message {n}"));
        let envelope =
            envelope::seal_drop(&sender, epoch, w.epoch_key.public(), &[n; 64], payload).unwrap();
        let stamp = stamp::search(&envelope::envelope_id(&envelope), bits, 0, u64::MAX)
            .unwrap()
            .unwrap();
        buffer::item(&stamp, &envelope)
    }

    /// What an ntfy poll would return for these items, with noise mixed in.
    fn feed(items: &[Vec<u8>]) -> String {
        let mut lines = vec![
            r#"{"id":"a","time":1,"event":"open","topic":"t"}"#.to_owned(),
            "not json".to_owned(),
        ];
        for item in items {
            for part in buffer::split(item).unwrap() {
                lines.push(format!(
                    r#"{{"id":"x","time":1,"event":"message","topic":"t","message":"{part}"}}"#
                ));
            }
        }
        lines.push(r#"{"id":"b","time":1,"event":"message","topic":"t","message":"hello from a stranger"}"#.to_owned());
        lines.join("\n")
    }

    fn stored(vault: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(epochs) = fs::read_dir(vault.join("drops")) else {
            return out;
        };
        for epoch in epochs.flatten() {
            for file in fs::read_dir(epoch.path()).unwrap().flatten() {
                out.push(format!(
                    "{}/{}",
                    epoch.file_name().to_string_lossy(),
                    file.file_name().to_string_lossy()
                ));
            }
        }
        out.sort();
        out
    }

    #[test]
    fn owner_doc_is_verified_and_read() {
        let w = world();
        assert_eq!(&w.config.oik, w.owner.oik());
        assert_eq!(w.config.pow_bits, BITS);
        assert_eq!(w.config.params, EpochParams::default());
        assert_eq!(
            w.config.poll_urls(),
            vec![format!(
                "https://ntfy.example/sy{}/json?poll=1&since=12h",
                buffer::topic(w.owner.oik())
            )]
        );
    }

    #[test]
    fn owner_doc_with_a_bad_signature_or_shape_is_refused() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let mut tampered = manifest(&owner, &body("[]"));
        // Change the signed body: `"name":"t"` becomes `"name":"u"`.
        let pattern = br#"\"name\":\"t"#;
        let at = tampered
            .windows(pattern.len())
            .position(|w| w == pattern)
            .unwrap()
            + pattern.len()
            - 1;
        tampered[at] = b'u';
        assert!(matches!(
            Config::from_owner(&tampered),
            Err(OpsError::Signature | OpsError::Manifest(_))
        ));
        assert!(matches!(
            Config::from_owner(b"{}"),
            Err(OpsError::Manifest(_))
        ));
        let wrong_version = body("[]").replace(r#""v":1"#, r#""v":2"#);
        assert!(matches!(
            Config::from_owner(&manifest(&owner, &wrong_version)),
            Err(OpsError::Manifest(_))
        ));
    }

    #[test]
    fn only_plain_https_buffers_are_polled() {
        let owner = OwnerKeys::from_root(&[1; 32]);
        let buffers = r#"[{"kind":"ntfy","url":"http://insecure.example"},{"kind":"ntfy","url":"https://u:p@evil.example"},{"kind":"ntfy","url":"https://ok.example"},{"kind":"ntfy","url":"file:///etc/passwd"},{"kind":"ntfy"}]"#;
        let config = Config::from_owner(&manifest(&owner, &body(buffers))).unwrap();
        assert_eq!(config.ntfy, vec!["https://ok.example".to_owned()]);
    }

    #[test]
    fn harvest_files_valid_drops_and_is_idempotent() {
        let w = world();
        let epoch = w.config.params.epoch_at(NOW);
        let items = vec![
            drop_item(&w, 10, epoch, BITS),
            drop_item(&w, 11, epoch, BITS),
        ];
        let input = feed(&items);

        let first = harvest(
            &w.config,
            input.as_bytes(),
            &w.vault,
            NOW,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            first,
            HarvestReport {
                stored: 2,
                ..Default::default()
            }
        );
        let files = stored(&w.vault);
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .all(|f| f.starts_with(&format!("e{epoch}/")) && f.ends_with(".bin"))
        );

        // What is in the vault is exactly the envelope, named by its hash,
        // and the owner can open it.
        for item in &items {
            let (_, envelope) = buffer::check(item, BITS).unwrap();
            let path = drop_path(&w.vault, epoch, &envelope::envelope_id(envelope));
            assert_eq!(fs::read(path).unwrap(), envelope);
            assert!(envelope::open_drop(&w.epoch_key, w.owner.oik(), envelope).is_ok());
        }

        let again = harvest(
            &w.config,
            input.as_bytes(),
            &w.vault,
            NOW,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            again,
            HarvestReport {
                duplicate: 2,
                ..Default::default()
            }
        );
        assert_eq!(stored(&w.vault), files);
    }

    #[test]
    fn harvest_rejects_weak_stamps_and_closed_epochs() {
        let w = world();
        let epoch = w.config.params.epoch_at(NOW);
        let weak = {
            // A valid item whose stamp claims fewer bits than the owner demands.
            let strong = drop_item(&w, 20, epoch, BITS);
            let (_, envelope) = buffer::check(&strong, BITS).unwrap();
            buffer::item(&stamp::Stamp { bits: 0, nonce: 0 }, envelope)
        };
        let retained = drop_item(&w, 21, epoch - 3, BITS);
        let far_future = drop_item(&w, 22, epoch + 2, BITS);
        let in_grace = drop_item(&w, 23, epoch - 1, BITS);
        // The previous epoch ended at most 7 days ago; pick a moment inside its 2-day grace.
        let now = w.config.params.start(epoch) + 3600;

        let report = harvest(
            &w.config,
            feed(&[weak, retained, far_future, in_grace]).as_bytes(),
            &w.vault,
            now,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            report,
            HarvestReport {
                stored: 1,
                rejected: 3,
                ..Default::default()
            }
        );
        assert!(stored(&w.vault)[0].starts_with(&format!("e{}/", epoch - 1)));
    }

    #[test]
    fn under_a_flood_the_strongest_stamps_are_kept() {
        let w = world();
        let epoch = w.config.params.epoch_at(NOW);
        let mut items: Vec<Vec<u8>> = (30..36).map(|n| drop_item(&w, n, epoch, BITS)).collect();
        let hard = drop_item(&w, 40, epoch, BITS + 6);
        items.insert(3, hard.clone());

        let limits = Limits {
            max_items: 2,
            max_bytes: usize::MAX,
        };
        let report = harvest(&w.config, feed(&items).as_bytes(), &w.vault, NOW, limits).unwrap();
        assert_eq!(
            report,
            HarvestReport {
                stored: 2,
                deferred: 5,
                ..Default::default()
            }
        );
        let (_, envelope) = buffer::check(&hard, BITS).unwrap();
        assert!(drop_path(&w.vault, epoch, &envelope::envelope_id(envelope)).exists());

        // A byte cap works the same way.
        let w2 = world();
        let limits = Limits {
            max_items: usize::MAX,
            max_bytes: 3204 * 3,
        };
        let report = harvest(&w2.config, feed(&items).as_bytes(), &w2.vault, NOW, limits).unwrap();
        assert_eq!((report.stored, report.deferred), (3, 4));
    }

    #[test]
    fn expire_removes_exactly_the_shredded_epochs() {
        let w = world();
        let epoch = w.config.params.epoch_at(NOW);
        // Shredded once now >= start + 7d + 30d: epoch - 6 is gone, epoch - 5 is not.
        for e in [epoch - 8, epoch - 6, epoch - 5, epoch] {
            let dir = w.vault.join("drops").join(format!("e{e}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("x.bin"), b"x").unwrap();
        }
        fs::create_dir_all(w.vault.join("drops").join("not-an-epoch")).unwrap();

        let removed = expire(&w.config, &w.vault, NOW).unwrap();
        assert_eq!(removed, vec![epoch - 8, epoch - 6]);
        assert!(
            w.vault
                .join("drops")
                .join(format!("e{}", epoch - 5))
                .exists()
        );
        assert!(w.vault.join("drops").join(format!("e{epoch}")).exists());
        assert!(w.vault.join("drops").join("not-an-epoch").exists());
        assert!(expire(&w.config, &w.vault, NOW).unwrap().is_empty());

        // No vault yet is not an error.
        assert!(
            expire(&w.config, &w.vault.join("missing"), NOW)
                .unwrap()
                .is_empty()
        );
    }
}
