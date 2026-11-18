//! Writes what `ops/test-harvest.sh` needs, valid for the current time: a
//! signed owner.json and the relay output for two stamped drops.
//!
//!     cargo run -p sayso-ops --example fixtures -- <dir>
//!
//! Every key here is derived from fixed bytes. They protect nothing and must
//! never be used for a real inbox.

use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, path::PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use sayso_core::doc::{self, DocKind};
use sayso_core::epoch::EpochParams;
use sayso_core::keys::{OwnerKeys, SenderKeys};
use sayso_core::payload::Payload;
use sayso_core::{buffer, envelope, stamp, xwing};

const BITS: u8 = 12;

fn main() {
    let dir = PathBuf::from(env::args().nth(1).expect("usage: fixtures <dir>"));
    fs::create_dir_all(&dir).expect("create the output directory");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    let owner = OwnerKeys::from_root(&[0x11; 32]);
    let params = EpochParams::default();
    let body = format!(
        r#"{{"v":1,"issued":{now},"name":"Fixture","epoch_len":{},"grace":{},"ttl":{},"receivers":[],"pow":{{"alg":1,"bits":{BITS}}},"buffers":[]}}"#,
        params.epoch_len, params.grace, params.ttl
    );
    let b64 = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
    let sig = doc::sign(&owner, DocKind::Owner, body.as_bytes());
    let signed = serde_json::json!({ "key": b64(owner.oik()), "sig": b64(&sig), "body": body });
    fs::write(dir.join("owner.json"), signed.to_string()).expect("write owner.json");

    let epoch = params.epoch_at(now);
    let epoch_key = xwing::SecretKey::from_seed(&[0x22; 32]);
    let mut lines = Vec::new();
    for n in 1..=2u8 {
        let sender = SenderKeys::derive(&[n; 32], owner.oik());
        let mut payload = Payload::new([n; 16], now * 1000);
        payload.text = Some(format!("fixture message {n}"));
        let sealed = envelope::seal_drop(&sender, epoch, epoch_key.public(), &[n; 64], payload)
            .expect("seal");
        let found = stamp::search(&envelope::envelope_id(&sealed), BITS, 0, u64::MAX)
            .expect("search")
            .expect("stamp");
        for part in buffer::split(&buffer::item(&found, &sealed)).expect("split") {
            lines.push(format!(
                r#"{{"id":"m{}","time":{now},"event":"message","topic":"t","message":"{part}"}}"#,
                lines.len()
            ));
        }
    }
    fs::write(dir.join("relay.ndjson"), lines.join("\n") + "\n").expect("write relay output");
    println!(
        "wrote owner.json and relay.ndjson ({} parts) to {}",
        lines.len(),
        dir.display()
    );
}
