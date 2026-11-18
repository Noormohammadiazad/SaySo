//! Prints test vectors for the TypeScript implementation in `web/src/crypto`:
//! every derivation, encoding and envelope the browser produces, computed
//! here by the reference implementation from fixed inputs.
//!
//!     cargo run -p sayso-wire --example vectors > web/src/crypto/vectors.json
//!
//! The keys are derived from fixed bytes. They protect nothing.

use sayso_core::doc::{self, DocKind};
use sayso_core::epoch::EpochParams;
use sayso_core::file::{self, FilePlan};
use sayso_core::keys::{self, OwnerKeys, SenderKeys};
use sayso_core::payload::{FileRef, Payload};
use sayso_core::{aead, buffer, envelope, invite, kdf, mailbox, stamp, to_hex, verified, xwing};
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> Value {
    Value::String(to_hex(bytes))
}

fn full_payload() -> Payload {
    let mut payload = Payload::new([7; 16], 1_794_300_000_123);
    payload.text = Some("hello, owner — ünïcode ✓".into());
    payload.files = Some(vec![FileRef {
        name: "report.pdf".into(),
        mime: "application/pdf".into(),
        size: 5000,
        root: [1; 32].into(),
        key: [2; 32].into(),
        padded_size: FilePlan::for_size(5000).padded,
    }]);
    payload.reply_to = Some([5; 16].into());
    payload.creds = Some(vec![vec![6; 80].into(), vec![9; 3].into()]);
    payload.ctl = Some(1);
    payload
}

fn main() {
    let owner_root = [1u8; 32];
    let owner = OwnerKeys::from_root(&owner_root);
    let sender = SenderKeys::derive(&[2; 32], owner.oik());
    let epoch_key = xwing::SecretKey::from_seed(&[3; 32]);

    // ---- primitives
    let kdf_cases: Vec<Value> = [
        ("sayso/v1/test", vec![b"".to_vec()]),
        ("sayso/v1/test", vec![b"abc".to_vec(), vec![0xff; 100]]),
        ("sayso/v1/envelope/id", vec![vec![0x42; 5000]]),
    ]
    .iter()
    .map(|(ctx, parts)| {
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        json!({ "ctx": ctx, "parts": parts.iter().map(|p| hex(p)).collect::<Vec<_>>(), "out": hex(&kdf::kdf(ctx, &refs)) })
    })
    .collect();
    let mac = json!({ "key": hex(&[9; 32]), "parts": [hex(b"sayso/v1/mbox"), hex(&7u32.to_be_bytes())], "out": hex(&kdf::mac(&[9; 32], &[b"sayso/v1/mbox", &7u32.to_be_bytes()])) });
    let wrap = json!({
        "key": hex(&[1; 32]), "nonce": hex(&[2; 24]), "aad": hex(b"epoch:7"), "msg": hex(b"secret seed"),
        "out": hex(&aead::wrap(&[1; 32], &[2; 24], b"epoch:7", b"secret seed")),
    });

    // ---- X-Wing
    let (ct, ss) = xwing::encapsulate(epoch_key.public(), &[4; 64]).unwrap();
    let xwing = json!({
        "seed": hex(&[3; 32]), "public": hex(epoch_key.public()),
        "entropy": hex(&[4; 64]), "ciphertext": hex(&ct), "shared": hex(&ss),
        "keyId": hex(&keys::key_id(epoch_key.public())),
    });

    // ---- keys
    let owner_v = json!({
        "root": hex(&owner_root), "oik": hex(owner.oik()), "store": hex(owner.store_key()),
        "wire0": hex(&OwnerKeys::wire_secret(&owner_root, 0)), "wire1": hex(&OwnerKeys::wire_secret(&owner_root, 1)),
        "fingerprint": keys::fingerprint(owner.oik()),
        "endpoint0": sayso_wire::endpoint_id_for(&OwnerKeys::wire_secret(&owner_root, 0)),
        "topic": buffer::topic(owner.oik()),
    });
    let sender_v = json!({
        "seed": hex(&[2; 32]), "sid": hex(sender.sid()), "replyPublic": hex(sender.reply_public()),
        "tagKey": hex(sender.tag_key()), "localKey": hex(sender.local_key()), "threadId": hex(&sender.thread_id()),
        "mailbox2966": mailbox::path(sender.tag_key(), 2966),
        "mailboxTopic": mailbox::topic(sender.tag_key()),
    });

    // ---- payloads
    let minimal = Payload::new([0; 16], 1);
    let payloads = json!([
        { "name": "minimal", "cbor": hex(&minimal.encode()) },
        { "name": "full", "cbor": hex(&full_payload().encode()) },
        { "name": "big-ts", "cbor": hex(&Payload::new([3; 16], u64::MAX).encode()) },
    ]);

    // ---- envelopes
    let mut text = Payload::new([7; 16], 1_794_300_000_000);
    text.text = Some("hello".into());
    let drop =
        envelope::seal_drop(&sender, 2966, epoch_key.public(), &[4; 64], text.clone()).unwrap();
    let mut full = full_payload();
    full.ctl = None;
    let drop_full =
        envelope::seal_drop(&sender, 2966, epoch_key.public(), &[8; 64], full.clone()).unwrap();
    let reply = envelope::seal_reply(
        &owner,
        sender.sid(),
        sender.reply_public(),
        2966,
        &[5; 64],
        &text,
    )
    .unwrap();
    let mut mbox = Vec::new();
    mailbox::append(&mut mbox, &reply).unwrap();
    mailbox::append(&mut mbox, &reply).unwrap();

    // ---- documents, invites, stamps, buffer
    let body = br#"{"v":1,"name":"Ada"}"#;
    let doc_sig = doc::sign(&owner, DocKind::Owner, body);
    let invite = invite::mint(&owner, [2; 16], "Ada from the lab", 2_000).unwrap();
    let verification =
        verified::mint(&owner, sender.sid(), "Ada, verified", 1_794_300_000).unwrap();
    let eid = envelope::envelope_id(&drop);
    let found = stamp::search(&eid, 12, 0, u64::MAX).unwrap().unwrap();
    let item = buffer::item(&found, &drop);

    // ---- files
    let sizes: Vec<u64> = vec![
        0,
        1,
        2,
        3,
        100,
        4095,
        4096,
        4097,
        5000,
        65_537,
        1 << 20,
        (1 << 20) + 1,
        10_000_000,
        123_456_789,
    ];
    let plans: Vec<Value> = sizes
        .iter()
        .map(|&size| {
            let plan = FilePlan::for_size(size);
            json!({ "size": size, "padme": file::padme(size), "padded": plan.padded, "chunks": plan.chunks, "totalCipher": plan.total_cipher() })
        })
        .collect();
    let plan = FilePlan::for_size(5000);
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
    let chunk = file::encrypt_chunk(&[5; 32], &plan, 0, &data).unwrap();
    let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| file::leaf(&[i; 40])).collect();
    let roots: Vec<Value> = (1..=5)
        .map(|n| json!({ "n": n, "total": 1000 * n as u64, "root": hex(&file::merkle_root(&leaves[..n], 1000 * n as u64).unwrap()) }))
        .collect();

    // ---- epochs
    let params = EpochParams::default();
    let times: Vec<u64> = vec![
        0,
        86_400 * 36,
        1_794_300_000,
        1_794_300_000 + 604_800 * 3 + 17,
    ];
    let epochs: Vec<Value> = times
        .iter()
        .map(|&now| {
            let live = params.live(now);
            let published = params.published(now);
            let e = params.epoch_at(now);
            let around = [e.saturating_sub(6), e.saturating_sub(1), e, e + 1, e + 2];
            let states: Vec<Value> = around
                .iter()
                .map(|&x| {
                    json!({
                        "e": x,
                        "state": format!("{:?}", params.state(x, now)).to_lowercase(),
                        "senderMaySeal": params.sender_may_seal(x, now),
                        "receiverAccepts": params.receiver_accepts(x, now),
                        "shredAt": params.shred_at(x),
                    })
                })
                .collect();
            json!({
                "now": now, "at": e,
                "live": [live.start(), live.end()], "published": [published.start(), published.end()],
                "states": states,
            })
        })
        .collect();

    let out = json!({
        "comment": "Generated by `cargo run -p sayso-wire --example vectors`. Do not edit.",
        "kdf": kdf_cases, "mac": mac, "hash": { "msg": hex(b"abc"), "out": hex(&kdf::hash(b"abc")) },
        "wrap": wrap, "xwing": xwing, "owner": owner_v, "sender": sender_v, "payloads": payloads,
        "envelopes": {
            "epochSeed": hex(&[3; 32]),
            "drop": { "entropy": hex(&[4; 64]), "epoch": 2966, "payload": hex(&text.encode()), "bytes": hex(&drop), "eid": hex(&eid) },
            "dropFull": { "entropy": hex(&[8; 64]), "epoch": 2966, "payload": hex(&full.encode()), "bytes": hex(&drop_full) },
            "reply": { "entropy": hex(&[5; 64]), "epoch": 2966, "payload": hex(&text.encode()), "bytes": hex(&reply) },
            "mailbox": hex(&mbox),
        },
        "doc": { "body": hex(body), "sig": hex(&doc_sig) },
        "invite": { "id": hex(&[2; 16]), "label": "Ada from the lab", "notAfter": 2000, "bytes": hex(&invite) },
        "verified": { "label": "Ada, verified", "issued": 1_794_300_000u64, "bytes": hex(&verification) },
        "stamp": { "eid": hex(&eid), "bits": 12, "nonce": found.nonce.to_string(), "encoded": hex(&found.encode()) },
        "buffer": { "item": hex(&item), "parts": buffer::split(&item).unwrap() },
        "file": {
            "plans": plans,
            "chunk": { "key": hex(&[5; 32]), "size": 5000, "cipherLen": chunk.len(), "cipherHash": hex(&kdf::hash(&chunk)), "leaf": hex(&file::leaf(&chunk)) },
            "leaves": leaves.iter().map(|l| hex(l)).collect::<Vec<_>>(),
            "roots": roots,
        },
        "epochs": epochs,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
