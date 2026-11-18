//! A sender and a receiver in one process, connected directly (no relay, no
//! network beyond loopback), exercising every exchange of the wire protocol.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sayso_core::envelope::{self, envelope_id};
use sayso_core::file::{self, CHUNK, FilePlan, Manifest};
use sayso_core::keys::{OwnerKeys, SenderKeys};
use sayso_core::payload::Payload;
use sayso_core::stamp::{self, Stamp};
use sayso_core::xwing;
use sayso_wire::iroh::endpoint::presets;
use sayso_wire::iroh::{Endpoint, EndpointAddr, RelayMode};
use sayso_wire::{ALPN, Client, ErrCode, Incoming, Server, WireError};

const REQUIRED_BITS: u8 = 8;

/// What a receiving application keeps: a stand-in for the dashboard.
#[derive(Default)]
struct Store {
    drops: Vec<Vec<u8>>,
    manifests: HashMap<[u8; 32], Manifest>,
    chunks: HashMap<([u8; 32], u64), Vec<u8>>,
    finished: Vec<[u8; 32]>,
    seen: Vec<[u8; 32]>,
    listening: Vec<u64>,
    closed: Vec<u64>,
}

/// An endpoint bound to loopback only: the tests need no network at all.
async fn endpoint(accept: bool) -> Endpoint {
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("loopback address");
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    builder.bind().await.expect("bind")
}

fn loopback_addr(endpoint: &Endpoint) -> EndpointAddr {
    EndpointAddr::new(endpoint.id()).with_ip_addr(endpoint.bound_sockets()[0])
}

/// Start a receiver whose application logic is the minimal honest one.
async fn receiver() -> (Arc<Server>, Arc<Mutex<Store>>) {
    let server = Arc::new(Server::with_endpoint(endpoint(true).await));
    let store = Arc::new(Mutex::new(Store::default()));
    tokio::spawn({
        let (server, store) = (server.clone(), store.clone());
        async move {
            while let Some(event) = server.next().await {
                let mut store = store.lock().unwrap();
                match event {
                    Incoming::Drop {
                        stamp,
                        envelope,
                        respond,
                        ..
                    } => {
                        let answer = if stamp.verify(&envelope_id(&envelope), REQUIRED_BITS) {
                            store.drops.push(envelope);
                            Ok(())
                        } else {
                            Err(ErrCode::WeakStamp)
                        };
                        let _ = respond.send(answer);
                    }
                    Incoming::PutBegin {
                        manifest, respond, ..
                    } => {
                        let root = manifest.root;
                        let have = (0..manifest.chunks())
                            .take_while(|i| store.chunks.contains_key(&(root, *i)))
                            .count() as u64;
                        store.manifests.insert(root, manifest);
                        let _ = respond.send(Ok(have));
                    }
                    Incoming::PutChunk {
                        root,
                        index,
                        cipher,
                        respond,
                        ..
                    } => {
                        store.chunks.insert((root, index), cipher);
                        let _ = respond.send(Ok(()));
                    }
                    Incoming::PutEnd { root, respond, .. } => {
                        store.finished.push(root);
                        let _ = respond.send(Ok(()));
                    }
                    Incoming::GetBegin { root, respond, .. } => {
                        let _ = respond
                            .send(store.manifests.get(&root).cloned().ok_or(ErrCode::NotFound));
                    }
                    Incoming::GetChunk {
                        root,
                        index,
                        respond,
                        ..
                    } => {
                        let _ = respond.send(
                            store
                                .chunks
                                .get(&(root, index))
                                .cloned()
                                .ok_or(ErrCode::NotFound),
                        );
                    }
                    Incoming::Listening { conn } => store.listening.push(conn),
                    Incoming::Seen { eid, .. } => store.seen.push(eid),
                    Incoming::Closed { conn } => store.closed.push(conn),
                    Incoming::Opened { .. } => {}
                }
            }
        }
    });
    (server, store)
}

async fn dial(server: &Server) -> Client {
    Client::connect_with(
        endpoint(false).await,
        loopback_addr(server.endpoint()),
        Duration::from_secs(10),
    )
    .await
    .expect("connect")
}

struct Keys {
    owner: OwnerKeys,
    sender: SenderKeys,
    epoch: xwing::SecretKey,
}

fn keys() -> Keys {
    let owner = OwnerKeys::from_root(&[1; 32]);
    let sender = SenderKeys::derive(&[2; 32], owner.oik());
    Keys {
        owner,
        sender,
        epoch: xwing::SecretKey::from_seed(&[3; 32]),
    }
}

fn sealed_drop(keys: &Keys, text: &str) -> Vec<u8> {
    let mut payload = Payload::new([7; 16], 1);
    payload.text = Some(text.into());
    envelope::seal_drop(&keys.sender, 9, keys.epoch.public(), &[4; 64], payload).unwrap()
}

fn stamp_for(envelope: &[u8], bits: u8) -> Stamp {
    stamp::search(&envelope_id(envelope), bits, 0, u64::MAX)
        .unwrap()
        .unwrap()
}

/// Encrypt `data` and return the manifest a receiver would check it against.
fn encrypted_file(data: &[u8]) -> (Manifest, Vec<Vec<u8>>) {
    let plan = FilePlan::for_size(data.len() as u64);
    let chunks: Vec<Vec<u8>> = (0..plan.chunks)
        .map(|i| {
            let start = (i as usize * CHUNK).min(data.len());
            let end = start + plan.data_len(i).unwrap();
            file::encrypt_chunk(&[5; 32], &plan, i, &data[start..end]).unwrap()
        })
        .collect();
    let leaves: Vec<[u8; 32]> = chunks.iter().map(|c| file::leaf(c)).collect();
    let root = file::merkle_root(&leaves, plan.total_cipher()).unwrap();
    let manifest =
        Manifest::verify(root, plan.chunks, plan.total_cipher(), &leaves.concat()).unwrap();
    (manifest, chunks)
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test]
async fn envelope_is_delivered_acknowledged_and_opens_at_the_owner() {
    let keys = keys();
    let (server, store) = receiver().await;
    let client = dial(&server).await;

    let envelope = sealed_drop(&keys, "over the wire");
    let eid = client
        .deliver(&stamp_for(&envelope, REQUIRED_BITS), &envelope)
        .await
        .unwrap();
    assert_eq!(eid, envelope_id(&envelope));

    let stored = store.lock().unwrap().drops[0].clone();
    let opened = envelope::open_drop(&keys.epoch, keys.owner.oik(), &stored).unwrap();
    assert_eq!(opened.payload.text.as_deref(), Some("over the wire"));
    client.close().await;
}

#[tokio::test]
async fn weak_stamp_and_malformed_envelope_are_refused() {
    let keys = keys();
    let (server, store) = receiver().await;
    let client = dial(&server).await;

    let envelope = sealed_drop(&keys, "cheap");
    let weak = Stamp { bits: 0, nonce: 0 };
    let refused = client.deliver(&weak, &envelope).await.unwrap_err();
    assert!(
        matches!(refused, WireError::Refused(ErrCode::WeakStamp)),
        "{refused}"
    );

    // The client refuses to send bytes that are not an envelope at all.
    assert!(matches!(
        client.deliver(&weak, b"junk").await,
        Err(WireError::Core(_))
    ));
    assert!(store.lock().unwrap().drops.is_empty());
    client.close().await;
}

#[tokio::test]
async fn file_upload_resumes_after_a_dropped_connection() {
    let data: Vec<u8> = (0..(2 * CHUNK + 4321)).map(|i| (i % 253) as u8).collect();
    let (manifest, chunks) = encrypted_file(&data);
    assert_eq!(manifest.chunks(), 3);
    let (server, store) = receiver().await;

    // First attempt: one chunk, then the sender vanishes.
    let client = dial(&server).await;
    let mut put = client.put(&manifest).await.unwrap();
    assert_eq!(put.next_index(), 0);
    put.chunk(0, &chunks[0]).await.unwrap();
    eventually("first chunk stored", || {
        store.lock().unwrap().chunks.len() == 1
    })
    .await;
    drop(put);
    client.close().await;

    // Second attempt, new connection: the receiver asks for chunk 1 onwards.
    let client = dial(&server).await;
    let mut put = client.put(&manifest).await.unwrap();
    assert_eq!(put.next_index(), 1);
    for index in 1..3 {
        put.chunk(index, &chunks[index as usize]).await.unwrap();
    }
    put.finish().await.unwrap();

    let store = store.lock().unwrap();
    assert_eq!(store.finished, vec![manifest.root]);
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(&store.chunks[&(manifest.root, index as u64)], chunk);
    }
}

#[tokio::test]
async fn corrupted_chunk_is_refused_and_never_stored() {
    let (manifest, mut chunks) = encrypted_file(&vec![9u8; CHUNK + 10]);
    let (server, store) = receiver().await;
    let client = dial(&server).await;

    chunks[0][100] ^= 1;
    let mut put = client.put(&manifest).await.unwrap();
    put.chunk(0, &chunks[0]).await.unwrap();
    put.chunk(1, &chunks[1]).await.ok();
    let outcome = put.finish().await;
    assert!(
        matches!(
            outcome,
            Err(WireError::Refused(ErrCode::Malformed)) | Err(WireError::Closed(_))
        ),
        "{outcome:?}"
    );
    assert!(store.lock().unwrap().chunks.is_empty());
    assert!(store.lock().unwrap().finished.is_empty());
    client.close().await;
}

#[tokio::test]
async fn a_leaf_list_that_does_not_match_its_root_is_refused() {
    let (mut manifest, _) = encrypted_file(&vec![9u8; 5000]);
    let (server, _) = receiver().await;
    let client = dial(&server).await;
    manifest.leaves[0][0] ^= 1;
    let outcome = client.put(&manifest).await.map(|_| ());
    assert!(
        matches!(outcome, Err(WireError::Refused(ErrCode::Malformed))),
        "{outcome:?}"
    );
    client.close().await;
}

#[tokio::test]
async fn file_download_is_verified_and_can_start_midway() {
    let data: Vec<u8> = (0..(2 * CHUNK + 99)).map(|i| (i % 241) as u8).collect();
    let (manifest, chunks) = encrypted_file(&data);
    let (server, store) = receiver().await;
    {
        let mut store = store.lock().unwrap();
        store.manifests.insert(manifest.root, manifest.clone());
        for (index, chunk) in chunks.iter().enumerate() {
            store
                .chunks
                .insert((manifest.root, index as u64), chunk.clone());
        }
    }
    let client = dial(&server).await;

    let mut get = client.get(manifest.root, 0).await.unwrap();
    assert_eq!(get.manifest(), &manifest);
    let mut received = Vec::new();
    while let Some((index, cipher)) = get.next_chunk().await.unwrap() {
        assert_eq!(index, received.len() as u64);
        received.push(cipher);
    }
    assert_eq!(received, chunks);

    let mut get = client.get(manifest.root, 2).await.unwrap();
    assert_eq!(get.next_chunk().await.unwrap().unwrap().0, 2);
    assert!(get.next_chunk().await.unwrap().is_none());

    let missing = client.get([0; 32], 0).await.map(|_| ());
    assert!(
        matches!(missing, Err(WireError::Refused(ErrCode::NotFound))),
        "{missing:?}"
    );

    // A receiver that serves a tampered chunk is caught by the client.
    store
        .lock()
        .unwrap()
        .chunks
        .get_mut(&(manifest.root, 1))
        .unwrap()[7] ^= 1;
    let mut get = client.get(manifest.root, 0).await.unwrap();
    assert!(get.next_chunk().await.unwrap().is_some());
    assert!(matches!(get.next_chunk().await, Err(WireError::Core(_))));
    client.close().await;
}

#[tokio::test]
async fn replies_are_pushed_to_a_listening_sender_and_acknowledged() {
    let keys = keys();
    let (server, store) = receiver().await;
    let client = dial(&server).await;

    // Nobody is listening yet, so a push reports that it went nowhere.
    assert!(!server.push_reply(1, vec![0; 8]).await);

    let mut listener = client.listen().await.unwrap();
    eventually("listener registered", || {
        !store.lock().unwrap().listening.is_empty()
    })
    .await;
    let conn = store.lock().unwrap().listening[0];

    let mut payload = Payload::new([8; 16], 2);
    payload.text = Some("live reply".into());
    let reply = envelope::seal_reply(
        &keys.owner,
        keys.sender.sid(),
        keys.sender.reply_public(),
        9,
        &[6; 64],
        &payload,
    )
    .unwrap();
    assert!(server.push_reply(conn, reply.clone()).await);

    let received = listener.next().await.unwrap().expect("a reply");
    let opened = envelope::open_reply(&keys.sender, &received).unwrap();
    assert_eq!(opened.payload.text.as_deref(), Some("live reply"));
    listener.seen(&opened.eid).await.unwrap();
    eventually("seen recorded", || {
        store.lock().unwrap().seen == vec![envelope_id(&reply)]
    })
    .await;

    client.close().await;
    eventually("close reported", || {
        store.lock().unwrap().closed == vec![conn]
    })
    .await;
    assert!(
        !server.push_reply(conn, reply).await,
        "a departed sender cannot be pushed to"
    );
}

#[tokio::test]
async fn dialing_an_absent_receiver_fails_within_the_limit() {
    let nobody = sayso_wire::iroh::SecretKey::generate().public();
    let started = std::time::Instant::now();
    let outcome = Client::connect_with(endpoint(false).await, nobody, Duration::from_secs(2)).await;
    assert!(matches!(
        outcome,
        Err(WireError::Timeout) | Err(WireError::Connect(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn a_receiver_that_never_answers_times_out_the_delivery() {
    // A receiver whose application takes requests and sits on them: what a
    // sender sees when the owner's tab froze or vanished without closing.
    let server = Arc::new(Server::with_endpoint(endpoint(true).await));
    let held = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn({
        let (server, held) = (server.clone(), held.clone());
        async move {
            while let Some(event) = server.next().await {
                held.lock().unwrap().push(event);
            }
        }
    });

    let keys = keys();
    let mut client = dial(&server).await;
    client.set_ack_timeout(Duration::from_millis(300));
    let envelope = sealed_drop(&keys, "anyone there?");

    let started = std::time::Instant::now();
    let outcome = client
        .deliver(&stamp_for(&envelope, REQUIRED_BITS), &envelope)
        .await;
    assert!(matches!(outcome, Err(WireError::Timeout)), "{outcome:?}");
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(3));

    // The request did reach the application; it was the answer that never came.
    let reached = held
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, Incoming::Drop { .. }));
    assert!(reached);
    assert_eq!(
        sayso_wire::ACK_TIMEOUT,
        Duration::from_secs(10),
        "the default a browser sender gets"
    );
    client.close().await;
}

#[tokio::test]
async fn the_endpoint_id_is_known_before_the_receiver_starts() {
    let secret = [42u8; 32];
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("loopback address")
        .secret_key(sayso_wire::iroh::SecretKey::from_bytes(&secret))
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("bind");
    let server = Server::with_endpoint(endpoint);
    assert_eq!(sayso_wire::endpoint_id_for(&secret), server.endpoint_id());
    assert_ne!(
        sayso_wire::endpoint_id_for(&[43u8; 32]),
        server.endpoint_id()
    );
    server.shutdown().await;
}
