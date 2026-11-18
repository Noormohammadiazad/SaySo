//! The receiving side: the owner's dashboard, or a courier.

use core::fmt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, SecretKey};
use n0_future::task;
use sayso_core::envelope::{self, EID_LEN};
use sayso_core::file::{HASH_LEN, Manifest};
use sayso_core::stamp::{STAMP_LEN, Stamp};
use tokio::sync::oneshot;

use crate::frame::*;
use crate::{ALPN, Result};

/// How the application answers one request.
pub type Respond<T> = oneshot::Sender<core::result::Result<T, ErrCode>>;

/// One thing a connected sender asked for. Events that expect an answer carry
/// a [`Respond`]; dropping it without answering refuses the request as busy.
#[derive(Debug)]
pub enum Incoming {
    /// A sender connected.
    Opened { conn: u64 },
    /// An envelope, already checked for shape. Answer `Ok` to acknowledge it.
    Drop {
        conn: u64,
        stamp: Stamp,
        envelope: Vec<u8>,
        respond: Respond<()>,
    },
    /// A sender wants to upload this file. The leaf list is already verified
    /// against the root. Answer with the first chunk index still missing.
    PutBegin {
        conn: u64,
        manifest: Manifest,
        respond: Respond<u64>,
    },
    /// The next chunk of an upload, already checked against its leaf.
    PutChunk {
        conn: u64,
        root: [u8; HASH_LEN],
        index: u64,
        cipher: Vec<u8>,
        respond: Respond<()>,
    },
    /// Every chunk of the upload was delivered.
    PutEnd {
        conn: u64,
        root: [u8; HASH_LEN],
        respond: Respond<()>,
    },
    /// A sender asks for a file by root. Answer with its manifest.
    GetBegin {
        conn: u64,
        root: [u8; HASH_LEN],
        respond: Respond<Manifest>,
    },
    /// Provide one encrypted chunk of a download.
    GetChunk {
        conn: u64,
        root: [u8; HASH_LEN],
        index: u64,
        respond: Respond<Vec<u8>>,
    },
    /// The sender is ready to receive pushed replies.
    Listening { conn: u64 },
    /// The sender opened a pushed reply.
    Seen { conn: u64, eid: [u8; EID_LEN] },
    /// The sender is gone.
    Closed { conn: u64 },
}

struct Shared {
    events: async_channel::Sender<Incoming>,
    listeners: Mutex<HashMap<u64, async_channel::Sender<Vec<u8>>>>,
    next_conn: AtomicU64,
}

impl Shared {
    async fn emit(&self, event: Incoming) {
        // A closed channel means the server was dropped; nothing to report to.
        let _ = self.events.send(event).await;
    }

    /// Put a request to the application and wait for its answer.
    async fn ask<T>(
        &self,
        make: impl FnOnce(Respond<T>) -> Incoming,
    ) -> core::result::Result<T, ErrCode> {
        let (respond, answer) = oneshot::channel();
        self.emit(make(respond)).await;
        answer.await.unwrap_or(Err(ErrCode::Busy))
    }
}

/// A running receiver. Poll [`Server::next`] in a loop and answer each event.
pub struct Server {
    router: Router,
    events: async_channel::Receiver<Incoming>,
    shared: Arc<Shared>,
}

impl Server {
    /// Start a receiver on the public relays under a fixed secret key, so its
    /// endpoint id is the one published in the owner manifest.
    pub async fn start(secret_key: &[u8; 32]) -> Result<Self> {
        let endpoint = crate::public_endpoint()
            .secret_key(SecretKey::from_bytes(secret_key))
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|err| WireError::Connect(err.to_string()))?;
        Ok(Self::with_endpoint(endpoint))
    }

    /// Serve on an endpoint the caller configured. It must accept [`ALPN`].
    pub fn with_endpoint(endpoint: Endpoint) -> Self {
        let (sender, events) = async_channel::bounded(64);
        let shared = Arc::new(Shared {
            events: sender,
            listeners: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
        });
        let router = Router::builder(endpoint)
            .accept(ALPN, Handler(shared.clone()))
            .spawn();
        Self {
            router,
            events,
            shared,
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    /// The id senders dial.
    pub fn endpoint_id(&self) -> String {
        self.router.endpoint().id().to_string()
    }

    /// Resolves once the receiver is reachable through a relay.
    pub async fn online(&self) {
        self.router.endpoint().online().await
    }

    /// The next request from any connected sender; `None` after shutdown.
    pub async fn next(&self) -> Option<Incoming> {
        self.events.recv().await.ok()
    }

    /// Push a reply envelope to a connected sender. `false` means that sender
    /// is not listening, and the reply has to go to a mailbox instead.
    pub async fn push_reply(&self, conn: u64, envelope: Vec<u8>) -> bool {
        let listener = self
            .shared
            .listeners
            .lock()
            .expect("lock")
            .get(&conn)
            .cloned();
        match listener {
            Some(listener) => listener.send(envelope).await.is_ok(),
            None => false,
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.router.shutdown().await;
        self.events.close();
    }
}

#[derive(Clone)]
struct Handler(Arc<Shared>);

impl fmt::Debug for Handler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sayso_wire::Handler")
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        let shared = self.0.clone();
        let conn = shared.next_conn.fetch_add(1, Ordering::Relaxed);
        shared.emit(Incoming::Opened { conn }).await;
        // One task per stream, so a long upload never blocks a message.
        while let Ok((send, recv)) = connection.accept_bi().await {
            let shared = shared.clone();
            task::spawn(async move {
                let _ = serve_stream(shared, conn, send, recv).await;
            });
        }
        shared.listeners.lock().expect("lock").remove(&conn);
        shared.emit(Incoming::Closed { conn }).await;
        Ok(())
    }
}

async fn refuse(send: &mut SendStream, code: ErrCode) -> Result<()> {
    write_frame(send, ERR, &[code as u8]).await?;
    send.finish().map_err(closed)
}

async fn serve_stream(
    shared: Arc<Shared>,
    conn: u64,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    // The first frame decides what the stream is; none of them outsizes a
    // file's leaf list.
    let Some((kind, body)) = read_frame(&mut recv, MAX_FILE_META).await? else {
        return Ok(());
    };
    match kind {
        DROP => serve_drop(&shared, conn, &mut send, body).await,
        PUT => serve_put(&shared, conn, &mut send, &mut recv, body).await,
        GET => serve_get(&shared, conn, &mut send, body).await,
        LISTEN => serve_listen(&shared, conn, send, recv).await,
        _ => refuse(&mut send, ErrCode::Malformed).await,
    }
}

async fn serve_drop(
    shared: &Shared,
    conn: u64,
    send: &mut SendStream,
    body: Vec<u8>,
) -> Result<()> {
    if body.len() > MAX_DROP {
        return refuse(send, ErrCode::TooLarge).await;
    }
    let Some((stamp, envelope)) = body.split_at_checked(STAMP_LEN) else {
        return refuse(send, ErrCode::Malformed).await;
    };
    let (Ok(stamp), Ok(_)) = (Stamp::decode(stamp), envelope::peek(envelope)) else {
        return refuse(send, ErrCode::Malformed).await;
    };
    let eid = envelope::envelope_id(envelope);
    let envelope = envelope.to_vec();
    match shared
        .ask(|respond| Incoming::Drop {
            conn,
            stamp,
            envelope,
            respond,
        })
        .await
    {
        Ok(()) => {
            write_frame(send, ACK, &eid).await?;
            send.finish().map_err(closed)
        }
        Err(code) => refuse(send, code).await,
    }
}

async fn serve_put(
    shared: &Shared,
    conn: u64,
    send: &mut SendStream,
    recv: &mut RecvStream,
    body: Vec<u8>,
) -> Result<()> {
    let parsed = (|| {
        let root: [u8; HASH_LEN] = body.get(..HASH_LEN)?.try_into().ok()?;
        let chunks = u64_at(&body, HASH_LEN)?;
        let total = u64_at(&body, HASH_LEN + 8)?;
        Some((root, chunks, total))
    })();
    let Some((root, chunks, total)) = parsed else {
        return refuse(send, ErrCode::Malformed).await;
    };
    if chunks > MAX_FILE_CHUNKS {
        return refuse(send, ErrCode::TooLarge).await;
    }
    let Ok(manifest) = Manifest::verify(root, chunks, total, &body[FILE_HEAD..]) else {
        return refuse(send, ErrCode::Malformed).await;
    };

    let mut next = match shared
        .ask(|respond| Incoming::PutBegin {
            conn,
            manifest: manifest.clone(),
            respond,
        })
        .await
    {
        Ok(next) if next <= chunks => next,
        Ok(_) => return refuse(send, ErrCode::Busy).await,
        Err(code) => return refuse(send, code).await,
    };
    write_frame(send, HAVE, &next.to_be_bytes()).await?;

    loop {
        match expect_frame(recv, MAX_CHUNK_FRAME).await? {
            (CHUNK, body) => {
                let cipher = match u64_at(&body, 0) {
                    Some(index) if index == next => body[8..].to_vec(),
                    _ => return refuse(send, ErrCode::Malformed).await,
                };
                if manifest.check_chunk(next, &cipher).is_err() {
                    return refuse(send, ErrCode::Malformed).await;
                }
                let index = next;
                if let Err(code) = shared
                    .ask(|respond| Incoming::PutChunk {
                        conn,
                        root,
                        index,
                        cipher,
                        respond,
                    })
                    .await
                {
                    return refuse(send, code).await;
                }
                next += 1;
            }
            (FIN, _) if next == chunks => {
                return match shared
                    .ask(|respond| Incoming::PutEnd {
                        conn,
                        root,
                        respond,
                    })
                    .await
                {
                    Ok(()) => {
                        write_frame(send, STORED, &root).await?;
                        send.finish().map_err(closed)
                    }
                    Err(code) => refuse(send, code).await,
                };
            }
            _ => return refuse(send, ErrCode::Malformed).await,
        }
    }
}

async fn serve_get(shared: &Shared, conn: u64, send: &mut SendStream, body: Vec<u8>) -> Result<()> {
    let parsed = (|| {
        let root: [u8; HASH_LEN] = body.get(..HASH_LEN)?.try_into().ok()?;
        Some((root, u64_at(&body, HASH_LEN)?))
    })();
    let Some((root, first)) = parsed else {
        return refuse(send, ErrCode::Malformed).await;
    };
    let manifest = match shared
        .ask(|respond| Incoming::GetBegin {
            conn,
            root,
            respond,
        })
        .await
    {
        Ok(manifest) if manifest.root == root && first <= manifest.chunks() => manifest,
        Ok(_) => return refuse(send, ErrCode::Malformed).await,
        Err(code) => return refuse(send, code).await,
    };
    let mut meta = Vec::with_capacity(16 + manifest.leaves.len() * HASH_LEN);
    meta.extend_from_slice(&manifest.chunks().to_be_bytes());
    meta.extend_from_slice(&manifest.total_cipher.to_be_bytes());
    meta.extend_from_slice(&manifest.leaf_bytes());
    write_frame(send, META, &meta).await?;

    for index in first..manifest.chunks() {
        let cipher = match shared
            .ask(|respond| Incoming::GetChunk {
                conn,
                root,
                index,
                respond,
            })
            .await
        {
            Ok(cipher) => cipher,
            Err(code) => return refuse(send, code).await,
        };
        let mut body = Vec::with_capacity(8 + cipher.len());
        body.extend_from_slice(&index.to_be_bytes());
        body.extend_from_slice(&cipher);
        write_frame(send, CHUNK, &body).await?;
    }
    write_frame(send, FIN, &[]).await?;
    send.finish().map_err(closed)
}

async fn serve_listen(
    shared: &Arc<Shared>,
    conn: u64,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let (replies, outbox) = async_channel::bounded::<Vec<u8>>(16);
    shared.listeners.lock().expect("lock").insert(conn, replies);
    shared.emit(Incoming::Listening { conn }).await;

    // Replies flow out on one task while acknowledgements are read here.
    let writer = task::spawn(async move {
        while let Ok(envelope) = outbox.recv().await {
            if write_frame(&mut send, REPLY, &envelope).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    let outcome = loop {
        match read_frame(&mut recv, MAX_SHORT).await {
            Ok(Some((SEEN, body))) => match <[u8; EID_LEN]>::try_from(&body[..]) {
                Ok(eid) => shared.emit(Incoming::Seen { conn, eid }).await,
                Err(_) => break Err(WireError::Protocol("bad SEEN")),
            },
            Ok(Some(_)) => break Err(WireError::Protocol("unexpected frame")),
            Ok(None) => break Ok(()),
            Err(err) => break Err(err),
        }
    };
    // Dropping the registered sender ends the writer task.
    shared.listeners.lock().expect("lock").remove(&conn);
    writer.abort();
    outcome
}
