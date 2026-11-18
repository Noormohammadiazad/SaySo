//! The dialing side: a sender.

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::time::{Duration, timeout};
use sayso_core::envelope::{self, EID_LEN};
use sayso_core::file::{HASH_LEN, Manifest};
use sayso_core::stamp::Stamp;

use crate::frame::*;
use crate::{ALPN, Result};

/// How long a receiver may take to acknowledge an envelope, unless the
/// caller chose otherwise with [`Client::set_ack_timeout`].
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// A live connection to one receiver.
///
/// The endpoint behind it has a fresh random key, so two sessions by the same
/// sender cannot be linked at the transport.
pub struct Client {
    endpoint: Endpoint,
    conn: Connection,
    ack_timeout: Duration,
}

impl Client {
    /// Dial a receiver by the endpoint id from the owner manifest, over the
    /// public relays. [`WireError::Timeout`] means nobody is home.
    pub async fn connect(receiver: &str, limit: Duration) -> Result<Self> {
        let id: EndpointId = receiver
            .parse()
            .map_err(|_| WireError::Connect("invalid receiver id".into()))?;
        let endpoint = crate::public_endpoint()
            .bind()
            .await
            .map_err(|err| WireError::Connect(err.to_string()))?;
        Self::connect_with(endpoint, id, limit).await
    }

    /// Dial from an endpoint the caller configured.
    pub async fn connect_with(
        endpoint: Endpoint,
        receiver: impl Into<EndpointAddr>,
        limit: Duration,
    ) -> Result<Self> {
        let outcome = timeout(limit, endpoint.connect(receiver, ALPN)).await;
        match outcome {
            Ok(Ok(conn)) => Ok(Self {
                endpoint,
                conn,
                ack_timeout: ACK_TIMEOUT,
            }),
            Ok(Err(err)) => {
                endpoint.close().await;
                Err(WireError::Connect(err.to_string()))
            }
            Err(_) => {
                endpoint.close().await;
                Err(WireError::Timeout)
            }
        }
    }

    /// Change how long [`Client::deliver`] waits for the acknowledgement.
    pub fn set_ack_timeout(&mut self, limit: Duration) {
        self.ack_timeout = limit;
    }

    async fn open(&self) -> Result<(SendStream, RecvStream)> {
        self.conn.open_bi().await.map_err(closed)
    }

    /// Hand over one envelope. Returns once the receiver acknowledged it by id.
    pub async fn deliver(&self, stamp: &Stamp, envelope: &[u8]) -> Result<[u8; EID_LEN]> {
        envelope::peek(envelope)?;
        let eid = envelope::envelope_id(envelope);
        let (mut send, mut recv) = self.open().await?;
        write_frame(&mut send, DROP, &[&stamp.encode()[..], envelope].concat()).await?;
        send.finish().map_err(closed)?;
        // A receiver that vanished without closing is only noticed by QUIC
        // after its idle timeout; an honest one answers in milliseconds.
        let answer = timeout(self.ack_timeout, expect_frame(&mut recv, MAX_SHORT))
            .await
            .map_err(|_| WireError::Timeout)??;
        match answer {
            (ACK, body) if body == eid => Ok(eid),
            (ACK, _) => Err(WireError::Protocol("acknowledged a different envelope")),
            (kind, body) => Err(unexpected(kind, &body)),
        }
    }

    /// Start, or resume, uploading a file's encrypted chunks.
    pub async fn put(&self, manifest: &Manifest) -> Result<PutStream> {
        if manifest.chunks() > MAX_FILE_CHUNKS {
            return Err(WireError::Refused(ErrCode::TooLarge));
        }
        let (mut send, mut recv) = self.open().await?;
        let mut body = file_head(&manifest.root, manifest.chunks(), manifest.total_cipher);
        body.extend_from_slice(&manifest.leaf_bytes());
        write_frame(&mut send, PUT, &body).await?;
        let next = match expect_frame(&mut recv, MAX_SHORT).await? {
            (HAVE, body) => u64_at(&body, 0).ok_or(WireError::Protocol("bad HAVE"))?,
            (kind, body) => return Err(unexpected(kind, &body)),
        };
        if next > manifest.chunks() {
            return Err(WireError::Protocol("receiver wants a chunk past the end"));
        }
        Ok(PutStream {
            send,
            recv,
            root: manifest.root,
            chunks: manifest.chunks(),
            next,
        })
    }

    /// Start downloading a file's encrypted chunks from index `first`.
    /// `root` must come from a sealed envelope: it is what every chunk is
    /// checked against.
    pub async fn get(&self, root: [u8; HASH_LEN], first: u64) -> Result<GetStream> {
        let (mut send, mut recv) = self.open().await?;
        let mut body = root.to_vec();
        body.extend_from_slice(&first.to_be_bytes());
        write_frame(&mut send, GET, &body).await?;
        send.finish().map_err(closed)?;
        let manifest = match expect_frame(&mut recv, MAX_FILE_META).await? {
            (META, body) => {
                let chunks = u64_at(&body, 0).ok_or(WireError::Protocol("bad META"))?;
                let total = u64_at(&body, 8).ok_or(WireError::Protocol("bad META"))?;
                if chunks > MAX_FILE_CHUNKS {
                    return Err(WireError::Protocol("file has too many chunks"));
                }
                Manifest::verify(root, chunks, total, &body[16..])?
            }
            (kind, body) => return Err(unexpected(kind, &body)),
        };
        if first > manifest.chunks() {
            return Err(WireError::Protocol("start index past the end"));
        }
        Ok(GetStream {
            recv,
            manifest,
            next: first,
        })
    }

    /// Open the stream on which the receiver pushes replies for the thread
    /// this connection is bound to.
    pub async fn listen(&self) -> Result<Listener> {
        let (mut send, recv) = self.open().await?;
        write_frame(&mut send, LISTEN, &[]).await?;
        Ok(Listener { send, recv })
    }

    /// Resolves when the connection is gone, with the reason.
    pub async fn closed(&self) -> String {
        self.conn.closed().await.to_string()
    }

    /// Say goodbye and release the endpoint. Takes `&self` so a caller that
    /// is still awaiting [`Client::closed`] can close.
    pub async fn close(&self) {
        self.conn.close(0u32.into(), b"done");
        self.endpoint.close().await;
    }
}

/// An upload in progress. Chunks go strictly in order, starting at
/// [`PutStream::next_index`].
pub struct PutStream {
    send: SendStream,
    recv: RecvStream,
    root: [u8; HASH_LEN],
    chunks: u64,
    next: u64,
}

impl PutStream {
    /// The first chunk the receiver does not have yet.
    pub fn next_index(&self) -> u64 {
        self.next
    }

    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    /// Send chunk `index`, which must be the next one.
    pub async fn chunk(&mut self, index: u64, cipher: &[u8]) -> Result<()> {
        if index != self.next || index >= self.chunks {
            return Err(WireError::Protocol("chunk out of order"));
        }
        let mut body = Vec::with_capacity(8 + cipher.len());
        body.extend_from_slice(&index.to_be_bytes());
        body.extend_from_slice(cipher);
        write_frame(&mut self.send, CHUNK, &body).await?;
        self.next += 1;
        Ok(())
    }

    /// Finish the upload. Returns once the receiver has every chunk stored.
    pub async fn finish(mut self) -> Result<()> {
        if self.next != self.chunks {
            return Err(WireError::Protocol("upload is incomplete"));
        }
        write_frame(&mut self.send, FIN, &[]).await?;
        self.send.finish().map_err(closed)?;
        match expect_frame(&mut self.recv, MAX_SHORT).await? {
            (STORED, body) if body == self.root => Ok(()),
            (kind, body) => Err(unexpected(kind, &body)),
        }
    }
}

/// A download in progress. Every chunk handed out has been checked against
/// the manifest, which was checked against the root.
pub struct GetStream {
    recv: RecvStream,
    manifest: Manifest,
    next: u64,
}

impl GetStream {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The next chunk and its index, or `None` when the file is complete.
    pub async fn next_chunk(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        match expect_frame(&mut self.recv, MAX_CHUNK_FRAME).await? {
            (CHUNK, body) => {
                let index = u64_at(&body, 0).ok_or(WireError::Protocol("bad CHUNK"))?;
                if index != self.next {
                    return Err(WireError::Protocol("chunk out of order"));
                }
                let cipher = body[8..].to_vec();
                self.manifest.check_chunk(index, &cipher)?;
                self.next += 1;
                Ok(Some((index, cipher)))
            }
            (FIN, _) if self.next == self.manifest.chunks() => Ok(None),
            (FIN, _) => Err(WireError::Protocol("file ended early")),
            (kind, body) => Err(unexpected(kind, &body)),
        }
    }
}

/// Replies pushed by the receiver while the sender is connected.
pub struct Listener {
    send: SendStream,
    recv: RecvStream,
}

impl Listener {
    /// The next reply envelope, or `None` when the receiver ended the stream.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>> {
        match read_frame(&mut self.recv, MAX_ENVELOPE_FRAME).await? {
            None => Ok(None),
            Some((REPLY, envelope)) => {
                envelope::peek(&envelope)?;
                Ok(Some(envelope))
            }
            Some((kind, body)) => Err(unexpected(kind, &body)),
        }
    }

    /// Tell the receiver a reply arrived and was opened, so it need not be
    /// published to a mailbox.
    pub async fn seen(&mut self, eid: &[u8; EID_LEN]) -> Result<()> {
        write_frame(&mut self.send, SEEN, eid).await
    }
}

const MAX_ENVELOPE_FRAME: usize = envelope::MAX_ENVELOPE;
