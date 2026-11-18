//! The Live Wire transport for JavaScript.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use n0_future::time::Duration;
use sayso_core::file::Manifest;
use sayso_core::stamp::Stamp;
use sayso_wire::{Client, ErrCode, GetStream, Incoming, Listener, PutStream, Respond, Server};
use serde::Serialize;
use serde_bytes::ByteBuf;
use wasm_bindgen::prelude::*;

use crate::util::*;

fn manifest_from(root: &[u8], leaves: &[u8], total_cipher: f64) -> Result<Manifest, JsValue> {
    let chunks = (leaves.len() / 32) as u64;
    Manifest::verify(
        array(root, "file root")?,
        chunks,
        uint(total_cipher, "file length")?,
        leaves,
    )
    .map_err(core_err)
}

// ---- dialer ----------------------------------------------------------------

/// A sender's live connection to one receiver.
#[wasm_bindgen]
pub struct WireClient {
    inner: Client,
}

#[wasm_bindgen]
impl WireClient {
    /// Dial a receiver by endpoint id. Rejects with `kind: "timeout"` when
    /// nobody answers within `timeout_ms`.
    pub async fn connect(receiver: String, timeout_ms: u32) -> Result<WireClient, JsValue> {
        let inner = Client::connect(&receiver, Duration::from_millis(timeout_ms as u64))
            .await
            .map_err(wire_err)?;
        Ok(WireClient { inner })
    }

    /// Hand over one envelope with its stamp. Resolves with the envelope id
    /// once the receiver acknowledged it.
    pub async fn deliver(&self, stamp: Vec<u8>, envelope: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let stamp = Stamp::decode(&stamp).map_err(core_err)?;
        let eid = self
            .inner
            .deliver(&stamp, &envelope)
            .await
            .map_err(wire_err)?;
        Ok(eid.to_vec())
    }

    /// Start or resume uploading a file's encrypted chunks.
    pub async fn put(
        &self,
        root: Vec<u8>,
        leaves: Vec<u8>,
        total_cipher: f64,
    ) -> Result<WirePut, JsValue> {
        let manifest = manifest_from(&root, &leaves, total_cipher)?;
        let inner = self.inner.put(&manifest).await.map_err(wire_err)?;
        Ok(WirePut { inner: Some(inner) })
    }

    /// Start downloading a file's encrypted chunks from index `first`.
    pub async fn get(&self, root: Vec<u8>, first: f64) -> Result<WireGet, JsValue> {
        let inner = self
            .inner
            .get(array(&root, "file root")?, uint(first, "chunk index")?)
            .await
            .map_err(wire_err)?;
        Ok(WireGet { inner })
    }

    /// Open the stream of replies pushed by the receiver.
    pub async fn listen(&self) -> Result<WireListener, JsValue> {
        Ok(WireListener {
            inner: self.inner.listen().await.map_err(wire_err)?,
        })
    }

    /// Resolves with the reason once the connection is gone.
    pub async fn closed(&self) -> String {
        self.inner.closed().await
    }

    /// Say goodbye and release the endpoint.
    pub async fn close(&self) {
        self.inner.close().await
    }
}

/// An upload in progress.
#[wasm_bindgen]
pub struct WirePut {
    inner: Option<PutStream>,
}

#[wasm_bindgen]
impl WirePut {
    fn stream(&mut self) -> Result<&mut PutStream, JsValue> {
        self.inner
            .as_mut()
            .ok_or_else(|| bad_input("upload: already finished"))
    }

    /// The first chunk the receiver does not have yet.
    #[wasm_bindgen(getter, js_name = nextIndex)]
    pub fn next_index(&self) -> f64 {
        self.inner.as_ref().map_or(0.0, |s| s.next_index() as f64)
    }

    /// Send chunk `index`; chunks go strictly in order from `nextIndex`.
    pub async fn chunk(&mut self, index: f64, cipher: Vec<u8>) -> Result<(), JsValue> {
        let index = uint(index, "chunk index")?;
        self.stream()?.chunk(index, &cipher).await.map_err(wire_err)
    }

    /// Resolves once the receiver has stored every chunk.
    pub async fn finish(&mut self) -> Result<(), JsValue> {
        let stream = self
            .inner
            .take()
            .ok_or_else(|| bad_input("upload: already finished"))?;
        stream.finish().await.map_err(wire_err)
    }
}

/// A download in progress. Every chunk is verified before it is handed out.
#[wasm_bindgen]
pub struct WireGet {
    inner: GetStream,
}

#[derive(Serialize)]
struct JsChunk {
    index: f64,
    cipher: ByteBuf,
}

#[wasm_bindgen]
impl WireGet {
    #[wasm_bindgen(getter)]
    pub fn chunks(&self) -> f64 {
        self.inner.manifest().chunks() as f64
    }

    /// `{ index, cipher }` for the next chunk, or `undefined` at the end.
    pub async fn next(&mut self) -> Result<JsValue, JsValue> {
        Ok(match self.inner.next_chunk().await.map_err(wire_err)? {
            Some((index, cipher)) => to_js(&JsChunk {
                index: index as f64,
                cipher: ByteBuf::from(cipher),
            }),
            None => JsValue::UNDEFINED,
        })
    }
}

/// Replies pushed by the receiver while the sender stays connected.
#[wasm_bindgen]
pub struct WireListener {
    inner: Listener,
}

#[wasm_bindgen]
impl WireListener {
    /// The next reply envelope, or `undefined` when the stream ended.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner.next().await.map_err(wire_err)
    }

    /// Tell the receiver a reply was opened.
    pub async fn seen(&mut self, eid: Vec<u8>) -> Result<(), JsValue> {
        self.inner
            .seen(&array(&eid, "envelope id")?)
            .await
            .map_err(wire_err)
    }
}

// ---- receiver --------------------------------------------------------------

/// The endpoint id a receiver started with this secret will have, without
/// starting it.
#[wasm_bindgen(js_name = endpointIdFor)]
pub fn endpoint_id_for(secret_key: &[u8]) -> Result<String, JsValue> {
    Ok(sayso_wire::endpoint_id_for(&array(
        secret_key,
        "wire secret",
    )?))
}

enum Pending {
    Unit(Respond<()>),
    Index(Respond<u64>),
    Manifest(Respond<Manifest>),
    Chunk(Respond<Vec<u8>>),
}

/// One request from a connected sender, as a plain object. Events with an
/// `id` must be answered with one of the `accept*` methods or `refuse`.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct JsEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    conn: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stamp: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    envelope: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunks: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_cipher: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cipher: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eid: Option<ByteBuf>,
}

/// The receiving side of Live Wire: the owner's dashboard.
#[wasm_bindgen]
pub struct WireServer {
    inner: Server,
    pending: RefCell<HashMap<u32, Pending>>,
    next_id: Cell<u32>,
}

#[wasm_bindgen]
impl WireServer {
    /// Start receiving under the endpoint key derived for this receiver slot.
    pub async fn start(secret_key: Vec<u8>) -> Result<WireServer, JsValue> {
        let inner = Server::start(&array(&secret_key, "wire secret")?)
            .await
            .map_err(wire_err)?;
        Ok(WireServer {
            inner,
            pending: RefCell::new(HashMap::new()),
            next_id: Cell::new(1),
        })
    }

    /// The id senders dial; goes into the owner manifest.
    #[wasm_bindgen(getter, js_name = endpointId)]
    pub fn endpoint_id(&self) -> String {
        self.inner.endpoint_id()
    }

    /// Resolves once the receiver is reachable through a relay.
    pub async fn online(&self) {
        self.inner.online().await
    }

    fn park(&self, pending: Pending) -> Option<u32> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1).max(1));
        self.pending.borrow_mut().insert(id, pending);
        Some(id)
    }

    /// The next event, or `null` after shutdown.
    pub async fn next(&self) -> JsValue {
        let Some(event) = self.inner.next().await else {
            return JsValue::NULL;
        };
        let bytes = |b: &[u8]| Some(ByteBuf::from(b.to_vec()));
        let js = match event {
            Incoming::Opened { conn } => JsEvent {
                kind: "opened",
                conn: conn as f64,
                ..Default::default()
            },
            Incoming::Closed { conn } => JsEvent {
                kind: "closed",
                conn: conn as f64,
                ..Default::default()
            },
            Incoming::Listening { conn } => JsEvent {
                kind: "listening",
                conn: conn as f64,
                ..Default::default()
            },
            Incoming::Seen { conn, eid } => JsEvent {
                kind: "seen",
                conn: conn as f64,
                eid: bytes(&eid),
                ..Default::default()
            },
            Incoming::Drop {
                conn,
                stamp,
                envelope,
                respond,
            } => JsEvent {
                kind: "drop",
                conn: conn as f64,
                id: self.park(Pending::Unit(respond)),
                stamp: bytes(&stamp.encode()),
                envelope: Some(ByteBuf::from(envelope)),
                ..Default::default()
            },
            Incoming::PutBegin {
                conn,
                manifest,
                respond,
            } => JsEvent {
                kind: "putBegin",
                conn: conn as f64,
                id: self.park(Pending::Index(respond)),
                root: bytes(&manifest.root),
                chunks: Some(manifest.chunks() as f64),
                total_cipher: Some(manifest.total_cipher as f64),
                ..Default::default()
            },
            Incoming::PutChunk {
                conn,
                root,
                index,
                cipher,
                respond,
            } => JsEvent {
                kind: "putChunk",
                conn: conn as f64,
                id: self.park(Pending::Unit(respond)),
                root: bytes(&root),
                index: Some(index as f64),
                cipher: Some(ByteBuf::from(cipher)),
                ..Default::default()
            },
            Incoming::PutEnd {
                conn,
                root,
                respond,
            } => JsEvent {
                kind: "putEnd",
                conn: conn as f64,
                id: self.park(Pending::Unit(respond)),
                root: bytes(&root),
                ..Default::default()
            },
            Incoming::GetBegin {
                conn,
                root,
                respond,
            } => JsEvent {
                kind: "getBegin",
                conn: conn as f64,
                id: self.park(Pending::Manifest(respond)),
                root: bytes(&root),
                ..Default::default()
            },
            Incoming::GetChunk {
                conn,
                root,
                index,
                respond,
            } => JsEvent {
                kind: "getChunk",
                conn: conn as f64,
                id: self.park(Pending::Chunk(respond)),
                root: bytes(&root),
                index: Some(index as f64),
                ..Default::default()
            },
        };
        to_js(&js)
    }

    fn take(&self, id: u32) -> Result<Pending, JsValue> {
        self.pending
            .borrow_mut()
            .remove(&id)
            .ok_or_else(|| bad_input("request id"))
    }

    /// Accept a `drop`, `putChunk` or `putEnd`.
    pub fn accept(&self, id: u32) -> Result<(), JsValue> {
        match self.take(id)? {
            Pending::Unit(respond) => drop(respond.send(Ok(()))),
            _ => return Err(bad_input("answer for this request")),
        }
        Ok(())
    }

    /// Accept a `putBegin`, saying which chunk index to start from.
    #[wasm_bindgen(js_name = acceptFrom)]
    pub fn accept_from(&self, id: u32, next_index: f64) -> Result<(), JsValue> {
        let next = uint(next_index, "chunk index")?;
        match self.take(id)? {
            Pending::Index(respond) => drop(respond.send(Ok(next))),
            _ => return Err(bad_input("answer for this request")),
        }
        Ok(())
    }

    /// Answer a `getBegin` with the stored file's leaf list and length.
    #[wasm_bindgen(js_name = acceptFile)]
    pub fn accept_file(
        &self,
        id: u32,
        root: &[u8],
        leaves: &[u8],
        total_cipher: f64,
    ) -> Result<(), JsValue> {
        let manifest = manifest_from(root, leaves, total_cipher)?;
        match self.take(id)? {
            Pending::Manifest(respond) => drop(respond.send(Ok(manifest))),
            _ => return Err(bad_input("answer for this request")),
        }
        Ok(())
    }

    /// Answer a `getChunk` with the stored encrypted chunk.
    #[wasm_bindgen(js_name = acceptChunk)]
    pub fn accept_chunk(&self, id: u32, cipher: Vec<u8>) -> Result<(), JsValue> {
        match self.take(id)? {
            Pending::Chunk(respond) => drop(respond.send(Ok(cipher))),
            _ => return Err(bad_input("answer for this request")),
        }
        Ok(())
    }

    /// Refuse any request with a protocol error code (1 malformed, 2 stamp
    /// too weak, 3 epoch not accepted, 4 too large, 5 not found, 6 busy).
    pub fn refuse(&self, id: u32, code: u8) -> Result<(), JsValue> {
        let code = ErrCode::from_byte(code).ok_or_else(|| bad_input("error code"))?;
        match self.take(id)? {
            Pending::Unit(respond) => drop(respond.send(Err(code))),
            Pending::Index(respond) => drop(respond.send(Err(code))),
            Pending::Manifest(respond) => drop(respond.send(Err(code))),
            Pending::Chunk(respond) => drop(respond.send(Err(code))),
        }
        Ok(())
    }

    /// Push a reply to a connected sender. Resolves `false` if that sender
    /// is not listening, in which case the reply belongs in a mailbox.
    #[wasm_bindgen(js_name = pushReply)]
    pub async fn push_reply(&self, conn: f64, envelope: Vec<u8>) -> Result<bool, JsValue> {
        Ok(self
            .inner
            .push_reply(uint(conn, "connection")?, envelope)
            .await)
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown().await
    }
}
