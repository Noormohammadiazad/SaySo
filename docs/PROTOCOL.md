# Sayso protocol, version 1

This is the normative description of what Sayso puts on the wire and at rest.
`crates/sayso-core` is the reference implementation; where the two disagree,
that is a bug in one of them.

## 1. Conventions

- All integers are big-endian. `u32(x)` is 4 bytes, `u64(x)` is 8.
- `||` is concatenation. `b64u` is unpadded base64url.
- `KDF(ctx, ikm)` is BLAKE3 in `derive_key` mode with context string `ctx`,
  32 bytes of output unless a length is given.
- `MAC(key, msg)` is BLAKE3 keyed hash, 32 bytes.
- Every context string starts with `sayso/v1/`.

### Suite `0x0001`

| Role | Primitive | Sizes |
|---|---|---|
| KEM | X-Wing (ML-KEM-768 + X25519) | public key 1216, ciphertext 1120, secret seed 32, shared secret 32 |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | key 32, nonce 12, tag 16 |
| Signature | Ed25519 | public key 32, signature 64 |
| Hash, KDF, MAC | BLAKE3 | 32 |
| Records at rest on a device | XChaCha20-Poly1305 | key 32, random nonce 24, tag 16 |

The KEM is hybrid because sealed envelopes may sit in public for their whole
lifetime and can be copied by anyone; confidentiality has to survive a future
quantum adversary. Signatures only need to hold when they are checked, so
Ed25519 is enough for now. The 2-byte suite field in every envelope is the
upgrade path.

## 2. Keys

### Owner

| Key | Derivation | Lifetime |
|---|---|---|
| `root` | 32 random bytes, kept in the key vault (section 10) | long-term |
| `OIK` (identity) | Ed25519 from `KDF("sayso/v1/owner/ident", root)` | long-term, the trust anchor |
| wire key, slot `n` | Ed25519 from `KDF("sayso/v1/owner/wire", root \|\| u32(n))` | long-term; slot 0 is the dashboard |
| store key | `KDF("sayso/v1/owner/store", root)` | wraps the dashboard's archive in browser storage |
| epoch secret `e` | **32 random bytes**, an X-Wing seed | one epoch, then destroyed (section 3) |

Epoch secrets are never derived from `root`. A derived key can be regenerated,
so it cannot be destroyed. They live in the key vault next to `root` and leave
it when they expire.

### Sender

A sender has one 32-byte `seed`: the output of their passkey's PRF, or random
bytes kept in the browser and exported as a resume link (`#k=<b64u seed>`).
Everything else is derived, and bound to the owner it talks to:

| Key | Derivation |
|---|---|
| identity `SID` | Ed25519 from `KDF("sayso/v1/sender/ident", seed \|\| OIK)` |
| reply key | X-Wing from seed `KDF("sayso/v1/sender/reply", seed \|\| OIK)` |
| tag key | `KDF("sayso/v1/sender/tag", seed \|\| OIK)` |
| local key | `KDF("sayso/v1/sender/local", seed \|\| OIK)` |

`thread_id = KDF("sayso/v1/thread", SID \|\| OIK)[..16]`.

The sender is stateless by design: nothing but `seed` is needed to resume a
thread on any device. The price is that the reply key cannot be destroyed, so
replies (owner to sender) do not get a cryptographic TTL, only deletion.

## 3. Epochs and the TTL state machine

Time is cut into epochs of `L` seconds: `e = floor(unix_time / L)`, and epoch
`e` starts at `s = e * L`. The owner manifest fixes three durations:

| Parameter | Meaning | Default |
|---|---|---|
| `L` (`epoch_len`) | length of an epoch | 7 days |
| `G` (`grace`) | how long after an epoch ends late deliveries are still accepted | 2 days |
| `T` (`ttl`) | how long after an epoch ends its drops stay readable | 30 days |

`G <= T`. Each epoch key moves through five states, driven only by the clock:

```
SCHEDULED ──s──▶ ACTIVE ──s+L──▶ GRACE ──s+L+G──▶ RETAINED ──s+L+T──▶ SHREDDED
```

| State | Senders seal to it | Receivers accept drops | Owner can decrypt |
|---|---|---|---|
| SCHEDULED | no (yes within 1 h of `s`, for clock skew) | same | yes |
| ACTIVE | yes | yes | yes |
| GRACE | no | yes | yes |
| RETAINED | no | no | yes |
| SHREDDED | no | no | **no, the secret no longer exists** |

Every drop is therefore readable for at least `T` and at most `T + L` after it
was sealed.

"Receivers accept" is about custody: it limits how late a party may take a
drop in. A live receiver applies it when a drop arrives, and the harvest job
applies it when it files a drop in the vault. A drop already in custody, in
the vault or still on a relay, is opened later by the dashboard with any
epoch secret that still exists.

Only the owner's dashboard holds epoch secrets, so only it can advance the
machine. On every start and then hourly it runs `tick`:

1. Generate secrets for any epoch in `[now, now + H]` that has none (`H` = 4
   epochs of lookahead) and publish the public halves in `epochs.json`.
2. For every stored epoch whose state is SHREDDED: collect what is still
   waiting for it on the relays and in the vault, then overwrite and delete
   the secret and raise `shredded_before`.
3. Delete `mail/e<e>/` and `blob/e<e>/` for every epoch below
   `shredded_before` and commit `data/` as a single parentless commit, so the
   expired files are not reachable from the branch. The harvest job does the
   same for `drops/e<e>/` on the vault branch.

Step 2 means an owner who was away longer than `T + L` still reads what
arrived, once, before the key goes. The guarantee is about the future: after
the tick, no copy of that ciphertext is readable by anyone.

Epoch secrets live on one owner device. Syncing them through the repo would
turn destruction back into deletion, so multi-device owners need a direct
device-to-device transfer, which is not in version 1.

## 4. Envelope

An envelope is the only thing any transport or store ever sees.

```
Envelope = Header (20) || KemCt (1120) || Sealed (padded length + 16)

Header
  offset size  field
  0      4     magic     "SYSO" (53 59 53 4F)
  4      1     version   0x01
  5      1     kind      0x01 DROP (sender to owner), 0x02 REPLY (owner to sender)
  6      2     suite     0x0001
  8      4     epoch     owner epoch index
  12     8     key_hint  DROP: KeyId(epoch public key)[..8]; REPLY: zero
```

`KeyId(pk) = KDF("sayso/v1/key-id", pk)`. The hint is zero on replies because
the reply key is long-lived and a hint would link a sender's replies together.

### Sealing

```
(ss, KemCt) = XWing.Encaps(pk_recipient)
ikm    = ss || Header || KeyId(pk_recipient)
key    = KDF("sayso/v1/envelope/key", ikm)
nonce  = KDF("sayso/v1/envelope/nonce", ikm)[..12]
Sealed = ChaCha20-Poly1305(key, nonce, aad = Header || KemCt, Pad(Inner))
```

Each envelope has a fresh encapsulation, so `key` is used exactly once.

`Pad(m) = u32(len(m)) || m || zeros`, with total length the smallest power of
two that fits, from 2^11 to 2^17. Anything larger travels as a file.

`eid = KDF("sayso/v1/envelope/id", Envelope)` names the envelope everywhere: it
is the file name in a store, the dedupe key across transports, and the value
acknowledged on the wire.

### Inner

```
Inner = Sig (64) || Signer (32) || Payload (CBOR)
Sig   = Ed25519.Sign(sk_signer,
          "sayso/v1/envelope/sig" || Header || BLAKE3(KemCt) || Peer || Signer || Payload)
```

- DROP: `Signer = SID`, `Peer = OIK`.
- REPLY: `Signer = OIK`, `Peer = SID`. The sender rejects any other signer.

The signature is inside the ciphertext, so observers never see who sent a drop.
It covers the header and the encapsulation, so a signed payload cannot be
lifted out and re-sealed to someone else or into another epoch.

### Payload

CBOR map with integer keys, definite lengths.

| Key | Field | Type | Notes |
|---|---|---|---|
| 1 | `id` | bytes(16) | random message id |
| 2 | `ts` | uint | sender clock, Unix milliseconds |
| 3 | `text` | text | optional |
| 4 | `files` | array of File | optional |
| 5 | `hello` | map | DROP only, required: `{1: reply public key (1216), 2: tag key (32)}` |
| 6 | `reply_to` | bytes(16) | optional |
| 7 | `creds` | array of bytes | optional invites or proofs (section 8) |
| 8 | `ctl` | uint | optional control, see below |

`File = {1: name, 2: mime, 3: size, 4: root (32), 5: key (32), 6: padded_size}`.

The owner drops duplicates by `eid` and by `(Signer, id)`.

A payload with `ctl` carries no message to show; it tells the other side of
the same thread to do something. Each is sealed and signed like any other
envelope, so it can only come from that thread's other party:

| `ctl` | Name | Meaning |
|---|---|---|
| 1 | presence | binds a live connection to the thread |
| 2 | delete | delete the message whose `id` is `reply_to`; with no `reply_to`, every message with `ts` up to this payload's `ts` |
| 3 | ack | owner to sender: the drop whose `id` is `reply_to` arrived |
| 4 | verified | owner to sender: `creds[0]` is a verification (section 8); absent `creds` withdraws it |

Replays are harmless: every control is idempotent, and nothing whose `ts`
is at or before a whole-thread deletion is taken back in.

## 5. Files

A file is encrypted once, by the sender, and is then an opaque list of chunks
that any party can verify and resume without holding a key.

```
C      = 2^20                          plaintext bytes per chunk
P      = max(4096, Padme(size))        plaintext zero-padded to P bytes
n      = ceil(P / C)
ct[i]  = ChaCha20-Poly1305(file_key, nonce = u32(0) || u64(i),
                           aad = "sayso/v1/chunk" || u64(n), chunk i)
leaf[i]= KDF("sayso/v1/merkle/leaf", ct[i])
node   = KDF("sayso/v1/merkle/node", left || right)
root   = KDF("sayso/v1/merkle/root", u64(n) || u64(total ciphertext bytes) || top)
```

`file_key` is 32 random bytes and never reused. The tree has the RFC 6962
shape: split at the largest power of two below the leaf count. `Padme` rounds
up so that at most about 12% is added and the size leaks only
`O(log log size)` bits. The 4096-byte floor keeps tiny files from revealing
their exact length.

`root` is the file's identity. The key and root travel in a `File` entry inside
a sealed envelope; the chunks travel separately, in the clear as far as the
transport is concerned.

## 6. Reply mailboxes

Replies that could not be delivered live are published where a sender with no
account can read them:

```
addr(e) = MAC(tag_key, "sayso/v1/mbox" || u32(e))[..16]
path    = mail/e<e>/<hex(addr(e))>.bin
file    = repeated ( u32(len) || REPLY envelope )
```

A sender polls the path, under the site's copy of `data/` from main,
for every epoch that is not yet SHREDDED. Addresses in
different epochs cannot be linked to each other or to the sender without the
tag key.

Replies are also pushed live, the moment they are sealed, to the thread's
mailbox topic on every relay the owner lists (section 11):

```
topic = "sm" || hex( KDF("sayso/v1/mbox-topic", tag_key)[..20] )
```

One topic per thread for all epochs, so a sender subscribes once; as
unlinkable as the addresses. A reply envelope travels there in the same
`S1` parts as a buffer item, without a stamp; the sender keeps only what
opens under its reply key and verifies as the owner's.

## 7. Stamps

A stamp is proof of work that lets a receiver refuse bulk junk before storing
anything. It rides next to an envelope and is not part of it.

```
Stamp = alg (1) = 0x01 || bits (1) || nonce (8)
valid = leading_zero_bits(KDF("sayso/v1/stamp", eid || nonce)) >= bits
        and bits >= the receiver's required bits
```

`alg` exists so a memory-hard function can replace plain hashing later.

## 8. Verified senders

An invite is a bearer credential the owner hands to someone out of band:

```
Invite = Sig (64) || Body (CBOR {1: id bytes(16), 2: label text, 3: not_after uint})
Sig    = Ed25519.Sign(sk_OIK, "sayso/v1/invite" || Body)
```

It is shared as a link fragment (`#i=<b64u Invite>`) and presented in `creds`
inside a sealed drop, so it is never exposed in transit. On first use the owner
binds the invite id to that sender identity; the thread then shows as verified
under the invite's label.

The owner can also verify a sender at any time after they wrote, without an
invite:

```
Verification = Sig (64) || Body (CBOR {1: sid bytes(32), 2: label text (<= 64 bytes), 3: issued uint})
Sig          = Ed25519.Sign(sk_OIK, "sayso/v1/verified" || Body)
```

It is bound to that sender's identity key, kept in the owner's key vault, and
sent to the sender in a `ctl: 4` reply; the sender accepts it only if it
verifies under the pinned owner identity and names its own `sid`.

## 9. Wire protocol

ALPN `sayso/wire/1` over iroh (QUIC). The dialer learns the receiver's endpoint
id from the signed owner manifest, so the receiver is authenticated by the
transport. The dialer uses a fresh random key for every session.

Every exchange is one bidirectional stream opened by the dialer. A frame is
`type (1) || u32(len) || body`.

| Stream | Dialer sends | Receiver answers |
|---|---|---|
| Drop | `0x01 DROP`: Stamp (10) \|\| Envelope | `0x81 ACK`: eid, or `0xFF ERR`: code (1) |
| Put file | `0x02 PUT`: root \|\| u64(n) \|\| u64(total) \|\| leaf[0..n] | `0x82 HAVE`: u64(next index wanted) |
| | then `0x10 CHUNK`: u64(i) \|\| ct[i] for each `i` from that index, then `0x11 FIN` | `0x83 STORED`: root |
| Get file | `0x03 GET`: root \|\| u64(first index) | `0x84 META`: u64(n) \|\| u64(total) \|\| leaf[0..n], then `CHUNK`s, then `FIN` |
| Listen | `0x04 LISTEN` | `0x20 REPLY`: Envelope, any number of times |
| | `0x21 SEEN`: eid, after each reply | |

Rules:

- A receiver checks the leaf list against `root` before accepting a chunk, and
  each chunk against its leaf before writing it. A transfer that stops can be
  resumed on a new connection: `HAVE` says where to continue.
- A receiver that holds epoch secrets (the dashboard) accepts a PUT only for
  a root named in a drop it has already accepted, so the envelope goes first
  and its files follow. A receiver without secrets (the courier) cannot know
  that and admits files by stamp instead.
- A GET is answered only on a connection bound to the thread the file was
  sent to.
- A connection is bound to a thread by the first DROP on it that the receiver
  can open. `LISTEN` only yields replies for that thread. A returning sender
  who has nothing to say binds with a presence drop (`ctl = 1`).
- A reply that was acknowledged with `SEEN` is not published to a mailbox.
- Error codes: 1 malformed, 2 stamp too weak, 3 epoch not accepted, 4 too
  large, 5 not found, 6 busy.

## 10. The owner's documents

`data/` on main carries two files about the owner. Both are public.

### owner.json

Who the owner is and everything a sender needs, signed by `OIK`:

```json
{ "key": "<b64u OIK>", "sig": "<b64u>", "body": "<the JSON text of the body>" }
```

`sig = Ed25519.Sign(sk_OIK, "sayso/v1/doc/owner" || body)`, over the bytes of
`body` exactly as they appear in the string, which is why the body is kept as
text. The body:

```json
{ "v": 1, "issued": 1794300000, "name": "…",
  "github": { "login": "octocat", "repo": "octocat/inbox" },
  "epoch_len": 604800, "grace": 172800, "ttl": 2592000,
  "receivers": [{ "kind": "dashboard", "node": "<iroh endpoint id>" }],
  "pow": { "alg": 1, "bits": 16 },
  "buffers": [{ "kind": "ntfy", "url": "https://ntfy.sh" }],
  "shredded_before": 2962,
  "epochs": [{ "e": 2966, "pk": "<b64u, 1216 bytes>" }] }
```

`github` names the account whose token published the document and the
repository it was published to. Only someone with write access to that
repository can publish there, so a sender shows the owner as verified on
GitHub when `github.repo` is the repository the page itself belongs to (case
does not matter), and as unanchored otherwise.

`buffers` lists the relays of section 11 the owner collects from; a kind an
implementation does not know is skipped. `epochs` lists the published range of
section 3.

A sender pins `key` the first time it sees it, refuses a document signed by
another key, and ignores one whose `issued` is older than the newest it has
accepted. The deploy workflow also writes the document into the page itself,
so a sender verifies the owner without a request of its own.

### owner-vault.enc

The owner's key vault: what the dashboard needs to run on any device.

```json
{ "v": 1, "oik": "<b64u OIK>",
  "slots": [
    { "kind": "passphrase", "kdf": "argon2id", "m": 65536, "t": 3, "p": 1,
      "salt": "<b64u, 16 bytes>", "key": "<b64u wrapped vault key>" },
    { "kind": "passkey", "cred": "<b64u credential id>", "key": "<b64u wrapped vault key>" } ],
  "body": "<b64u sealed body>" }
```

A random 32-byte vault key seals the body; each slot wraps that key under a
key-encryption key `KEK`, with `Wrap` the XChaCha20-Poly1305 record format
(`nonce || ciphertext`, 24-byte random nonce):

- passphrase: `KEK = Argon2id(NFKC(passphrase), salt, m KiB, t passes, p lanes, 32 bytes)`
- passkey: `KEK = KDF("sayso/v1/vault/passkey", PRF output)`, where the PRF
  input is `SHA-256("sayso/v1/prf/owner-vault")`
- `slot.key = Wrap(KEK, "sayso/v1/vault/slot" || OIK, vault key)`
- `body = Wrap(vault key, "sayso/v1/vault/body" || OIK, JSON)`, with JSON
  `{ "v": 1, "root": "<b64u>", "epochs": [{ "e": 2966, "seed": "<b64u>" }],
  "settings": { "name", "ntfy", "waku", "live", "updated" } }`

Binding both labels to `OIK` stops a slot or body from being moved into
another inbox's vault. A reader checks that `root` derives `OIK`.

Several dashboards may be signed in at once. Each writes the vault only as a
compare-and-swap over the version it read (GitHub's blob id), after merging:
the union of the epochs both know, the repository's seed where both made one
for the same epoch, none due for destruction, and the settings with the later
`updated`. A writer that loses the race reads, merges and tries again, and
publishes owner.json only from what it wrote.

The vault is as strong as the passphrase against anyone holding a copy. When
epochs expire, the dashboard rewrites the vault without them; every commit
has no parent, so older copies are no longer reachable from main;
a copy someone kept before then still opens with the passphrase. Section 12
says what that means for the TTL.

## 11. Buffer lane

(Read with section 6: the same relays carry replies live, on per-thread
mailbox topics, and both sides subscribe with Server-Sent Events while their
page is open, so neither polls.)

When no receiver answers, a sender leaves a drop on public store-and-forward
networks ("relays") for the owner to collect.

```
topic = hex(KDF("sayso/v1/buffer/topic", OIK)[..20])       40 hex characters
item  = Stamp (10) || Envelope
```

The topic is not secret. It only keeps unrelated inboxes apart, and anyone
may read from it or write to it. Every reader therefore applies one gate
before keeping an item: it must be a DROP-shaped envelope under a stamp of
at least the manifest's `pow.bits`. Nothing else about an item can be checked
without an epoch secret.

A sender writes the same item to every relay in the manifest and is done when
the first one accepts. Receivers drop repeats by `eid`.

| Kind | Where | Form |
|---|---|---|
| `waku` | content topic `/sayso/1/sy<topic>/proto`, default network | the item as one message payload |
| `ntfy` | topic `sy<topic>` on the server at `url` | the item as text parts |

ntfy caps a message at 4096 bytes, so an item travels as parts:

```
part = "S1." id "." index "." count "." data
id   = hex(KDF("sayso/v1/buffer/item", item)[..8])
data = up to 3600 characters of base64url(item), split in order
```

A reader collects parts by `id` in any order, ignores what is not a part,
and accepts the result only if the reassembled bytes hash back to `id`. It
holds at most 256 incomplete items and refuses a `count` above what the
largest item needs.

### The vault

Relays forget (ntfy after twelve hours). A scheduled job in the owner's
repository polls each `ntfy` relay, applies the gate above and the acceptance
window of section 3, and files what passes as
`drops/e<epoch>/<hex(eid)>.bin` on the vault branch: the envelope alone,
named by its hash. One run adds at most 200 drops or 4 MiB; when more is
waiting, the items with the strongest stamps are kept, so an honest sender
can outbid a flood by working harder.

The job holds no secret and cannot read what it files.

## 12. What this does not protect against

- **The page itself.** Whoever can change the repository can change the
  JavaScript a sender runs. This is the standard limit of browser cryptography.
- **A stolen sender seed.** It opens that sender's thread, past and future.
- **Timing and volume.** Padding hides sizes within a bucket, not the fact
  that a mailbox or the vault changed at a given moment.
- **A hostile owner.** The owner reads everything by design and may keep
  plaintext beyond the TTL.
- **Relays learning who talks.** A relay sees the network address of whoever
  writes to or reads from a topic, and when. It never sees content.
- **Suppression on one relay.** Whoever can post to a topic can race a real
  item's parts with false ones and make that copy fail its hash. This is why
  an item goes to more than one relay.
- **History the host keeps.** Rewriting a branch makes old commits
  unreachable from it; the host may keep the objects for some time, and
  anyone who cloned the branch earlier still has them. Expiry of the
  ciphertext itself rests on destroying the epoch secret.
- **An old copy of the key vault plus the passphrase.** The vault holds the
  live epoch secrets, sealed under the passphrase (section 10). Whoever kept
  a copy from before an epoch expired, and later learns or guesses the
  passphrase, can still open that epoch's drops if they also kept those. The
  TTL is final against everyone else. A long, unique passphrase is what
  stands between a public vault and an offline guess.
- **A leaked GitHub token alone** cannot sign in (the vault needs the
  passphrase or a passkey), but it can write to main: replace
  owner.json, which senders who pinned the old key refuse, or delete files.
