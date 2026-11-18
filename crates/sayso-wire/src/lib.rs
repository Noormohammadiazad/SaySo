//! The Sayso wire protocol (spec section 9) over iroh.
//!
//! [`Client`] is the dialer: a sender's browser. [`Server`] is the receiver:
//! the owner's dashboard or a courier. The server never interprets a payload;
//! it frames, checks what can be checked without a key (envelope shape, leaf
//! lists, chunk hashes) and hands each request to the application as an
//! [`Incoming`] event that carries its own reply channel.
//!
//! The same code builds natively and for `wasm32-unknown-unknown`, where iroh
//! runs relay-only.

mod client;
mod frame;
mod server;

pub use client::{ACK_TIMEOUT, Client, GetStream, Listener, PutStream};
pub use frame::{ErrCode, MAX_FILE_CHUNKS, WireError};
pub use server::{Incoming, Respond, Server};

pub use iroh;

use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMap, RelayMode};

/// Application-layer protocol name negotiated in the QUIC handshake.
pub const ALPN: &[u8] = b"sayso/wire/1";

/// The public relays run by number 0, the authors of iroh: the same servers
/// iroh uses by default.
///
/// iroh's own list writes them as fully qualified names with a trailing dot
/// (`use1-1.relay.n0.iroh.link.`). Some networks, and some of the proxies
/// people use to get around them, cannot open a WebSocket to a name in that
/// form while the same name without the dot works. Measured from a browser
/// on such a network: without the dot the relay answered in 0.3 to 2.7
/// seconds; with it, never. So the list is spelled out here without dots.
pub const RELAYS: [&str; 4] = [
    "https://use1-1.relay.n0.iroh.link",
    "https://usw1-1.relay.n0.iroh.link",
    "https://euc1-1.relay.n0.iroh.link",
    "https://aps1-1.relay.n0.iroh.link",
];

/// The endpoint id a receiver started with `secret` will have. It is the
/// public half of the key, so it is known before the receiver is up, and the
/// owner can publish it while the relays are still unreachable.
pub fn endpoint_id_for(secret: &[u8; 32]) -> String {
    iroh::SecretKey::from_bytes(secret).public().to_string()
}

pub fn relay_map() -> RelayMap {
    RelayMap::try_from_iter(RELAYS).expect("the relay list is valid")
}

/// An endpoint on the public relays with address lookup, which is what both
/// a sender and a receiver use.
pub(crate) fn public_endpoint() -> iroh::endpoint::Builder {
    Endpoint::builder(presets::N0).relay_mode(RelayMode::Custom(relay_map()))
}

pub type Result<T> = core::result::Result<T, WireError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relays_are_the_iroh_defaults_without_trailing_dots() {
        let ours: Vec<String> = relay_map()
            .urls::<Vec<_>>()
            .iter()
            .map(|u| u.host_str().unwrap().to_owned())
            .collect();
        let theirs: Vec<String> = iroh::defaults::prod::default_relay_map()
            .urls::<Vec<_>>()
            .iter()
            .map(|u| u.host_str().unwrap().trim_end_matches('.').to_owned())
            .collect();
        assert_eq!(ours.len(), 4);
        assert!(ours.iter().all(|host| !host.ends_with('.')), "{ours:?}");
        let (mut a, mut b) = (ours, theirs);
        a.sort();
        b.sort();
        assert_eq!(a, b, "the same servers as iroh's defaults");
    }
}
