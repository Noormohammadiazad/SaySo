//! JavaScript bindings for Live Wire. The page loads this module only when a
//! live transfer starts: everything else (keys, envelopes, stamps, files)
//! is implemented in TypeScript in `web/src/crypto`, checked against
//! vectors from `sayso-core`.

mod util;
mod wire_api;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}
