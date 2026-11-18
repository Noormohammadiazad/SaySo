use js_sys::{Error, Reflect};
use sayso_wire::WireError;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// A JavaScript `Error` with a machine-readable `kind`, and a `code` when the
/// receiver refused a request.
pub fn js_error(kind: &str, message: &str, code: Option<u8>) -> JsValue {
    let error = Error::new(message);
    error.set_name("SaysoError");
    let _ = Reflect::set(&error, &"kind".into(), &kind.into());
    if let Some(code) = code {
        let _ = Reflect::set(&error, &"code".into(), &code.into());
    }
    error.into()
}

pub fn core_err(err: sayso_core::Error) -> JsValue {
    js_error("core", &err.to_string(), None)
}

pub fn wire_err(err: WireError) -> JsValue {
    let (kind, code) = match &err {
        WireError::Connect(_) => ("connect", None),
        WireError::Timeout => ("timeout", None),
        WireError::Closed(_) => ("closed", None),
        WireError::Protocol(_) => ("protocol", None),
        WireError::Refused(code) => ("refused", Some(*code as u8)),
        WireError::Core(_) => ("core", None),
    };
    js_error(kind, &err.to_string(), code)
}

pub fn bad_input(what: &str) -> JsValue {
    js_error("input", &format!("invalid {what}"), None)
}

/// Borrow a byte slice as a fixed-size array, or report which argument was wrong.
pub fn array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsValue> {
    bytes.try_into().map_err(|_| bad_input(what))
}

/// Serialise to a plain JavaScript object, with byte fields as `Uint8Array`
/// and maps as objects.
pub fn to_js<T: Serialize>(value: &T) -> JsValue {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value.serialize(&serializer).expect("plain data serialises")
}

/// A JavaScript number that must be a non-negative integer.
pub fn uint(value: f64, what: &str) -> Result<u64, JsValue> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= 9_007_199_254_740_991.0
    {
        Ok(value as u64)
    } else {
        Err(bad_input(what))
    }
}
