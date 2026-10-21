//! JSON output with JS number semantics. `JSON.stringify` prints integral
//! numbers without a fraction (`1`, not `1.0`); serde prints `f64` as `1.0`.
//! Every CLI `--json` / file output goes through here so structs can keep
//! plain `f64` fields.

use serde::Serialize;
use serde_json::{Number, Value};

/// Recursively rewrite integral finite floats as integers, in place.
pub fn normalize_js_numbers(v: &mut Value) {
    match v {
        Value::Number(n) if n.is_f64() => {
            let f = n.as_f64().unwrap_or(0.0);
            if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
                *n = Number::from(f as i64);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(normalize_js_numbers),
        Value::Object(o) => o.values_mut().for_each(normalize_js_numbers),
        _ => {}
    }
}

/// Serialize to a `Value` with JS number semantics.
pub fn to_js_value<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Value> {
    let mut v = serde_json::to_value(value)?;
    normalize_js_numbers(&mut v);
    Ok(v)
}

/// `JSON.stringify(value, null, 2)`.
pub fn to_js_json_pretty<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&to_js_value(value)?)
}

/// `JSON.stringify(value)`.
pub fn to_js_json<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    serde_json::to_string(&to_js_value(value)?)
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
fn self_check() {
    let s = to_js_json(&serde_json::json!({"a": 1.0, "b": [2.5, 3.0], "c": -0.0})).unwrap();
    assert_eq!(s, r#"{"a":1,"b":[2.5,3],"c":0}"#);
}
