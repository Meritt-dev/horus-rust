//! Small JS-semantics helpers shared by the HTTP providers (no TS counterpart):
//! `Date` ⇄ ISO strings, `Number`/`String` coercions and JSON number shaping so the
//! JSON this crate emits is byte-comparable with the TS CLI.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::Serializer;
use serde_json::{Map, Number, Value};

/// JS `Number(str)` for finite results (`""` → 0, non-numeric → None).
pub fn js_number_from_str(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    let lower = t.to_ascii_lowercase();
    if lower.contains("inf") || lower.contains("nan") {
        return None;
    }
    t.parse::<f64>().ok().filter(|n| n.is_finite())
}

/// JS `Number#toString()` for finite values: integral floats print without ".0".
pub fn js_number_string(n: f64) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i64)
    } else {
        n.to_string()
    }
}

/// JS `String(value)` for the scalar/object cases that matter here.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number_string(n.as_f64().unwrap_or(0.0)),
        Value::Array(items) => items.iter().map(|i| if i.is_null() { String::new() } else { js_string(i) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(v ?? '')`.
pub fn js_string_or_empty(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    }
}

/// JS `str.slice(0, n)` (by char; UTF-16 surrogate pairs are rare in log text).
pub fn slice_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `n.toFixed(digits)`.
pub fn to_fixed(n: f64, digits: usize) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    format!("{:.*}", digits, n)
}

/// Short, human "MM-DD HH:MM" form of an ISO timestamp (empty-safe).
pub fn short_ts(iso: &str) -> String {
    if iso.is_empty() {
        return "—".into();
    }
    let chars: Vec<char> = iso.chars().collect();
    if chars.len() < 16 {
        return iso.to_string();
    }
    format!("{} {}", chars[5..10].iter().collect::<String>(), chars[11..16].iter().collect::<String>())
}

/// Shape JSON numbers like `JSON.stringify` would: integral floats (`50.0`) become
/// integers (`50`) so serialized output matches the TS CLI byte-for-byte. Walks
/// objects and arrays in place.
pub fn normalize_js_numbers(v: &mut Value) {
    match v {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if n.is_f64() && f.is_finite() && f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 {
                    *n = Number::from(f as i64);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_js_numbers),
        Value::Object(map) => map.values_mut().for_each(normalize_js_numbers),
        _ => {}
    }
}

/// `serde_json::to_value` + JS number shaping — use for every evidence payload.
pub fn js_value<T: serde::Serialize>(t: &T) -> Value {
    let mut v = serde_json::to_value(t).unwrap_or(Value::Null);
    normalize_js_numbers(&mut v);
    v
}

/// `typeof v === 'string'`.
pub fn as_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

/// `typeof v === 'number'` (finite).
pub fn as_num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|n| n.is_finite())
}

/// `v !== null && typeof v === 'object' && !Array.isArray(v)`.
pub fn as_obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// `Array.isArray(v) ? v : []`.
pub fn as_arr(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// JS `encodeURIComponent`: percent-encode everything except `A-Z a-z 0-9 - _ . ! ~ * ' ( )`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// `new URLSearchParams(pairs).toString()` (application/x-www-form-urlencoded; space → `+`).
pub fn url_search_params(pairs: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

/// `Number#toLocaleString('en-US')` for the integral case (thousands separators).
pub fn to_locale_string_en_us(n: f64) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.0e15 {
        to_locale_string(n as i64)
    } else {
        js_number_string(n)
    }
}

/// Collect a core `Issues` list into one error (zod-style `path: message` lines).
pub fn issues_to_error(issues: &horus_core::Issues) -> anyhow::Result<()> {
    if issues.items.is_empty() {
        return Ok(());
    }
    anyhow::bail!(issues.items.iter().map(|i| format!("{}: {}", i.path, i.message)).collect::<Vec<_>>().join("; "))
}

/// Node's socket error text (`connect ECONNREFUSED 127.0.0.1:5432`) for the common connect
/// failures; `None` when Node's wording is not known for this kind.
pub fn node_connect_error(e: &std::io::Error, addr: &str) -> Option<String> {
    use std::io::ErrorKind::*;
    let code = match e.kind() {
        ConnectionRefused => "ECONNREFUSED",
        ConnectionReset => "ECONNRESET",
        TimedOut => "ETIMEDOUT",
        HostUnreachable => "EHOSTUNREACH",
        NetworkUnreachable => "ENETUNREACH",
        _ => return None,
    };
    Some(format!("connect {code} {addr}"))
}

// --- date / number helpers (merged from agent C's jscompat.rs) ---

/// `new Date(ms).toISOString()` — always millisecond precision, `Z` suffix.
pub fn iso_from_ms(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

/// `Date.now()`
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// `new Date().toISOString()`
pub fn now_iso() -> String {
    iso_from_ms(now_ms())
}

/// `Date.parse(s)` for the formats datastores hand us (RFC 3339, SQL timestamps,
/// bare dates). `None` stands for `NaN`.
pub fn parse_js_date_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp_millis());
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f%#z", "%Y-%m-%d %H:%M:%S%.f%#z"] {
        if let Ok(d) = DateTime::parse_from_str(s, f) {
            return Some(d.timestamp_millis());
        }
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(d) = NaiveDateTime::parse_from_str(s, f) {
            return Some(d.and_utc().timestamp_millis());
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    None
}

/// JSON number the way JS would print it: integral floats become integers.
pub fn js_num_value(n: f64) -> Value {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.0e15 {
        Value::from(n as i64)
    } else {
        serde_json::Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// serde `serialize_with` for `f64` fields that are usually integral in TS output.
pub fn js_num<S: Serializer>(n: &f64, s: S) -> Result<S::Ok, S::Error> {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.0e15 {
        s.serialize_i64(*n as i64)
    } else {
        s.serialize_f64(*n)
    }
}

/// serde `serialize_with` for `Option<f64>` (pair with `skip_serializing_if = "Option::is_none"`).
pub fn js_num_opt<S: Serializer>(n: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match n {
        Some(v) => js_num(v, s),
        None => s.serialize_none(),
    }
}

/// `Number#toLocaleString()` (en-US grouping) for non-negative integers.
pub fn to_locale_string(n: i64) -> String {
    let digits = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}
