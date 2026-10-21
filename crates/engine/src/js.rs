//! JavaScript number/string semantics the engine's output depends on
//! (`toFixed`, `Math.round`, `localeCompare`, `Date.parse`, char slicing).
//! Private helper for this crate — not a TS module.

use std::cmp::Ordering;

/// `Number.prototype.toFixed(digits)`: round half AWAY from zero on the exact
/// binary value. Rust's formatter rounds exact ties half-to-even, so exact
/// ties (0.125 → "0.13" in JS) are patched here.
pub fn to_fixed(x: f64, digits: usize) -> String {
    if x.is_nan() {
        return "NaN".to_string();
    }
    let scaled = x.abs() * 10f64.powi(digits as i32);
    // ponytail: an exact .5 fraction after scaling is a tie only when the product was
    // exact (< 2^52); spurious ties are not reachable for the magnitudes scored here.
    if scaled.fract() == 0.5 && scaled < 4503599627370496.0 {
        let n = scaled.ceil() as u64;
        let s = n.to_string();
        let body = if digits == 0 {
            s
        } else {
            let padded = format!("{:0>width$}", s, width = digits + 1);
            let (int, frac) = padded.split_at(padded.len() - digits);
            format!("{int}.{frac}")
        };
        // JS prints "-0.00" for small negatives; `(-0.001).toFixed(2)` → "-0.00".
        return if x < 0.0 { format!("-{body}") } else { body };
    }
    format!("{:.*}", digits, x)
}

/// `+(x).toFixed(digits)` — round via toFixed and parse back.
pub fn round_to(x: f64, digits: usize) -> f64 {
    to_fixed(x, digits).parse().unwrap_or(0.0)
}

/// `Math.round`: half toward +∞.
pub fn math_round(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    (x + 0.5).floor()
}

/// `String(n)` for a number that is integer-valued (e.g. a `Math.round` result).
pub fn int_string(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e21 {
        format!("{}", x as i64)
    } else {
        number_string(x)
    }
}

/// `String(n)` for an arbitrary double (shortest round-trip, like V8).
pub fn number_string(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x.fract() == 0.0 && x.abs() < 1e21 {
        return format!("{}", x as i64);
    }
    // ryu-style shortest repr is what `{}` gives for non-integers.
    format!("{}", x)
}

/// `Date.parse(s)`: milliseconds since epoch, or NaN when unparseable.
/// Accepts RFC 3339 / ISO 8601 with offset, a bare `YYYY-MM-DD` (UTC), and a
/// naive `YYYY-MM-DDTHH:MM:SS[.fff]` (treated as UTC — JS would use local time).
pub fn date_parse(s: &str) -> f64 {
    use chrono::{DateTime, NaiveDate, NaiveDateTime};
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.timestamp_millis() as f64;
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp_millis() as f64).unwrap_or(f64::NAN);
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(t) = NaiveDateTime::parse_from_str(s, fmt) {
            return t.and_utc().timestamp_millis() as f64;
        }
    }
    f64::NAN
}

/// `new Date().toISOString()` shape: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// `s.slice(0, n)` on code points.
pub fn slice_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `a.localeCompare(b)` approximation of ICU root collation for the ASCII ids the
/// engine sorts: primary = punctuation < digits < letters (case-insensitive),
/// tertiary = lowercase before uppercase.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    fn primary(c: char) -> (u8, u32) {
        if c.is_ascii_digit() {
            (1, c as u32)
        } else if c.is_alphabetic() {
            (2, c.to_lowercase().next().unwrap_or(c) as u32)
        } else {
            // ICU root order for ASCII punctuation/symbols.
            const ORDER: &str = "\t\n\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";
            let pos = ORDER.find(c).map(|p| p as u32).unwrap_or(1000 + c as u32);
            (0, pos)
        }
    }
    let pa: Vec<char> = a.chars().collect();
    let pb: Vec<char> = b.chars().collect();
    for (x, y) in pa.iter().zip(pb.iter()) {
        let o = primary(*x).cmp(&primary(*y));
        if o != Ordering::Equal {
            return o;
        }
    }
    match pa.len().cmp(&pb.len()) {
        Ordering::Equal => {}
        o => return o,
    }
    // Tertiary: lowercase sorts before uppercase at the first case difference.
    for (x, y) in pa.iter().zip(pb.iter()) {
        if x != y {
            let o = x.is_uppercase().cmp(&y.is_uppercase());
            if o != Ordering::Equal {
                return o;
            }
            return x.cmp(y);
        }
    }
    Ordering::Equal
}

/// Comparator for `sort((a, b) => b - a)` style float sorts; NaN compares equal.
pub fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

/// `new Date(ms).toISOString()`: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso_from_ms(ms: f64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}
