//! Canonical JSON (SPEC.md § 2.3): RFC 8785's JSON Canonicalization Scheme.
//!
//! No space; an object's members sorted by their names as UTF-16 code units;
//! a string with only what JSON must escape escaped; a number as ECMAScript
//! writes it (`1.0` is `1`, `-0` is `0`, `1e21` is `1e+21`). Sync's merge
//! rule (§ 20.4) compares values by it and a chunk index (§ 22.1) is written
//! in it.

use serde_json::Value;

use crate::error::{Error, Result};

/// Nesting deeper than this is refused: a document is bounded long before.
const DEPTH: usize = 512;

/// A value's canonical JSON as text.
///
/// # Errors
///
/// [`Error::Document`] for a value nested too deep or a number JSON cannot hold.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    write(value, 0, &mut out)?;
    Ok(out)
}

/// A value's canonical JSON as UTF-8 bytes: what is compared, hashed and served.
///
/// # Errors
///
/// As [`canonical_json`].
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    canonical_json(value).map(String::into_bytes)
}

fn write(value: &Value, depth: usize, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(text) => string(text, out),
        Value::Number(number) => {
            let float = number.as_f64().filter(|f| f.is_finite());
            out.push_str(&es_number(float.ok_or_else(|| {
                Error::field("JSON has no NaN nor infinity", "value")
            })?));
        }
        Value::Array(items) => {
            if depth > DEPTH {
                return Err(Error::field("nested too deep", "value"));
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            if depth > DEPTH {
                return Err(Error::field("nested too deep", "value"));
            }
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (index, (name, member)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                string(name, out);
                out.push(':');
                write(member, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn string(text: &str, out: &mut String) {
    use std::fmt::Write as _;
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A finite number as ECMAScript's `Number::toString` writes it (ECMA-262 § 6.1.6.1.20).
fn es_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // The shortest digits that read back as the same number, as `d.ddde<exp>`.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let k = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let n = exponent + 1;
    let body = if k <= n && n <= 21 {
        format!(
            "{digits}{}",
            "0".repeat(usize::try_from(n - k).unwrap_or(0))
        )
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).unwrap_or(0);
        format!(
            "{}.{}",
            digits.get(..split).unwrap_or(""),
            digits.get(split..).unwrap_or("")
        )
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat(usize::try_from(-n).unwrap_or(0)))
    } else {
        let e = n - 1;
        let sign_e = if e < 0 { '-' } else { '+' };
        let head = digits.get(..1).unwrap_or("");
        let tail = digits.get(1..).unwrap_or("");
        if tail.is_empty() {
            format!("{head}e{sign_e}{}", e.abs())
        } else {
            format!("{head}.{tail}e{sign_e}{}", e.abs())
        }
    };
    format!("{sign}{body}")
}
