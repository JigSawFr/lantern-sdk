//! The digest fields of RFC 9530 that Lantern uses: `Repr-Digest` on every
//! file response (SPEC.md § 6.6) and `Content-Digest` on a request body
//! (§ 5.4, § 9.2), both `sha-256=:<base64>:`.

use sha2::{Digest, Sha256};

use crate::bytes::{from_base64, from_hex, to_base64, to_hex};

/// The SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The field's value for a SHA-256 given in hex: `sha-256=:<base64>:`; `None`
/// when it is not 64 hex digits.
#[must_use]
pub fn format_digest(hex: &str) -> Option<String> {
    let raw = from_hex(hex).filter(|raw| raw.len() == 32)?;
    Some(format!("sha-256=:{}:", to_base64(&raw)))
}

/// The `Content-Digest` of a body.
#[must_use]
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", to_base64(&sha256(body)))
}

fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('a'..='z' | '*'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-' | '.' | '*'))
}

/// A `Repr-Digest` or `Content-Digest` value (an RFC 8941 dictionary of byte
/// sequences): each algorithm and its digest. Members that are not a byte
/// sequence, or not base64, are left out; parameters are ignored.
#[must_use]
pub fn parse_digest(value: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for member in value.split(',') {
        let Some((key, rest)) = member.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let item = rest.split(';').next().unwrap_or("").trim();
        let Some(inner) = item.strip_prefix(':').and_then(|i| i.strip_suffix(':')) else {
            continue;
        };
        if !valid_key(key) {
            continue;
        }
        if let Some(raw) = from_base64(inner) {
            out.push((key.to_owned(), raw));
        }
    }
    out
}

/// The SHA-256 a digest field gives, as lower-case hex; `None` without one
/// (or with a malformed one).
#[must_use]
pub fn digest_sha256(value: Option<&str>) -> Option<String> {
    let parsed = parse_digest(value?);
    let (_, raw) = parsed.iter().find(|(key, _)| key == "sha-256")?;
    (raw.len() == 32).then(|| to_hex(raw))
}

/// The SHA-256 of `data`, lower-case hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&sha256(data))
}
