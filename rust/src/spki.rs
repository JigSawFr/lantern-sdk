//! A server's key fingerprint (SPEC.md § 5.3): the SHA-256 of its
//! certificate's DER `SubjectPublicKeyInfo`, and its short form for people
//! (`3F9A 1C07 B2E4 55D0`). Test vectors: `vectors/spki.json`. The
//! certificate is read with a small DER reader of its own: only the structure
//! that leads to the key.

use crate::bytes::{from_base64, to_hex};
use crate::digest::sha256;
use crate::error::{Error, Result};

fn bad(message: &str) -> Error {
    Error::Certificate(message.to_owned())
}

/// The tag, the start and the end of the element at `at`.
fn element(data: &[u8], at: usize) -> Result<(u8, usize, usize)> {
    let tag = *data.get(at).ok_or_else(|| bad("a truncated certificate"))?;
    let first = *data
        .get(at + 1)
        .ok_or_else(|| bad("a truncated certificate"))?;
    let mut position = at + 2;
    let mut length = usize::from(first);
    if first & 0x80 != 0 {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(bad("a length this reader does not take"));
        }
        length = 0;
        for index in 0..count {
            let byte = *data
                .get(position + index)
                .ok_or_else(|| bad("a truncated certificate"))?;
            length = length * 256 + usize::from(byte);
        }
        position += count;
    }
    let end = position
        .checked_add(length)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| bad("a truncated certificate"))?;
    Ok((tag, position, end))
}

/// The DER `SubjectPublicKeyInfo` of a DER certificate (RFC 5280 § 4.1).
///
/// # Errors
///
/// [`Error::Certificate`] when the structure that leads to the key is not there.
pub fn spki_der(certificate: &[u8]) -> Result<&[u8]> {
    let (tag, start, _) = element(certificate, 0)?;
    if tag != 0x30 {
        return Err(bad("not a certificate"));
    }
    let (tbs_tag, tbs_start, tbs_end) = element(certificate, start)?;
    if tbs_tag != 0x30 {
        return Err(bad("not a certificate"));
    }
    let mut fields: Vec<(u8, usize, usize)> = Vec::new();
    let mut position = tbs_start;
    while position < tbs_end && fields.len() < 7 {
        let (tag, _, end) = element(certificate, position)?;
        fields.push((tag, position, end));
        position = end;
    }
    // [0] version, when present; then serialNumber, signature, issuer,
    // validity, subject, subjectPublicKeyInfo.
    let skip = usize::from(fields.first().is_some_and(|f| f.0 == 0xa0));
    let (tag, from, to) = *fields
        .get(skip + 5)
        .ok_or_else(|| bad("no SubjectPublicKeyInfo"))?;
    if tag != 0x30 {
        return Err(bad("no SubjectPublicKeyInfo"));
    }
    certificate
        .get(from..to)
        .ok_or_else(|| bad("no SubjectPublicKeyInfo"))
}

/// The DER bytes of a PEM certificate (its first).
///
/// # Errors
///
/// [`Error::Certificate`] when `pem` holds no certificate.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body.split_whitespace().collect::<String>());
    body.and_then(|b| from_base64(&b))
        .ok_or_else(|| bad("not a PEM certificate"))
}

/// The fingerprint of a DER certificate: lower-case hex.
///
/// # Errors
///
/// As [`spki_der`].
pub fn spki_sha256(certificate: &[u8]) -> Result<String> {
    Ok(to_hex(&sha256(spki_der(certificate)?)))
}

/// The fingerprint of a PEM certificate: lower-case hex.
///
/// # Errors
///
/// As [`pem_to_der`] and [`spki_der`].
pub fn spki_sha256_pem(pem: &str) -> Result<String> {
    spki_sha256(&pem_to_der(pem)?)
}

/// Whether `text` is a SHA-256 in hex (either case).
#[must_use]
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A fingerprint's short form, for people: its first 16 hex digits,
/// upper-case, in groups of 4. `None` when it is not a SHA-256 in hex.
#[must_use]
pub fn short(fingerprint: &str) -> Option<String> {
    if !is_sha256_hex(fingerprint) {
        return None;
    }
    let head = fingerprint.get(..16)?.to_ascii_uppercase();
    let groups: Vec<&str> = (0..4).filter_map(|i| head.get(i * 4..i * 4 + 4)).collect();
    Some(groups.join(" "))
}

/// Whether the key `seen` is the one `pinned` (both hex).
#[must_use]
pub fn check_pin(seen: &str, pinned: &str) -> bool {
    seen.eq_ignore_ascii_case(pinned)
}
