//! A server's `uid` (SPEC.md § 4.1): a UUID that never changes for the
//! server. The library does no input and output, so the random bytes (and the
//! clock for a version 7) are the caller's.

use crate::bytes::to_hex;

/// Whether `text` is a UUID in its canonical form (RFC 9562), either case.
#[must_use]
pub fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn format(raw: &[u8; 16]) -> String {
    let hex = to_hex(raw);
    let part = |from: usize, to: usize| hex.get(from..to).unwrap_or("");
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

/// A version 4 UUID from 16 random bytes.
#[must_use]
pub fn uuid_v4(mut random: [u8; 16]) -> String {
    if let Some(byte) = random.get_mut(6) {
        *byte = *byte & 0x0f | 0x40;
    }
    if let Some(byte) = random.get_mut(8) {
        *byte = *byte & 0x3f | 0x80;
    }
    format(&random)
}

/// A version 7 UUID from the time in milliseconds since the Unix epoch (48
/// bits) and 10 random bytes.
#[must_use]
pub fn uuid_v7(unix_ms: u64, random: [u8; 10]) -> String {
    let mut raw = [0u8; 16];
    let time = unix_ms.to_be_bytes();
    for (slot, byte) in raw.iter_mut().zip(time.iter().skip(2).chain(random.iter())) {
        *slot = *byte;
    }
    if let Some(byte) = raw.get_mut(6) {
        *byte = *byte & 0x0f | 0x70;
    }
    if let Some(byte) = raw.get_mut(8) {
        *byte = *byte & 0x3f | 0x80;
    }
    format(&raw)
}
