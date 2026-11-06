//! Bytes and their text forms, the way the protocol writes them: hex
//! (lower-case) and base64 with padding (RFC 4648 § 4). No dependency.

use std::fmt::Write as _;

/// Lower-case hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The bytes of a hex string (either case); `None` when it is not one.
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [high, low] => Some(nibble(*high)? << 4 | nibble(*low)?),
            _ => None,
        })
        .collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 with padding.
#[must_use]
pub fn to_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = b0 << 16 | b1 << 8 | b2;
        let sextet = |shift: u32| {
            char::from(
                B64.get(((n >> shift) & 63) as usize)
                    .copied()
                    .unwrap_or(b'A'),
            )
        };
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    let value = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// The bytes of a padded base64 string; `None` when it is not one (wrong
/// length, a stray character, padding in the middle).
#[must_use]
pub fn from_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let last = bytes.len() / 4;
    for (index, quad) in bytes.chunks_exact(4).enumerate() {
        let [first, second, third, fourth] = quad else {
            return None;
        };
        let padding = usize::from(*third == b'=') + usize::from(*fourth == b'=');
        if padding > 0 && index + 1 != last || (*third == b'=' && *fourth != b'=') {
            return None;
        }
        let n = sextet(*first)? << 18
            | sextet(*second)? << 12
            | if *third == b'=' {
                0
            } else {
                sextet(*third)? << 6
            }
            | if *fourth == b'=' { 0 } else { sextet(*fourth)? };
        out.push(u8::try_from((n >> 16) & 255).ok()?);
        if padding < 2 {
            out.push(u8::try_from((n >> 8) & 255).ok()?);
        }
        if padding < 1 {
            out.push(u8::try_from(n & 255).ok()?);
        }
    }
    Some(out)
}
