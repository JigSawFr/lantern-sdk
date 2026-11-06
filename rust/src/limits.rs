//! The limits of SPEC.md § 13, which a client bounds what it reads with and
//! a server stays within, and a JSON reader that keeps to them.

use std::collections::HashSet;

use serde_json::Value;

use crate::error::{Error, Result};

/// A JSON document, in bytes.
pub const JSON_DOCUMENT: usize = 32 << 20;
/// A JSON document's nesting.
pub const DEPTH: usize = 16;
/// A string field, in UTF-8 bytes.
pub const STRING: usize = 4096;
/// A `name`.
pub const NAME: usize = 512;
/// A `note`.
pub const NOTE: usize = 120;
/// A `profile`.
pub const PROFILE: usize = 64;
/// Items in a page.
pub const PAGE_ITEMS: usize = 1000;
/// Titles asked at once.
pub const TITLES_AT_ONCE: usize = 100;
/// Files in a manifest.
pub const MANIFEST_FILES: usize = 4096;
/// A path, in bytes.
pub const PATH: usize = 1024;
/// A path's part, in bytes.
pub const PATH_PART: usize = 255;
/// Packages in a homebrew.
pub const PACKAGES: usize = 16;
/// Tags on a title.
pub const TAGS: usize = 32;
/// A tag, in bytes.
pub const TAG: usize = 64;
/// Files a port requires.
pub const REQUIRED_DATA: usize = 256;
/// Entries of an `accept` list.
pub const ACCEPT: usize = 32;
/// A set of cheats, in bytes.
pub const CHEAT_SET: usize = 1 << 20;
/// A discovery datagram, in bytes.
pub const DATAGRAM: usize = 1200;
/// Pages a client follows in one listing before it gives up.
pub const PAGES: usize = 10_000;
/// A signature header, in bytes.
pub const SIGNATURE_HEADER: usize = 1024;
/// Chunks in a chunk index (SPEC.md § 22.1).
pub const CHUNKS: usize = 100_000;
/// A chunk index, in bytes (SPEC.md § 22.1).
pub const CHUNK_INDEX: usize = 8 << 20;
/// The largest integer an I-JSON document holds: what an IEEE double holds exactly (SPEC.md § 2.3).
pub const IJSON_INTEGER: u64 = 9_007_199_254_740_991;

/// The string fields whose bound is not [`STRING`], by name.
const STRING_CAPS: &[(&str, usize)] = &[("name", NAME), ("note", NOTE), ("profile", PROFILE)];

const LIST_BOUNDS: &[(&str, usize)] = &[
    ("items", PAGE_ITEMS),
    ("manifest", MANIFEST_FILES),
    ("packages", PACKAGES),
    ("tags", TAGS),
    ("accept", ACCEPT),
];

fn lookup(table: &[(&str, usize)], key: Option<&str>) -> Option<usize> {
    let key = key?;
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, bound)| *bound)
}

/// Every way `document` goes beyond SPEC.md § 13 (empty when it does not): its
/// depth, its strings (by their key's bound), and the lists the section bounds.
#[must_use]
pub fn problems(document: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(document, 1, None, "$", &mut out);
    out
}

fn walk(value: &Value, depth: usize, key: Option<&str>, path: &str, out: &mut Vec<String>) {
    if out.len() > 20 {
        return;
    }
    match value {
        Value::Array(_) | Value::Object(_) if depth > DEPTH => {
            out.push(format!("{path}: nested deeper than {DEPTH}"));
        }
        Value::Array(items) => {
            if let Some(bound) = lookup(LIST_BOUNDS, key).filter(|bound| items.len() > *bound) {
                out.push(format!("{path}: {} items, above {bound}", items.len()));
            }
            let inner = if key == Some("tags") {
                Some("tag")
            } else {
                key
            };
            for (index, item) in items.iter().enumerate() {
                walk(item, depth + 1, inner, &format!("{path}[{index}]"), out);
            }
        }
        Value::Object(members) => {
            for (name, member) in members {
                walk(
                    member,
                    depth + 1,
                    Some(name),
                    &format!("{path}.{name}"),
                    out,
                );
            }
            if key == Some("port")
                && let Some(Value::Array(data)) = members.get("requires_data")
            {
                let count: usize = data
                    .iter()
                    .map(|entry| match entry.get("one_of") {
                        Some(Value::Array(groups)) => groups
                            .iter()
                            .map(|group| group.as_array().map_or(0, Vec::len))
                            .sum(),
                        _ => 1,
                    })
                    .sum();
                if count > REQUIRED_DATA {
                    out.push(format!(
                        "{path}.requires_data: {count} files, above {REQUIRED_DATA}"
                    ));
                }
            }
        }
        Value::String(text) => {
            let cap = if key == Some("tag") {
                TAG
            } else {
                lookup(STRING_CAPS, key).unwrap_or(STRING)
            };
            if text.len() > cap {
                out.push(format!("{path}: {} bytes, above {cap}", text.len()));
            }
        }
        _ => {}
    }
}

/// How deep a JSON text nests, read before it is parsed (so that a hostile
/// depth never reaches the parser).
#[must_use]
pub fn json_depth(text: &str) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    deepest = deepest.max(depth);
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    deepest
}

/// Why `text` is not I-JSON (RFC 7493; SPEC.md § 2.3): a member name given
/// twice in an object, or an integer beyond 2**53 - 1. `None` when it is.
/// (A lone surrogate is refused by the JSON reader itself.)
#[must_use]
pub fn ijson_problem(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    // One entry per open container: the names seen, for an object.
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    let mut want_name = false;
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'"' => {
                let mut j = i + 1;
                while let Some(&c) = bytes.get(j) {
                    if c == b'"' {
                        break;
                    }
                    j += if c == b'\\' { 2 } else { 1 };
                }
                if want_name && let Some(Some(names)) = stack.last_mut() {
                    let literal = text.get(i..=j)?;
                    let name: String = serde_json::from_str(literal).ok()?;
                    if !names.insert(name) {
                        return Some("a member name is given twice".to_owned());
                    }
                    want_name = false;
                }
                i = j + 1;
            }
            b'{' => {
                stack.push(Some(HashSet::new()));
                want_name = true;
                i += 1;
            }
            b'[' => {
                stack.push(None);
                want_name = false;
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                want_name = false;
                i += 1;
            }
            b',' => {
                want_name = matches!(stack.last(), Some(Some(_)));
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let mut j = i + 1;
                while bytes.get(j).is_some_and(|c| b"0123456789.eE+-".contains(c)) {
                    j += 1;
                }
                let token = text.get(i..j)?;
                let digits = token.strip_prefix('-').unwrap_or(token);
                if !digits.is_empty()
                    && digits.bytes().all(|c| c.is_ascii_digit())
                    && digits.parse::<u64>().map_or(true, |n| n > IJSON_INTEGER)
                {
                    return Some(format!(
                        "the integer {} is beyond 2**53 - 1",
                        token.chars().take(20).collect::<String>()
                    ));
                }
                i = j;
            }
            _ => i += 1,
        }
    }
    None
}

/// A JSON document read within SPEC.md § 13: at most `limit` bytes, UTF-8,
/// nested 16 deep at most, I-JSON, its strings within their bounds.
///
/// # Errors
///
/// [`Error::Document`] for anything else.
pub fn load_json(raw: &[u8], limit: usize, location: &str) -> Result<Value> {
    if raw.len() > limit {
        return Err(Error::field(
            format!("{} bytes, above {limit}", raw.len()),
            location,
        ));
    }
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Error::field("not I-JSON (a byte order mark)", location));
    }
    let text = std::str::from_utf8(raw).map_err(|_| Error::field("not UTF-8", location))?;
    if json_depth(text) > DEPTH {
        return Err(Error::field(
            format!("nested deeper than {DEPTH}"),
            location,
        ));
    }
    let document: Value = serde_json::from_str(text).map_err(|error| {
        let reason: String = error.to_string().chars().take(80).collect();
        Error::field(format!("not JSON ({reason})"), location)
    })?;
    if let Some(reason) = ijson_problem(text) {
        return Err(Error::field(format!("not I-JSON ({reason})"), location));
    }
    let found = problems(&document);
    if !found.is_empty() {
        let shown: Vec<&str> = found.iter().take(3).map(String::as_str).collect();
        return Err(Error::field(
            format!("beyond SPEC.md § 13: {}", shown.join("; ")),
            location,
        ));
    }
    Ok(document)
}

/// `text` cut to `limit` UTF-8 bytes, on a character's boundary.
#[must_use]
pub fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("").to_owned()
}

/// `text` without control characters, within `limit` bytes: what a client
/// shows of a server's `detail` or `motd` (SPEC.md § 12).
#[must_use]
pub fn printable(text: &str, limit: usize) -> String {
    let kept: String = text
        .chars()
        .filter(|c| *c == '\n' || !(c.is_control()))
        .collect();
    clip(&kept, limit)
}
