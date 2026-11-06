//! Reading a document by the `schema` rule (SPEC.md § 3.2): a document of a
//! newer `schema` than the reader knows is absent, not an error, and is never
//! written back; the fields a reader does not know stay on the value it
//! gives, so that a document written back loses none of them.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::limits::{JSON_DOCUMENT, load_json};

/// The `schema` this version of the library writes and reads.
pub const SCHEMA: i64 = 1;

/// A document's `schema`: an integer, 1 or more.
///
/// # Errors
///
/// [`Error::Document`] when `data` is not an object with one.
pub fn schema_of(data: &Value, location: &str) -> Result<i64> {
    let object = data
        .as_object()
        .ok_or_else(|| Error::field("not an object", location))?;
    object
        .get("schema")
        .and_then(Value::as_i64)
        .filter(|schema| *schema >= 1)
        .ok_or_else(|| Error::field("no integer schema", location))
}

/// Whether a document's `schema` is above `known`.
///
/// # Errors
///
/// As [`schema_of`].
pub fn is_newer(data: &Value, known: i64) -> Result<bool> {
    Ok(schema_of(data, "document")? > known)
}

/// `data` read as a `T`, or `None` when its `schema` is newer than `known`
/// (the document is absent: SPEC.md § 3.2).
///
/// # Errors
///
/// [`Error::Document`] when it is not a `T`.
pub fn read<T: DeserializeOwned>(data: Value, known: i64, location: &str) -> Result<Option<T>> {
    if schema_of(&data, location)? > known {
        return Ok(None);
    }
    serde_json::from_value(data).map(Some).map_err(|error| {
        let reason: String = error.to_string().chars().take(160).collect();
        Error::field(reason, location)
    })
}

/// A JSON document's bytes read as a `T` within SPEC.md § 13's limits; `None`
/// for a newer `schema`.
///
/// # Errors
///
/// [`Error::Document`] when it is beyond the limits or not a `T`.
pub fn parse<T: DeserializeOwned>(raw: &[u8], known: i64, location: &str) -> Result<Option<T>> {
    read(load_json(raw, JSON_DOCUMENT, location)?, known, location)
}
