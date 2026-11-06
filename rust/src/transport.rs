//! How a request reaches the server: built by the client, given its
//! credentials and its signature (for the server's origin only, SPEC.md § 2),
//! then sent by a [`Transport`].
//!
//! The library does no input or output of its own: a transport does. It must
//! follow no redirect (Lantern sends none: a redirect is an
//! [`Error::UnexpectedResponse`]), send no cookie, and say which key the TLS
//! connection came over when it can (`Response::spki`, the SHA-256 of the
//! certificate's `SubjectPublicKeyInfo`, hex).

use std::io::Read;
use std::time::Duration;

use crate::error::{Error, Result};

/// The headers of a request or an answer: names compared without regard to
/// case, in the order they were set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// No header.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The first value of `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether `name` is set.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Sets `name`, replacing what was there.
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.remove(name);
        self.0.push((name.to_owned(), value.into()));
    }

    /// Adds `name` without replacing (a header sent twice).
    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.0.push((name.to_owned(), value.into()));
    }

    /// Removes `name`.
    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// The headers, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// A request, as a transport sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `GET`, `POST`…
    pub method: String,
    /// The absolute URL.
    pub url: String,
    /// The headers.
    pub headers: Headers,
    /// The body; empty when there is none.
    pub body: Vec<u8>,
}

/// An answer: its status and headers, and its body, read once.
pub struct Response {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: Headers,
    /// The fingerprint (SHA-256 of the SPKI, hex) of the TLS key it came
    /// over, when the transport can tell.
    pub spki: Option<String>,
    /// The body. A read that fails is a [`Error::Transport`].
    pub body: Box<dyn Read + Send>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("spki", &self.spki)
            .finish_non_exhaustive()
    }
}

/// Sends requests. `timeout` bounds the wait for the answer's headers, then
/// the wait between two reads of its body.
pub trait Transport: Send + Sync {
    /// Sends `request`.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the connection fails or the server's
    /// certificate is refused; [`Error::PinMismatch`] when the key is not the
    /// pinned one.
    fn send(&self, request: &Request, timeout: Duration) -> Result<Response>;

    /// Pins a key seen without a CA to vouch for it, when the transport can
    /// (SPEC.md § 5.3).
    fn pin_seen(&self, _spki: &str) {}
}

/// Reads `source` whole, `limit` bytes at most.
///
/// # Errors
///
/// [`Error::Document`] beyond `limit`; [`Error::Transport`] when the read
/// fails.
pub fn read_body(source: &mut dyn Read, limit: usize, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut taken = source.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1));
    taken
        .read_to_end(&mut out)
        .map_err(|e| Error::Transport(format!("{what}: the connection failed: {e}")))?;
    if out.len() > limit {
        return Err(Error::field(format!("more than {limit} bytes"), what));
    }
    Ok(out)
}

/// Whether a bearer token may be sent: opaque text without spaces or control
/// characters.
#[must_use]
pub fn token_ok(token: &str) -> bool {
    !token.is_empty() && !token.chars().any(|c| c.is_whitespace() || c.is_control())
}
