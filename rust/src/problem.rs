//! A server's problem+json answers (SPEC.md § 12), by status.
//!
//! A server's answer becomes the [`ProblemKind`] of its status (`NotFound`
//! for 404, `Gone` for 410…), whatever its `code`: a code this library does
//! not know is read by its status alone, as SPEC.md § 12 asks. `code` is then
//! `None`; `problem` keeps the document as the server sent it.

use std::fmt;

use crate::generated::models::{ERROR_CODES, Problem};
use crate::limits::{load_json, printable};

const DETAIL_LIMIT: usize = 512;
const PROBLEM_LIMIT: usize = 1 << 16;

/// The kind of an error answer: its status, and for a 401 or a 403 its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProblemKind {
    /// 400, 405 and 416.
    BadRequest,
    /// 401: no token where one is needed, or one the server does not take.
    Unauthorized,
    /// 401 `signature_required`: the token is bound to a key, or the server takes only bound tokens.
    SignatureRequired,
    /// 401 `signature_invalid`: not the token's key, or not the form of SPEC.md § 5.4.
    SignatureInvalid,
    /// 401 `signature_expired`: `created` was outside the server's window.
    SignatureExpired,
    /// 401 `signature_replayed`: a nonce the server saw.
    SignatureReplayed,
    /// 403: a scope missing.
    Forbidden,
    /// 403 `account_frozen`: the account may do nothing for now.
    AccountFrozen,
    /// 404.
    NotFound,
    /// 409.
    Conflict,
    /// 410: an expired cursor or `since` token, a pairing, a file id.
    Gone,
    /// 412: a sync write whose `If-Match` is not the collection's (SPEC.md § 20.4).
    PreconditionFailed,
    /// 413.
    TooLarge,
    /// 422: `unsupported_schema` or `digest_mismatch`.
    Unprocessable,
    /// 429: wait `retry_after` seconds.
    SlowDown,
    /// 500, or another 5xx.
    ServerError,
    /// 503: scanning or maintenance; `retry_after` says when to come back.
    Unavailable,
    /// Any other status.
    Other,
}

impl ProblemKind {
    /// Whether this is one of the signature refusals of SPEC.md § 5.4.
    #[must_use]
    pub fn is_signature(self) -> bool {
        matches!(
            self,
            Self::SignatureRequired
                | Self::SignatureInvalid
                | Self::SignatureExpired
                | Self::SignatureReplayed
        )
    }
}

/// A server's error answer (SPEC.md § 12).
#[derive(Debug, Clone, PartialEq)]
pub struct ProblemError {
    /// The HTTP status.
    pub status: u16,
    /// Its kind.
    pub kind: ProblemKind,
    /// The problem document, when the body was one.
    pub problem: Option<Problem>,
    /// The `code`, when this library knows it (otherwise act on the status).
    pub code: Option<String>,
    /// `detail` for people: bounded, without control characters.
    pub detail: Option<String>,
    /// `Retry-After`, in seconds, when the server said.
    pub retry_after: Option<u64>,
}

impl fmt::Display for ProblemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.status,
            self.code.as_deref().unwrap_or("error")
        )?;
        match &self.detail {
            Some(detail) => write!(f, ": {detail}"),
            None => Ok(()),
        }
    }
}

impl std::error::Error for ProblemError {}

fn seconds(value: Option<&str>) -> Option<u64> {
    let text = value?.trim();
    (!text.is_empty() && text.len() <= 10 && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

fn kind_of(status: u16, code: Option<&str>) -> ProblemKind {
    match (status, code) {
        (401, Some("signature_required")) => ProblemKind::SignatureRequired,
        (401, Some("signature_invalid")) => ProblemKind::SignatureInvalid,
        (401, Some("signature_expired")) => ProblemKind::SignatureExpired,
        (401, Some("signature_replayed")) => ProblemKind::SignatureReplayed,
        (401, _) => ProblemKind::Unauthorized,
        (403, Some("account_frozen")) => ProblemKind::AccountFrozen,
        (403, _) => ProblemKind::Forbidden,
        (400 | 405 | 416, _) => ProblemKind::BadRequest,
        (404, _) => ProblemKind::NotFound,
        (409, _) => ProblemKind::Conflict,
        (410, _) => ProblemKind::Gone,
        (412, _) => ProblemKind::PreconditionFailed,
        (413, _) => ProblemKind::TooLarge,
        (422, _) => ProblemKind::Unprocessable,
        (429, _) => ProblemKind::SlowDown,
        (503, _) => ProblemKind::Unavailable,
        (500..=599, _) => ProblemKind::ServerError,
        _ => ProblemKind::Other,
    }
}

/// The error for an answer: its kind by status, its problem document when the
/// body is one (an unreadable body still gives the status). `retry_after` is
/// the value of the `Retry-After` header.
#[must_use]
pub fn problem_error(status: u16, body: &[u8], retry_after: Option<&str>) -> ProblemError {
    let problem: Option<Problem> = load_json(body, PROBLEM_LIMIT, "problem")
        .ok()
        .and_then(|value| serde_json::from_value(value).ok());
    let raw_code = problem.as_ref().map(|p| p.code.as_str());
    let code = raw_code
        .filter(|code| ERROR_CODES.contains(code))
        .map(str::to_owned);
    let kind = kind_of(status, raw_code);
    let text = problem
        .as_ref()
        .and_then(|p| p.detail.as_deref().or(p.title.as_deref()));
    let detail = text
        .filter(|t| !t.is_empty())
        .map(|t| printable(t, DETAIL_LIMIT));
    ProblemError {
        status,
        kind,
        problem,
        code,
        detail,
        retry_after: seconds(retry_after),
    }
}
