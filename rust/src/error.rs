//! The errors of the library.
//!
//! A value or a document the library refuses is a [`Error::Document`]; a
//! certificate whose key it cannot find is a [`Error::Certificate`]. Nothing
//! the library reads from outside ever makes it panic.

use std::fmt;

use crate::problem::ProblemError;

/// What went wrong.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A value or a document that is not what the specification allows.
    Document {
        /// What is wrong with it.
        message: String,
        /// Where, as the name of the field (empty when it is the value itself).
        field: String,
    },
    /// A certificate whose key could not be found.
    Certificate(String),
    /// A server's error answer (SPEC.md § 12).
    Problem(Box<ProblemError>),
    /// A document of a newer `schema` than this library reads: by SPEC.md § 3.2
    /// it is absent (the feature is unavailable), not an error of the server.
    NewerSchema {
        /// What was read.
        what: String,
        /// Its `schema`.
        schema: i64,
    },
    /// A download that is not what its document says (its SHA-256 or its size,
    /// or a `Repr-Digest` that contradicts the document): nothing of it may be installed.
    Integrity(String),
    /// The connection failed, or the server's certificate was refused.
    Transport(String),
    /// The server's key is not the one pinned at pairing (SPEC.md § 5.3): an
    /// alarm, not an error to retry.
    PinMismatch {
        /// The key seen (SHA-256, hex).
        seen: String,
        /// The key pinned (SHA-256, hex).
        pinned: String,
    },
    /// Plain HTTP to an address that is not a loopback one (SPEC.md § 2).
    InsecureTransport(String),
    /// An answer the protocol does not allow here: a redirect, an unexpected
    /// status or content type.
    UnexpectedResponse {
        /// What was wrong.
        message: String,
        /// The status, when there was one.
        status: Option<u16>,
    },
}

impl Error {
    /// A document error without a field.
    #[must_use]
    pub fn document(message: impl Into<String>) -> Self {
        Self::Document {
            message: message.into(),
            field: String::new(),
        }
    }

    /// A document error at a field.
    #[must_use]
    pub fn field(message: impl Into<String>, field: impl Into<String>) -> Self {
        Self::Document {
            message: message.into(),
            field: field.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document { message, field } if field.is_empty() => f.write_str(message),
            Self::Document { message, field } => write!(f, "{field}: {message}"),
            Self::Certificate(message) => write!(f, "certificate: {message}"),
            Self::Problem(problem) => problem.fmt(f),
            Self::NewerSchema { what, schema } => {
                write!(
                    f,
                    "{what}: schema {schema}, newer than this library reads: treated as absent"
                )
            }
            Self::Integrity(message) => write!(f, "integrity: {message}"),
            Self::Transport(message) => write!(f, "transport: {message}"),
            Self::PinMismatch { seen, pinned } => write!(
                f,
                "the server's key changed: {}, pinned {}",
                crate::spki::short(seen).unwrap_or_default(),
                crate::spki::short(pinned).unwrap_or_default()
            ),
            Self::InsecureTransport(message) => write!(f, "insecure transport: {message}"),
            Self::UnexpectedResponse { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<ProblemError> for Error {
    fn from(problem: ProblemError) -> Self {
        Self::Problem(Box::new(problem))
    }
}

/// The result type of the library.
pub type Result<T> = std::result::Result<T, Error>;
