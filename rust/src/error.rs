//! The errors of the library.
//!
//! A value or a document the library refuses is a [`Error::Document`]; a
//! certificate whose key it cannot find is a [`Error::Certificate`]. Nothing
//! the library reads from outside ever makes it panic.

use std::fmt;

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
    }
}

impl std::error::Error for Error {}

/// The result type of the library.
pub type Result<T> = std::result::Result<T, Error>;
