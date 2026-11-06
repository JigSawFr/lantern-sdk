//! Client and server library for the [Lantern protocol](https://lantern.boreale.dev/),
//! the open, versioned protocol between console homebrews and the library
//! servers people run at home.
//!
//! The documents are typed structs generated from the specification's JSON
//! Schemas ([`generated`]); each keeps the fields it does not know and writes
//! them back (SPEC.md § 3.2).

pub mod bytes;
pub mod canonical;
pub mod client;
pub mod digest;
pub mod documents;
pub mod download;
pub mod error;
pub mod generated;
pub mod http;
pub mod limits;
pub mod pairing;
pub mod problem;
pub mod profiles;
pub mod signatures;
pub mod spki;
pub mod transport;
pub mod uid;
pub mod variants;
pub mod vocabulary;

pub use error::{Error, Result};

/// The specification draft this version follows.
pub const SPEC_DRAFT: &str = "0.11";

/// The serde helper of an optional field that may also be `null` (a static
/// page's `next`): `None` is absent, `Some(None)` is `null`.
#[allow(clippy::option_option, clippy::ref_option)]
pub(crate) mod nullable {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(
        value: &Option<Option<T>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(inner) => inner.serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}
