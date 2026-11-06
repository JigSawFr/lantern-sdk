//! The client's side of SPEC.md § 5.2 to § 5.5: a pairing under way, the
//! checks a client makes on a pairing code before it shows anything, and what
//! an invitation's link carries.

use url::Url;

use crate::error::{Error, Result};
use crate::generated::models::PairingCode;
use crate::http::{origin, plain_http_allowed};
use crate::limits::clip;
use crate::signatures::DeviceKey;
use crate::spki::{is_sha256_hex, short};

/// A pairing under way (SPEC.md § 5.2). Show `code`, `verify` and the
/// fingerprint (the short one of the key of the server the client talks to:
/// the user compares it with the one the server's page shows), `verify` as a
/// QR code the client draws. Then poll.
#[derive(Debug, Clone)]
pub struct Pairing {
    /// The server's document.
    pub document: PairingCode,
    /// The device key the pairing asks to bind, when it does.
    pub key: Option<DeviceKey>,
    /// The fingerprint of the server's TLS key as this client saw it (hex),
    /// when the transport could tell.
    pub spki: Option<String>,
    /// The poll address, absolute.
    pub poll_url: String,
    /// When it started, on the caller's clock (seconds).
    pub started: f64,
}

impl Pairing {
    /// The code to show.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.document.code
    }

    /// The address the user opens to approve.
    #[must_use]
    pub fn verify(&self) -> &str {
        &self.document.verify
    }

    /// The QR code's text: `verify` with the code in its query.
    #[must_use]
    pub fn verify_complete(&self) -> &str {
        if self.document.verify_complete.is_empty() {
            &self.document.verify
        } else {
            &self.document.verify_complete
        }
    }

    /// The short fingerprint of the server's key, as this client sees it.
    #[must_use]
    pub fn fingerprint(&self) -> Option<String> {
        self.spki.as_deref().and_then(short)
    }

    /// When the code expires, on the caller's clock (seconds).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn deadline(&self) -> f64 {
        self.started + self.document.expires as f64
    }

    /// Whether the code expired at `now` (seconds on the caller's clock).
    #[must_use]
    pub fn expired(&self, now: f64) -> bool {
        now >= self.deadline()
    }
}

/// The checks a client makes on a pairing code before it shows anything
/// (SPEC.md § 5.2): `verify` an address it may open (HTTPS, or HTTP on
/// loopback); `verify_complete` on verify's origin with the code in its
/// query; the poll address on the server's origin.
///
/// # Errors
///
/// [`Error::Document`] when one fails.
pub fn check_pairing_code(doc: &PairingCode, root: &str) -> Result<()> {
    let where_ = "pairing code";
    if !plain_http_allowed(&doc.verify).unwrap_or(false) {
        return Err(Error::field(
            format!(
                "verify {:?} is not an HTTPS address",
                clip(&doc.verify, 100)
            ),
            where_,
        ));
    }
    if !doc.verify_complete.is_empty() {
        let typed = symbols(&doc.code);
        let query = Url::parse(&doc.verify_complete)
            .ok()
            .and_then(|u| u.query().map(symbols))
            .unwrap_or_default();
        let same = matches!(
            (origin(&doc.verify_complete), origin(&doc.verify)),
            (Ok(a), Ok(b)) if a == b
        );
        if !same || !query.contains(&typed) {
            return Err(Error::field(
                "verify_complete is not verify's address with the code in it",
                where_,
            ));
        }
    }
    let absolute = doc.poll.contains("://") || doc.poll.starts_with("//");
    if absolute {
        let same = matches!(
            (origin(&doc.poll), origin(root)),
            (Ok(a), Ok(b)) if a == b
        );
        if !same {
            return Err(Error::field(
                "the poll address is not on the server's origin",
                where_,
            ));
        }
    }
    if !(1..=600).contains(&doc.expires) || doc.interval < 1 {
        return Err(Error::field(
            "expires is 1 to 600 seconds, interval 1 or more",
            where_,
        ));
    }
    Ok(())
}

fn symbols(text: &str) -> String {
    text.to_ascii_uppercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

/// What an invitation's link carries (SPEC.md § 5.5): the server's origin,
/// the invitation's code, and the fingerprint of its key (SHA-256 hex) when
/// no CA vouches for its certificate: a client pins that one, without asking
/// the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationLink {
    /// The server's address, `scheme://host[:port]/`.
    pub url: String,
    /// The invitation's code, upper case.
    pub code: String,
    /// The key's SHA-256, hex, when the link carries it.
    pub spki: Option<String>,
}

/// Reads an invitation's link.
///
/// # Errors
///
/// [`Error::Document`] when it is not one.
pub fn invitation_link(link: &str) -> Result<InvitationLink> {
    let bad = |m: &str| Error::field(m.to_owned(), "invitation link");
    let parsed = Url::parse(link).map_err(|_| bad("an invitation's link is an HTTPS address"))?;
    if !plain_http_allowed(link).unwrap_or(false) {
        return Err(bad("an invitation's link is an HTTPS address"));
    }
    let values = |name: &str| -> Vec<String> {
        parsed
            .query_pairs()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .collect()
    };
    let codes = values("invitation");
    let spkis = values("spki");
    if codes.len() != 1 || spkis.len() > 1 {
        return Err(bad("an invitation's link carries one invitation code"));
    }
    let code = codes
        .first()
        .map(|c| c.trim().to_ascii_uppercase())
        .unwrap_or_default();
    let count = code.replace('-', "").chars().count();
    if !(16..=32).contains(&count) {
        return Err(bad("an invitation's code is 16 to 32 symbols"));
    }
    let spki = spkis.first().map(|s| s.to_ascii_lowercase());
    if spki.as_deref().is_some_and(|s| !is_sha256_hex(s)) {
        return Err(bad("spki is the server key's SHA-256, hex"));
    }
    let host = parsed.host_str().ok_or_else(|| bad("no host"))?;
    let port = parsed.port().map_or(String::new(), |p| format!(":{p}"));
    Ok(InvitationLink {
        url: format!("{}://{host}{port}/", parsed.scheme()),
        code,
        spki,
    })
}
