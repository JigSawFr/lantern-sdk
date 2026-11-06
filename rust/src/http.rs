//! HTTP pieces both sides share: origins, the loopback rule of SPEC.md § 2,
//! media types and percent-encoding.

use url::{Host, Url};

use crate::error::{Error, Result};
use crate::limits::clip;

/// The header that names the caller's platform.
pub const PLATFORM_HEADER: &str = "Lantern-Platform";
/// The media type of every document.
pub const JSON_TYPE: &str = "application/json";
/// The media type of an error.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// An origin: scheme, host (lower case, IPv6 in brackets) and port, made
/// explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// `http` or `https`.
    pub scheme: String,
    /// The host.
    pub host: String,
    /// The port.
    pub port: u16,
}

/// The origin of an absolute http(s) URL.
///
/// # Errors
///
/// When `url` is not one.
pub fn origin(url: &str) -> Result<Origin> {
    let bad = || {
        Error::field(
            format!("{} is not an absolute http(s) URL", clip(url, 100)),
            "url",
        )
    };
    let parsed = Url::parse(url).map_err(|_| bad())?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(bad());
    }
    let host = match parsed.host().ok_or_else(bad)? {
        Host::Domain(d) => d.to_ascii_lowercase(),
        Host::Ipv4(a) => a.to_string(),
        Host::Ipv6(a) => format!("[{a}]"),
    };
    let port = parsed.port_or_known_default().ok_or_else(bad)?;
    Ok(Origin {
        scheme: scheme.to_owned(),
        host,
        port,
    })
}

/// Whether `url` is on `server`'s origin; false for anything that is not an
/// absolute http(s) URL.
#[must_use]
pub fn on_origin(url: &str, server: &Origin) -> bool {
    origin(url).is_ok_and(|o| &o == server)
}

/// 127.0.0.0/8, `::1` or `localhost`: where plain HTTP is allowed, for
/// testing (SPEC.md § 2).
#[must_use]
pub fn is_loopback(host: &str) -> bool {
    let h = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_loopback(),
        Ok(std::net::IpAddr::V6(a)) => {
            a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

/// Whether `url` may be spoken to: HTTPS, or plain HTTP to a loopback
/// address.
///
/// # Errors
///
/// When `url` is not an absolute http(s) URL.
pub fn plain_http_allowed(url: &str) -> Result<bool> {
    let o = origin(url)?;
    Ok(o.scheme == "https" || is_loopback(&o.host))
}

/// The media type of a `Content-Type`, in lower case, without its parameters.
#[must_use]
pub fn media_type(content_type: Option<&str>) -> String {
    content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Percent-encodes a path segment or a query value (RFC 3986's unreserved
/// characters left as they are).
#[must_use]
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// The languages of an `Accept-Language` header, best first (`q=0` left out).
#[must_use]
pub fn accept_languages(header: Option<&str>) -> Vec<String> {
    let mut found: Vec<(f64, usize, String)> = Vec::new();
    for (i, part) in header.unwrap_or("").split(',').enumerate() {
        let mut pieces = part.trim().split(';');
        let tag = pieces.next().unwrap_or("").trim();
        if tag.is_empty() || tag == "*" {
            continue;
        }
        let mut q = 1.0;
        for param in pieces {
            if let Some((name, value)) = param.trim().split_once('=')
                && name.trim().eq_ignore_ascii_case("q")
            {
                q = value
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|n| n.is_finite())
                    .unwrap_or(0.0);
            }
        }
        if q > 0.0 {
            found.push((-q, i, tag.to_owned()));
        }
    }
    found.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    found.into_iter().map(|f| f.2).collect()
}
