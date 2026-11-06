//! Device keys and signed requests (SPEC.md § 5.4, RFC 9421), for both sides.
//!
//! A token bound to a device key travels with a signature of the request, by
//! that key, under the label `lantern`:
//!
//! - its components, in this order: `@method`, `@target-uri`, then
//!   `authorization` when the request carries a token, then `content-digest`
//!   when it has a body;
//! - its parameters, in this order: `created` (Unix seconds), `nonce` (22 to
//!   64 characters of base64url), `keyid` (the base64url of the SHA-256 of the
//!   key's 32 bytes, unpadded) and `alg="ed25519"`;
//! - the signature base: one line per component, then `@signature-params`,
//!   joined by a line feed, without one at the end.
//!
//! A client signs with [`DeviceKey::sign_request`]; a server checks with
//! [`verify_request`], which refuses with the code § 5.4 gives, in its order.
//! The library draws no random bytes and reads no clock: the caller gives the
//! seed, the nonce's bytes, the time.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use regex::Regex;

use crate::bytes::{from_base64, to_base64, to_hex};
use crate::digest::{content_digest, sha256};
use crate::error::{Error, Result};
use crate::vocabulary::pattern;

/// The label of the signature.
pub const LABEL: &str = "lantern";
/// The algorithm.
pub const ALG: &str = "ed25519";
/// `auth.skew` when a server announces none (SPEC.md § 5.4).
pub const SKEW: u64 = 300;
/// The bounds of `auth.skew`.
pub const SKEW_RANGE: (u64, u64) = (60, 900);
/// `Signature-Input` and `Signature`, each, in bytes (SPEC.md § 13).
pub const HEADER_LIMIT: usize = 1024;

static INPUT: LazyLock<Regex> = LazyLock::new(|| {
    pattern(
        r#"^lantern=\(((?:"[a-z@-]+")(?: "[a-z@-]+")*)\);created=([0-9]{1,12});nonce="([A-Za-z0-9_-]{22,64})";keyid="([A-Za-z0-9_-]{43})";alg="ed25519"$"#,
    )
});
static VALUE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^lantern=:([A-Za-z0-9+/]{86}==):$"));
static NONCE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^[A-Za-z0-9_-]{22,64}$"));
static HOST_PORT: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^(\[[0-9A-Fa-f:.]+\]|[^:\[\]]+)(?::([0-9]{1,5}))?$"));

/// The base64url of `bytes`, without padding.
#[must_use]
pub fn to_base64url(bytes: &[u8]) -> String {
    to_base64(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// A key's thumbprint, its `keyid`: the base64url of the SHA-256 of its 32
/// bytes, without padding.
#[must_use]
pub fn keyid(public_key: &[u8]) -> String {
    to_base64url(&sha256(public_key))
}

/// A key's short fingerprint, for people (SPEC.md § 5.3's form):
/// `21FE 31DF A154 A261`.
#[must_use]
pub fn short_fingerprint(public_key: &[u8]) -> String {
    let head = to_hex(&sha256(public_key)).to_uppercase();
    head.as_bytes()
        .chunks(4)
        .take(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A nonce from 16 random bytes (128 bits) the caller drew: base64url, 22
/// characters.
#[must_use]
pub fn new_nonce(random: [u8; 16]) -> String {
    to_base64url(&random)
}

/// Whether `signature` is a valid Ed25519 signature of `message` by
/// `public_key`, by the strict equation: a key or a point of small order, a
/// non-canonical encoding and an `S` not reduced are refused (SPEC.md § 8.4,
/// `vectors/ed25519-refused.json`).
#[must_use]
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify_strict(message, &sig).is_ok()
}

/// A device's Ed25519 key for one server (SPEC.md § 5.4): made at pairing,
/// kept with the token, never sent anywhere.
#[derive(Clone)]
pub struct DeviceKey {
    signing: SigningKey,
    public: [u8; 32],
    keyid: String,
}

impl DeviceKey {
    /// A key from its 32-byte secret seed, which the caller drew.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        let keyid = keyid(&public);
        Self {
            signing,
            public,
            keyid,
        }
    }

    /// A key from its seed in base64 (as a server record keeps it).
    ///
    /// # Errors
    ///
    /// When `seed` is not 32 bytes in base64.
    pub fn from_base64(seed: &str) -> Result<Self> {
        let raw = from_base64(seed)
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| Error::field("a device key is its 32-byte seed, in base64", "seed"))?;
        Ok(Self::from_seed(raw))
    }

    /// The public key's 32 bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// The public key, in base64.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        to_base64(&self.public)
    }

    /// The `keyid`.
    #[must_use]
    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    /// The short fingerprint, for people.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        short_fingerprint(&self.public)
    }

    /// The secret seed, in base64: for the place the device keeps its keys,
    /// and nowhere else.
    #[must_use]
    pub fn seed_base64(&self) -> String {
        to_base64(self.signing.as_bytes())
    }

    /// `key` of a pairing request: `{"alg": "ed25519", "public_key": <base64>}`.
    #[must_use]
    pub fn document(&self) -> serde_json::Value {
        serde_json::json!({ "alg": ALG, "public_key": self.public_key_base64() })
    }

    /// The signature of `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Signs a request (SPEC.md § 5.4). `url` is absolute; `authorization` is
    /// the Authorization header when the request has one (it is then
    /// covered); `body` is covered through its `Content-Digest` when it is
    /// not empty. `created` is Unix seconds; `nonce` is
    /// [`new_nonce`]'s.
    ///
    /// # Errors
    ///
    /// When `url` is not an absolute http(s) URL, or `nonce` is not 22 to 64
    /// characters of base64url.
    pub fn sign_request(
        &self,
        method: &str,
        url: &str,
        authorization: Option<&str>,
        body: &[u8],
        created: u64,
        nonce: &str,
    ) -> Result<SignedHeaders> {
        if !NONCE.is_match(nonce) {
            return Err(Error::field(
                "a nonce is 22 to 64 characters of base64url",
                "nonce",
            ));
        }
        let with_body = !body.is_empty();
        let digest = with_body.then(|| content_digest(body));
        let params = signature_params(
            &components(authorization.is_some(), with_body),
            created,
            nonce,
            &self.keyid,
        );
        let base = signature_base(
            &method.to_ascii_uppercase(),
            &target_uri(url)?,
            authorization,
            digest.as_deref(),
            &params,
        );
        Ok(SignedHeaders {
            content_digest: digest,
            signature_input: format!("{LABEL}={params}"),
            signature: format!("{LABEL}=:{}:", to_base64(&self.sign(base.as_bytes()))),
        })
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({})", self.keyid)
    }
}

/// The headers a signed request adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `Content-Digest`, when the request has a body.
    pub content_digest: Option<String>,
    /// `Signature-Input`.
    pub signature_input: String,
    /// `Signature`.
    pub signature: String,
}

/// `@target-uri` (RFC 9421 § 2.2.2, SPEC.md § 5.4): the scheme, the host in
/// lower case, its port only when not the scheme's default, then the path and
/// query exactly as sent (their percent-encoding unchanged).
///
/// # Errors
///
/// When `url` is not an absolute http(s) URL this library reads.
pub fn target_uri(url: &str) -> Result<String> {
    let bad = || {
        Error::field(
            format!(
                "{} is not an absolute http(s) URL",
                crate::limits::clip(url, 100)
            ),
            "url",
        )
    };
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(bad());
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let hp = HOST_PORT.captures(authority).ok_or_else(bad)?;
    let mut host = hp.get(1).ok_or_else(bad)?.as_str().to_ascii_lowercase();
    if let Some(port) = hp.get(2) {
        let n: u32 = port.as_str().parse().map_err(|_| bad())?;
        let default = if scheme == "https" { 443 } else { 80 };
        if n != default {
            host.push(':');
            host.push_str(&n.to_string());
        }
    }
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, q),
        None => (tail, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    Ok(format!("{scheme}://{host}{path}{query}"))
}

/// `@target-uri` of a request a server received: its scheme, its `Host`
/// header and its request target as sent.
///
/// # Errors
///
/// When there is no `Host` this library reads.
pub fn received_uri(scheme: &str, host: &str, target: &str) -> Result<String> {
    let h = host.trim();
    if h.is_empty() || h.contains(['/', '?', '#', '@', ' ', '\t']) {
        return Err(Error::field("no Host this server can read", "host"));
    }
    let slash = if target.starts_with('/') { "" } else { "/" };
    target_uri(&format!("{scheme}://{h}{slash}{target}"))
}

/// The components a request covers, in their order.
#[must_use]
pub fn components(with_token: bool, with_body: bool) -> Vec<&'static str> {
    let mut out = vec!["@method", "@target-uri"];
    if with_token {
        out.push("authorization");
    }
    if with_body {
        out.push("content-digest");
    }
    out
}

/// `@signature-params`: the `lantern` member's value of `Signature-Input`.
#[must_use]
pub fn signature_params(covered: &[&str], created: u64, nonce: &str, key_id: &str) -> String {
    let inner = covered
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!("({inner});created={created};nonce=\"{nonce}\";keyid=\"{key_id}\";alg=\"{ALG}\"")
}

/// The signature base (RFC 9421 § 2.5) of SPEC.md § 5.4's components.
#[must_use]
pub fn signature_base(
    method: &str,
    uri: &str,
    authorization: Option<&str>,
    digest: Option<&str>,
    params: &str,
) -> String {
    let mut lines = vec![
        format!("\"@method\": {method}"),
        format!("\"@target-uri\": {uri}"),
    ];
    if let Some(a) = authorization {
        lines.push(format!("\"authorization\": {a}"));
    }
    if let Some(d) = digest {
        lines.push(format!("\"content-digest\": {d}"));
    }
    lines.push(format!("\"@signature-params\": {params}"));
    lines.join("\n")
}

/// A signature refused (SPEC.md § 5.4): the server answers 401 with `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// `signature_required`, `signature_invalid`, `signature_expired` or
    /// `signature_replayed`.
    pub code: &'static str,
    /// Why, for the person who reads the answer.
    pub detail: String,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Refused {}

fn refuse(code: &'static str, detail: impl Into<String>) -> Refused {
    Refused {
        code,
        detail: detail.into(),
    }
}

/// The nonces taken, per key, kept `keep` seconds (twice `auth.skew` at
/// least, SPEC.md § 5.4): a nonce is never taken twice within them. Bounded:
/// past `limit` entries the expired go first, then the oldest.
#[derive(Debug)]
pub struct NonceCache {
    keep: f64,
    limit: usize,
    seen: HashMap<String, f64>,
}

impl Default for NonceCache {
    fn default() -> Self {
        #[allow(clippy::cast_precision_loss)]
        Self::new(2.0 * SKEW as f64, 200_000)
    }
}

impl NonceCache {
    /// A cache keeping nonces `keep` seconds, at most `limit` of them.
    #[must_use]
    pub fn new(keep: f64, limit: usize) -> Self {
        Self {
            keep,
            limit: limit.max(1),
            seen: HashMap::new(),
        }
    }

    /// True the first time; false when it was taken within the window. `now`
    /// is the server's clock, in seconds.
    pub fn take(&mut self, key_id: &str, nonce: &str, now: f64) -> bool {
        if self.seen.len() >= self.limit {
            self.seen.retain(|_, until| *until > now);
            if self.seen.len() >= self.limit {
                let mut entries: Vec<(String, f64)> =
                    self.seen.iter().map(|(k, t)| (k.clone(), *t)).collect();
                entries.sort_by(|a, b| a.1.total_cmp(&b.1));
                for (k, _) in entries.into_iter().take((self.limit / 10).max(1)) {
                    self.seen.remove(&k);
                }
            }
        }
        let entry = format!("{key_id} {nonce}");
        if self.seen.get(&entry).is_some_and(|until| *until > now) {
            return false;
        }
        self.seen.insert(entry, now + self.keep);
        true
    }

    /// How many nonces are kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether none is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// A signature that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The key's id.
    pub keyid: String,
    /// `created`, Unix seconds.
    pub created: u64,
    /// The nonce.
    pub nonce: String,
}

/// What [`verify_request`] needs besides the request.
#[derive(Debug)]
pub struct VerifyOptions<'a> {
    /// Whether the request carries a token (so `authorization` is covered).
    pub with_token: bool,
    /// Whether the request has a body (so `content-digest` is covered).
    pub with_body: bool,
    /// The nonces taken.
    pub nonces: &'a mut NonceCache,
    /// `auth.skew`, seconds ([`SKEW`] when the server announces none).
    pub skew: u64,
    /// The server's clock, Unix seconds.
    pub now: f64,
}

/// The headers of a request a server checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestHeaders<'a> {
    /// `Authorization`.
    pub authorization: Option<&'a str>,
    /// `Content-Digest`.
    pub content_digest: Option<&'a str>,
    /// `Signature-Input`.
    pub signature_input: Option<&'a str>,
    /// `Signature`.
    pub signature: Option<&'a str>,
}

/// Checks a request's signature by the key `public_key` (32 bytes), in the
/// order of SPEC.md § 5.4. `uri` is the request's `@target-uri`
/// ([`received_uri`]). The body's match with its `Content-Digest` is the
/// caller's to check after (422 `digest_mismatch`).
///
/// # Errors
///
/// [`Refused`] with the code § 5.4 gives.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub fn verify_request(
    method: &str,
    uri: &str,
    headers: &RequestHeaders<'_>,
    public_key: &[u8],
    options: VerifyOptions<'_>,
) -> std::result::Result<Verified, Refused> {
    let (Some(input), Some(value)) = (
        headers.signature_input.filter(|s| !s.is_empty()),
        headers.signature.filter(|s| !s.is_empty()),
    ) else {
        return Err(refuse(
            "signature_required",
            "This token is bound to a device key: sign the request (Signature-Input, Signature).",
        ));
    };
    if input.len() > HEADER_LIMIT || value.len() > HEADER_LIMIT {
        return Err(refuse(
            "signature_invalid",
            "Signature-Input and Signature are 1 KiB at most.",
        ));
    }
    let input = input.trim();
    let (Some(m), Some(v)) = (INPUT.captures(input), VALUE.captures(value.trim())) else {
        return Err(refuse(
            "signature_invalid",
            "Signature-Input or Signature is not of the form SPEC.md § 5.4 gives (the label lantern alone, its parameters in their order).",
        ));
    };
    let group = |c: &regex::Captures<'_>, i: usize| c.get(i).map_or("", |g| g.as_str()).to_owned();
    let covered: Vec<String> = group(&m, 1)
        .split(' ')
        .map(|c| c.replace('"', ""))
        .collect();
    let wanted = components(options.with_token, options.with_body);
    if covered
        .iter()
        .map(String::as_str)
        .ne(wanted.iter().copied())
    {
        return Err(refuse(
            "signature_invalid",
            format!(
                "The signature covers {}, not {}",
                covered.join(" "),
                wanted.join(" ")
            ),
        ));
    }
    if options.with_body && headers.content_digest.is_none() {
        return Err(refuse(
            "signature_invalid",
            "A signed request with a body carries its Content-Digest.",
        ));
    }
    let kid = group(&m, 4);
    if kid != keyid(public_key) {
        return Err(refuse(
            "signature_invalid",
            "keyid is not this token's key.",
        ));
    }
    let params = input.get(LABEL.len() + 1..).unwrap_or("");
    let base = signature_base(
        &method.to_ascii_uppercase(),
        uri,
        if options.with_token {
            headers.authorization
        } else {
            None
        },
        if options.with_body {
            headers.content_digest
        } else {
            None
        },
        params,
    );
    let signature = from_base64(&group(&v, 1)).unwrap_or_default();
    if !ed25519_verify(public_key, base.as_bytes(), &signature) {
        return Err(refuse(
            "signature_invalid",
            "The signature does not verify over the signature base of SPEC.md § 5.4.",
        ));
    }
    let created: u64 = group(&m, 2).parse().unwrap_or(0);
    #[allow(clippy::cast_precision_loss)]
    let off = created as f64 - options.now;
    #[allow(clippy::cast_precision_loss)]
    if off.abs() > options.skew as f64 {
        #[allow(clippy::cast_possible_truncation)]
        let seconds = off.trunc() as i64;
        return Err(refuse(
            "signature_expired",
            format!(
                "created is {seconds} s from this server's clock: take its Date, and sign within {} s.",
                options.skew
            ),
        ));
    }
    let nonce = group(&m, 3);
    if !options.nonces.take(&kid, &nonce, options.now) {
        return Err(refuse(
            "signature_replayed",
            "This nonce was taken already: a new one for each request.",
        ));
    }
    Ok(Verified {
        keyid: kid,
        created,
        nonce,
    })
}

/// `Accept-Signature` (RFC 9421 § 5.1) for a 401 of a signature: the
/// components and parameters the server wants.
#[must_use]
pub fn accept_signature(with_token: bool, with_body: bool, key_id: Option<&str>) -> String {
    let wanted = components(with_token, with_body)
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let kid = key_id.map_or(String::new(), |k| format!(";keyid=\"{k}\""));
    format!("{LABEL}=({wanted}){kid};alg=\"{ALG}\"")
}

/// A server's `Accept-Signature`, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptSignature {
    /// The components it wants.
    pub components: Vec<String>,
    /// The `keyid` it names.
    pub keyid: Option<String>,
    /// The `alg` it names.
    pub alg: Option<String>,
}

static ACCEPT: LazyLock<Regex> = LazyLock::new(|| {
    pattern(
        r#"^\s*lantern=\(((?:"[a-z@-]+"(?: "[a-z@-]+")*)?)\)((?:;[a-z]+=(?:"[^"]*"|[0-9]+))*)\s*$"#,
    )
});
static ACCEPT_PARAM: LazyLock<Regex> =
    LazyLock::new(|| pattern(r#";([a-z]+)=(?:"([^"]*)"|[0-9]+)"#));

/// The `lantern` member of an `Accept-Signature`, or `None` when there is
/// none this library can read.
#[must_use]
pub fn parse_accept_signature(value: Option<&str>) -> Option<AcceptSignature> {
    let value = value.filter(|v| !v.is_empty() && v.len() <= HEADER_LIMIT)?;
    // Members are separated by a comma before another `name=`.
    let mut members = Vec::new();
    let mut start = 0;
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b',' {
            let rest = value.get(i + 1..).unwrap_or("").trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-'
                })
                .collect();
            if rest.get(name.len()..).is_some_and(|r| r.starts_with('=')) && !name.is_empty() {
                members.push(value.get(start..i).unwrap_or(""));
                start = i + 1;
            }
        }
    }
    members.push(value.get(start..).unwrap_or(""));
    for member in members {
        let Some(m) = ACCEPT.captures(member) else {
            continue;
        };
        let covered = m
            .get(1)
            .map(|g| g.as_str())
            .filter(|g| !g.is_empty())
            .map(|g| g.split(' ').map(|c| c.replace('"', "")).collect())
            .unwrap_or_default();
        let mut keyid = None;
        let mut alg = None;
        for p in ACCEPT_PARAM.captures_iter(m.get(2).map_or("", |g| g.as_str())) {
            let v = p
                .get(2)
                .map(|g| g.as_str().to_owned())
                .filter(|s| !s.is_empty());
            match p.get(1).map(|g| g.as_str()) {
                Some("keyid") => keyid = v,
                Some("alg") => alg = v,
                _ => {}
            }
        }
        return Some(AcceptSignature {
            components: covered,
            keyid,
            alg,
        });
    }
    None
}
