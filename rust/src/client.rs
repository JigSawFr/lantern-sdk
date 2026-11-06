//! The client: a server's library read over a [`Transport`] (SPEC.md § 4 to
//! § 6), its handshake, its pairing, the requests it signs, its lists and its
//! downloads.
//!
//! The client does no input or output of its own, draws no random bytes and
//! reads no clock but the ones it is given ([`Entropy`], [`ClientOptions::clock`]).

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::documents::{SCHEMA, schema_of};
use crate::download::{DownloadSink, Expected, Verifier};
use crate::error::{Error, Result};
use crate::generated::models::{AppsPage, Handshake, PairingCode, PairingToken};
use crate::http::{
    JSON_TYPE, Origin, PLATFORM_HEADER, media_type, on_origin, origin, plain_http_allowed, quote,
};
use crate::limits::{JSON_DOCUMENT, clip, load_json, printable};
use crate::pairing::{Pairing, check_pairing_code};
use crate::problem::{ProblemKind, problem_error};
use crate::signatures::DeviceKey;
use crate::transport::{Headers, Request, Response, Transport, read_body, token_ok};
use crate::vocabulary::FAMILIES;

const ERROR_BODY: usize = 1 << 16;
const MISSING_WANTS: [&str; 3] = ["base", "update", "dlc"];

/// The source of random bytes, which the caller provides: the library draws
/// none itself (device keys, nonces).
pub trait Entropy: Send + Sync {
    /// Fills `buffer` with random bytes.
    fn fill(&self, buffer: &mut [u8]);
}

/// The operating system's random bytes (feature `os-entropy`).
#[cfg(feature = "os-entropy")]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

#[cfg(feature = "os-entropy")]
impl Entropy for OsEntropy {
    fn fill(&self, buffer: &mut [u8]) {
        // A system without random bytes cannot sign anything safely.
        #[allow(clippy::expect_used)]
        getrandom::fill(buffer).expect("the operating system gives no random bytes");
    }
}

/// A route or schema a server said is going away (SPEC.md § 3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deprecation {
    /// What was called.
    pub what: String,
    /// `Deprecation`.
    pub since: String,
    /// `Sunset`, when the server said.
    pub sunset: Option<String>,
    /// The `Link` of `rel="deprecation"`, when there is one.
    pub link: Option<String>,
}

/// What a client is made with.
#[derive(Clone)]
pub struct ClientOptions {
    /// The caller's platform (`Lantern-Platform`).
    pub platform: Option<String>,
    /// `Accept-Language`.
    pub accept_language: Option<String>,
    /// The wait for an answer's headers, then between two reads of its body.
    pub timeout: Duration,
    /// `User-Agent`.
    pub user_agent: String,
    /// The time, in Unix seconds; the system clock by default.
    pub clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    /// The random bytes.
    pub entropy: Arc<dyn Entropy>,
    /// The server's base path when it is known (otherwise the handshake gives it).
    pub base: Option<String>,
}

impl ClientOptions {
    /// Options with the given random bytes and the defaults for the rest.
    #[must_use]
    pub fn new(entropy: Arc<dyn Entropy>) -> Self {
        Self {
            platform: None,
            accept_language: None,
            timeout: Duration::from_secs(30),
            user_agent: format!("lantern-protocol/{} (rust)", env!("CARGO_PKG_VERSION")),
            clock: Arc::new(system_time),
            entropy,
            base: None,
        }
    }
}

fn system_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// One call to the server.
struct Call<'a> {
    method: &'a str,
    what: &'a str,
    /// A full URL, or `None` for the route `path` under the base.
    url: Option<String>,
    path: &'a str,
    query: Vec<(String, String)>,
    well_known: bool,
    body: Option<Vec<u8>>,
    json_body: bool,
    headers: Vec<(&'a str, String)>,
    anonymous: bool,
    signer: Option<&'a DeviceKey>,
    statuses: &'a [u16],
    empty_statuses: &'a [u16],
}

impl<'a> Call<'a> {
    fn get(what: &'a str, path: &'a str) -> Self {
        Self {
            method: "GET",
            what,
            url: None,
            path,
            query: Vec::new(),
            well_known: false,
            body: None,
            json_body: false,
            headers: Vec::new(),
            anonymous: false,
            signer: None,
            statuses: &[200],
            empty_statuses: &[],
        }
    }
}

/// An answer the client accepted: its status, headers and body.
struct Reply {
    status: u16,
    body: Vec<u8>,
}

/// Options of a list.
#[derive(Debug, Clone, Default)]
pub struct AppsOptions {
    /// The platform, when it is not the client's.
    pub platform: Option<String>,
    /// Items per page.
    pub page_size: Option<u32>,
    /// The cursor of the page to read.
    pub cursor: Option<String>,
    /// `type`: `base`, `update`, `dlc`.
    pub kind: Option<String>,
    /// `title_id`.
    pub title_id: Option<String>,
    /// `q`, a search.
    pub q: Option<String>,
    /// `sort`: `name`, `added` or `release`.
    pub sort: Option<String>,
    /// `format`.
    pub format: Option<String>,
}

/// Options of `missing`.
#[derive(Debug, Clone, Default)]
pub struct MissingOptions {
    /// The platform, when it is not the client's.
    pub platform: Option<String>,
    /// Items per page.
    pub page_size: Option<u32>,
    /// The cursor.
    pub cursor: Option<String>,
    /// The formats the device reads.
    pub formats: Vec<String>,
    /// What the device satisfies.
    pub satisfies: Vec<String>,
}

/// A client of one server.
pub struct Client<T: Transport> {
    transport: T,
    root: String,
    server: Origin,
    base: Option<String>,
    hello: Option<Handshake>,
    token: Option<String>,
    key: Option<DeviceKey>,
    clock_offset: f64,
    last_spki: Option<String>,
    deprecations: Vec<Deprecation>,
    options: ClientOptions,
}

impl<T: Transport> std::fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("root", &self.root)
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "…"))
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl<T: Transport> Client<T> {
    /// A client of the server at `url` (its origin).
    ///
    /// # Errors
    ///
    /// [`Error::InsecureTransport`] for plain HTTP to an address that is not a
    /// loopback one (SPEC.md § 2); [`Error::Document`] when `url` is not an
    /// http(s) address or `base` is not a path.
    pub fn new(url: &str, transport: T, options: ClientOptions) -> Result<Self> {
        if !plain_http_allowed(url)? {
            return Err(Error::InsecureTransport(format!(
                "{url}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)"
            )));
        }
        let server = origin(url)?;
        let default = if server.scheme == "https" { 443 } else { 80 };
        let root = if server.port == default {
            format!("{}://{}", server.scheme, server.host)
        } else {
            format!("{}://{}:{}", server.scheme, server.host, server.port)
        };
        let base = options.base.as_deref().map(check_base).transpose()?;
        Ok(Self {
            transport,
            root,
            server,
            base,
            hello: None,
            token: None,
            key: None,
            clock_offset: 0.0,
            last_spki: None,
            deprecations: Vec::new(),
            options,
        })
    }

    /// The transport.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The handshake, once read.
    #[must_use]
    pub fn hello(&self) -> Option<&Handshake> {
        self.hello.as_ref()
    }

    /// The deprecations the server announced.
    #[must_use]
    pub fn deprecations(&self) -> &[Deprecation] {
        &self.deprecations
    }

    /// The fingerprint of the TLS key the last answer came over (hex).
    #[must_use]
    pub fn last_spki(&self) -> Option<&str> {
        self.last_spki.as_deref()
    }

    /// Takes a token and, if it is bound, the device key that signs with it
    /// (SPEC.md § 5.4). `None` forgets both.
    ///
    /// # Errors
    ///
    /// When `token` is not opaque text.
    pub fn set_token(&mut self, token: Option<&str>, key: Option<DeviceKey>) -> Result<()> {
        if let Some(t) = token
            && !token_ok(t)
        {
            return Err(Error::field(
                "a token is opaque text without spaces",
                "token",
            ));
        }
        self.token = token.map(str::to_owned);
        self.key = if token.is_some() { key } else { None };
        Ok(())
    }

    /// The time to sign with, in Unix seconds: the clock's, corrected by its
    /// offset to the server's `Date`.
    #[must_use]
    pub fn now(&self) -> f64 {
        (self.options.clock)() + self.clock_offset
    }

    fn skew(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        self.hello
            .as_ref()
            .and_then(|h| h.auth.as_ref())
            .map_or(crate::signatures::SKEW as f64, |a| a.skew as f64)
    }

    fn v1(&self, path: &str) -> Result<String> {
        let base = self
            .base
            .as_deref()
            .ok_or_else(|| Error::document("no base yet: read the handshake first"))?;
        Ok(format!("{}{base}/v1{path}", self.root))
    }

    /// An address a document gave, made absolute: it must be on the server's origin.
    fn on_origin_url(&self, address: &str, what: &str) -> Result<String> {
        let base = url::Url::parse(&format!("{}/", self.root))
            .map_err(|_| Error::document("the server's address"))?;
        let joined = base.join(address).map_err(|_| Error::UnexpectedResponse {
            message: format!("{what}: {:?} is not an address", clip(address, 100)),
            status: None,
        })?;
        if !on_origin(joined.as_str(), &self.server) {
            return Err(Error::UnexpectedResponse {
                message: format!(
                    "{what}: {:?} is not on the server's origin",
                    clip(address, 100)
                ),
                status: None,
            });
        }
        Ok(joined.into())
    }

    fn nonce(&self) -> String {
        let mut random = [0u8; 16];
        self.options.entropy.fill(&mut random);
        crate::signatures::new_nonce(random)
    }

    fn prepare(&self, call: &Call<'_>, url: &str) -> Result<Request> {
        if !plain_http_allowed(url)? {
            return Err(Error::InsecureTransport(format!(
                "{url}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)"
            )));
        }
        let mut headers = Headers::new();
        headers.set("User-Agent", self.options.user_agent.clone());
        headers.set("Accept", JSON_TYPE);
        headers.set("Accept-Encoding", "identity");
        let accept_schema = FAMILIES
            .iter()
            .map(|f| format!("{f}={SCHEMA}"))
            .collect::<Vec<_>>()
            .join(", ");
        headers.set("Accept-Schema", accept_schema);
        if let Some(language) = &self.options.accept_language {
            headers.set("Accept-Language", language.clone());
        }
        if let Some(platform) = &self.options.platform {
            headers.set(PLATFORM_HEADER, platform.clone());
        }
        let body = call.body.clone().unwrap_or_default();
        if call.json_body {
            headers.set("Content-Type", JSON_TYPE);
        }
        for (name, value) in &call.headers {
            headers.set(name, value.clone());
        }
        // Credentials and the signature go to the server's origin alone.
        if on_origin(url, &self.server) {
            if !call.anonymous
                && let Some(token) = &self.token
            {
                headers.set("Authorization", format!("Bearer {token}"));
            }
            let device = call.signer.or(if call.anonymous {
                None
            } else {
                self.key.as_ref()
            });
            if let Some(key) = device {
                // Truncation to whole seconds is what `created` is.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let stamp = self.now().max(0.0).trunc() as u64;
                let random = self.nonce();
                let signed = key.sign_request(
                    call.method,
                    url,
                    headers.get("Authorization"),
                    &body,
                    stamp,
                    &random,
                )?;
                if let Some(digest) = signed.content_digest {
                    headers.set("Content-Digest", digest);
                }
                headers.set("Signature-Input", signed.signature_input);
                headers.set("Signature", signed.signature);
            }
        }
        Ok(Request {
            method: call.method.to_owned(),
            url: url.to_owned(),
            headers,
            body,
        })
    }

    fn server_offset(&self, headers: &Headers) -> Option<f64> {
        let when = parse_http_date(headers.get("Date")?)?;
        Some(when - (self.options.clock)())
    }

    /// Takes the offset of the server's `Date` after a 401 `signature_expired`
    /// (SPEC.md § 5.4); false when it changes nothing.
    fn adjust_clock(&mut self, headers: &Headers) -> bool {
        match self.server_offset(headers) {
            Some(offset) if (offset - self.clock_offset).abs() >= 1.0 => {
                self.clock_offset = offset;
                true
            }
            _ => false,
        }
    }

    fn note(&mut self, what: &str, headers: &Headers) {
        let Some(since) = headers.get("Deprecation") else {
            return;
        };
        let link = headers
            .get("Link")
            .unwrap_or("")
            .split(',')
            .find(|p| p.contains("rel=\"deprecation\""))
            .and_then(|p| p.split(';').next())
            .map(|p| {
                p.trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_owned()
            })
            .filter(|l| !l.is_empty());
        let found = Deprecation {
            what: what.to_owned(),
            since: printable(since, 64),
            sunset: headers.get("Sunset").map(|s| printable(s, 64)),
            link,
        };
        if !self.deprecations.contains(&found) {
            self.deprecations.push(found);
        }
    }

    fn error(what: &str, status: u16, headers: &Headers, body: &[u8]) -> Error {
        if (300..400).contains(&status) {
            return Error::UnexpectedResponse {
                message: format!("{what}: a redirect ({status}), which Lantern never sends"),
                status: Some(status),
            };
        }
        if status >= 400 {
            return Error::Problem(Box::new(problem_error(
                status,
                body,
                headers.get("Retry-After"),
            )));
        }
        Error::UnexpectedResponse {
            message: format!("{what}: status {status}"),
            status: Some(status),
        }
    }

    fn call_url(&mut self, call: &Call<'_>) -> Result<String> {
        if call.well_known {
            return Ok(format!("{}/.well-known/lantern", self.root));
        }
        if let Some(url) = &call.url {
            return Ok(url.clone());
        }
        if self.base.is_none() {
            self.handshake()?;
        }
        let mut url = self.v1(call.path)?;
        if !call.query.is_empty() {
            let query = call
                .query
                .iter()
                .map(|(k, v)| format!("{}={}", quote(k), quote(v).replace("%2C", ",")))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query);
        }
        Ok(url)
    }

    /// One call, with one more try when the server refuses a signature the
    /// client can mend (a clock that was off, a nonce taken twice).
    fn send(&mut self, call: &Call<'_>) -> Result<Reply> {
        let url = self.call_url(call)?;
        for attempt in 0..2 {
            let request = self.prepare(call, &url)?;
            let response = self.transport.send(&request, self.options.timeout)?;
            self.last_spki.clone_from(&response.spki);
            let signed = request.headers.contains("Signature");
            match self.finish(call, response) {
                Ok(reply) => return Ok(reply),
                Err((error, headers)) => {
                    let retry = attempt == 0
                        && signed
                        && match &error {
                            Error::Problem(p) if p.kind == ProblemKind::SignatureExpired => {
                                self.adjust_clock(&headers)
                            }
                            Error::Problem(p) => p.kind == ProblemKind::SignatureReplayed,
                            _ => false,
                        };
                    if !retry {
                        return Err(error);
                    }
                }
            }
        }
        Err(Error::document(format!(
            "{}: the request could not be signed",
            call.what
        )))
    }

    fn finish(
        &mut self,
        call: &Call<'_>,
        mut response: Response,
    ) -> std::result::Result<Reply, (Error, Headers)> {
        let headers = response.headers.clone();
        let fail = |e: Error| (e, headers.clone());
        self.note(call.what, &headers);
        let status = response.status;
        if call.statuses.contains(&status) {
            if media_type(headers.get("Content-Type")) != JSON_TYPE {
                return Err(fail(Error::UnexpectedResponse {
                    message: format!(
                        "{}: Content-Type {:?}, not JSON",
                        call.what,
                        headers.get("Content-Type").unwrap_or("")
                    ),
                    status: Some(status),
                }));
            }
            let body = read_body(&mut response.body, JSON_DOCUMENT, call.what).map_err(&fail)?;
            if call.well_known {
                self.accept_handshake(&body, &headers).map_err(&fail)?;
            }
            return Ok(Reply { status, body });
        }
        if call.empty_statuses.contains(&status) {
            return Ok(Reply {
                status,
                body: Vec::new(),
            });
        }
        let body = read_body(&mut response.body, ERROR_BODY, call.what).unwrap_or_default();
        Err(fail(Self::error(call.what, status, &headers, &body)))
    }

    fn accept_handshake(&mut self, body: &[u8], headers: &Headers) -> Result<()> {
        let hello: Handshake = document(body, "handshake")?;
        if !hello.versions.contains(&1) {
            return Err(Error::document(
                "the server does not serve version 1 of the protocol",
            ));
        }
        if self.base.is_none() {
            self.base = Some(check_base(&hello.base)?);
        }
        self.hello = Some(hello);
        // After the handshake (Annex B.9): a clock off by half the server's
        // window or more signs with the server's time.
        if let Some(offset) = self.server_offset(headers)
            && offset.abs() >= self.skew() / 2.0
        {
            self.clock_offset = offset;
        }
        Ok(())
    }

    // The handshake (SPEC.md § 4.2).

    /// `GET /.well-known/lantern`: the server, the caller's account and what it is offered.
    ///
    /// # Errors
    ///
    /// Any error of the exchange.
    pub fn handshake(&mut self) -> Result<Handshake> {
        let mut call = Call::get("handshake", "");
        call.well_known = true;
        self.send(&call)?;
        self.hello
            .clone()
            .ok_or_else(|| Error::document("no handshake"))
    }

    /// Whether the server offers `family` to this caller, in a schema this
    /// library reads (the handshake read first if need be).
    ///
    /// # Errors
    ///
    /// When the handshake fails.
    pub fn offers(&mut self, family: &str) -> Result<bool> {
        if self.hello.is_none() {
            self.handshake()?;
        }
        Ok(self
            .hello
            .as_ref()
            .and_then(|h| h.features.get(family))
            .is_some_and(|level| *level > 0 && *level <= SCHEMA))
    }

    // The library (SPEC.md § 6).

    fn platform_query(platform: Option<&str>) -> Vec<(String, String)> {
        platform
            .map(|p| vec![("platform".to_owned(), p.to_owned())])
            .unwrap_or_default()
    }

    fn listing(page_size: Option<u32>, cursor: Option<&str>) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(n) = page_size {
            out.push(("page_size".to_owned(), n.to_string()));
        }
        if let Some(c) = cursor {
            out.push(("cursor".to_owned(), c.to_owned()));
        }
        out
    }

    /// One page of apps; `next` is the cursor of the following page.
    ///
    /// # Errors
    ///
    /// Any error of the exchange.
    pub fn apps(&mut self, options: &AppsOptions) -> Result<AppsPage> {
        if let Some(sort) = &options.sort
            && !["name", "added", "release"].contains(&sort.as_str())
        {
            return Err(Error::field("sort is name, added or release", "sort"));
        }
        let mut call = Call::get("apps", "/apps");
        call.query = Self::platform_query(options.platform.as_deref());
        call.query
            .extend(Self::listing(options.page_size, options.cursor.as_deref()));
        for (name, value) in [
            ("type", &options.kind),
            ("title_id", &options.title_id),
            ("q", &options.q),
            ("sort", &options.sort),
            ("format", &options.format),
        ] {
            if let Some(v) = value {
                call.query.push((name.to_owned(), v.clone()));
            }
        }
        let reply = self.send(&call)?;
        document(&reply.body, "apps")
    }

    /// Every app, page by page. An expired cursor is a `Gone`: read the list
    /// again from its start.
    ///
    /// # Errors
    ///
    /// Any error of the exchange, a server that gives the same cursor twice, or
    /// one that never stops giving pages.
    pub fn all_apps(
        &mut self,
        options: &AppsOptions,
    ) -> Result<Vec<crate::generated::models::App>> {
        let mut options = options.clone();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        loop {
            if seen.len() >= crate::limits::PAGES {
                return Err(Error::UnexpectedResponse {
                    message: "apps: the server gave more pages than a client follows".to_owned(),
                    status: None,
                });
            }
            let page = self.apps(&options)?;
            out.extend(page.items);
            let Some(next) = page.next else {
                return Ok(out);
            };
            if !seen.insert(next.clone()) {
                return Err(Error::UnexpectedResponse {
                    message: "apps: the server gave the same cursor twice".to_owned(),
                    status: None,
                });
            }
            options.cursor = Some(next);
        }
    }

    /// What the device is missing (SPEC.md § 6.3): `installed` as
    /// `(app_id, version_code)`, `want` among `base`, `update`, `dlc`.
    ///
    /// # Errors
    ///
    /// When the request is not one the specification allows, or any error of
    /// the exchange.
    pub fn missing(
        &mut self,
        installed: &[(String, i64)],
        want: &[&str],
        options: &MissingOptions,
    ) -> Result<AppsPage> {
        if options.platform.is_none() && self.options.platform.is_none() {
            return Err(Error::field(
                "what is missing needs a platform (SPEC.md § 4.3)",
                "platform",
            ));
        }
        let mut wants: Vec<&str> = Vec::new();
        for w in want {
            if !wants.contains(w) {
                wants.push(w);
            }
        }
        if wants.is_empty() || wants.iter().any(|w| !MISSING_WANTS.contains(w)) {
            return Err(Error::field("want lists base, update or dlc", "want"));
        }
        let mut body = json!({
            "schema": SCHEMA,
            "installed": installed
                .iter()
                .map(|(id, code)| json!({ "app_id": id, "version_code": code }))
                .collect::<Vec<_>>(),
            "want": wants,
        });
        if !options.formats.is_empty() {
            set(&mut body, "formats", json!(options.formats));
        }
        if !options.satisfies.is_empty() {
            set(&mut body, "satisfies", json!(options.satisfies));
        }
        let mut call = Call::get("missing", "/apps/missing");
        call.method = "POST";
        call.query = Self::platform_query(options.platform.as_deref());
        call.query
            .extend(Self::listing(options.page_size, options.cursor.as_deref()));
        call.body = Some(serde_json::to_vec(&body).map_err(|e| Error::document(e.to_string()))?);
        call.json_body = true;
        let reply = self.send(&call)?;
        document(&reply.body, "missing")
    }

    // Pairing (SPEC.md § 5.2).

    /// Starts a pairing: the device asks `scopes`, with a key that binds the
    /// token to it when `key` is given. Show the code, then poll.
    ///
    /// # Errors
    ///
    /// When the request is not one the specification allows, or the server's
    /// code fails the checks of § 5.2, or any error of the exchange.
    pub fn pair(
        &mut self,
        device: &str,
        scopes: &[&str],
        key: Option<DeviceKey>,
        invitation: Option<&str>,
    ) -> Result<Pairing> {
        if self.hello.is_none() {
            self.handshake()?;
        }
        if device.trim().is_empty() || device.len() > 512 {
            return Err(Error::field(
                "device is the device's name, 512 bytes at most",
                "device",
            ));
        }
        if scopes.is_empty() {
            return Err(Error::field("ask for one scope at least", "scopes"));
        }
        let mut unique: Vec<&str> = Vec::new();
        for s in scopes {
            if !unique.contains(s) {
                unique.push(s);
            }
        }
        let mut body = json!({ "schema": SCHEMA, "device": device, "scopes": unique });
        if let Some(k) = &key {
            set(&mut body, "key", k.document());
        }
        if let Some(i) = invitation {
            set(&mut body, "invitation", Value::String(i.to_owned()));
        }
        let mut call = Call::get("pairing", "/pairing");
        call.method = "POST";
        call.anonymous = true;
        call.body = Some(serde_json::to_vec(&body).map_err(|e| Error::document(e.to_string()))?);
        call.json_body = true;
        call.statuses = &[200, 201];
        let reply = self.send(&call)?;
        let code: PairingCode = document(&reply.body, "pairing")?;
        check_pairing_code(&code, &self.root)?;
        let spki = self.last_spki.clone();
        if let Some(s) = &spki {
            self.transport.pin_seen(s);
        }
        let poll_url = self.on_origin_url(&code.poll, "pairing poll")?;
        Ok(Pairing {
            document: code,
            key,
            spki,
            poll_url,
            started: (self.options.clock)(),
        })
    }

    /// One poll: the token once approved (the client then uses it), `None`
    /// while waiting; `Gone` when refused, expired or collected.
    ///
    /// # Errors
    ///
    /// Any error of the exchange.
    pub fn poll_pairing(&mut self, pairing: &Pairing) -> Result<Option<PairingToken>> {
        let mut call = Call::get("pairing poll", "");
        call.url = Some(self.on_origin_url(&pairing.poll_url, "pairing poll")?);
        call.anonymous = true;
        call.signer = pairing.key.as_ref();
        call.statuses = &[200];
        call.empty_statuses = &[202];
        let reply = self.send(&call)?;
        if reply.status == 202 {
            return Ok(None);
        }
        let token: PairingToken = document(&reply.body, "pairing poll")?;
        let key = if token.bound == Some(false) {
            None
        } else {
            pairing.key.clone()
        };
        self.set_token(Some(&token.token), key)?;
        Ok(Some(token))
    }

    // Downloads (SPEC.md § 6.6).

    /// Downloads `url` (a route of this server, or another host: credentials
    /// go to the server's origin alone) into `sink`: resumed with a `Range`
    /// from what the sink holds, hashed as it arrives, and committed only once
    /// its size and SHA-256 are right.
    ///
    /// # Errors
    ///
    /// [`Error::Integrity`] for a file that is not what its document says (the
    /// sink is reset); [`Error::Transport`] for a cut connection (what arrived
    /// is kept for the next try); any other error of the exchange.
    pub fn download(
        &mut self,
        url: &str,
        sink: &mut dyn DownloadSink,
        expected: Expected<'_>,
        resume: bool,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let target = self.on_origin_or_absolute(url)?;
        let verifier = Verifier::new(expected, url);
        for _ in 0..3 {
            let mut offset = if resume { sink.held_size()? } else { 0 };
            if !resume || offset > expected.size {
                sink.reset()?;
                offset = 0;
            }
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            if offset > 0 {
                let mut held = sink.held()?;
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    let n = held
                        .read(&mut buffer)
                        .map_err(|e| Error::Transport(format!("{url}: {e}")))?;
                    if n == 0 {
                        break;
                    }
                    verifier.feed(&mut hasher, &mut size, buffer.get(..n).unwrap_or(&[]))?;
                }
            }
            if offset == expected.size {
                if verifier.finish(hasher, size).is_err() {
                    sink.reset()?;
                    continue;
                }
                return sink.commit();
            }
            let mut call = Call::get("download", "");
            call.url = Some(target.clone());
            call.statuses = &[];
            if offset > 0 {
                call.headers.push(("Range", format!("bytes={offset}-")));
            }
            call.headers.push(("Accept", "*/*".to_owned()));
            let request = self.prepare(&call, &target)?;
            let mut response = self.transport.send(&request, self.options.timeout)?;
            self.last_spki.clone_from(&response.spki);
            if response.status == 416 && offset > 0 {
                sink.reset()?;
                continue;
            }
            if response.status != 200 && response.status != 206 {
                let body = read_body(&mut response.body, ERROR_BODY, url).unwrap_or_default();
                return Err(Self::error(url, response.status, &response.headers, &body));
            }
            let start = match verifier.start(
                response.status,
                response.headers.get("Content-Range"),
                offset,
            ) {
                Ok(s) => s,
                Err(e) => {
                    sink.reset()?;
                    return Err(e);
                }
            };
            if start == 0 && offset > 0 {
                sink.reset()?;
                hasher = Sha256::new();
                size = 0;
            }
            let outcome = (|| -> Result<()> {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    let n = response.body.read(&mut buffer).map_err(|e| {
                        Error::Transport(format!("{url}: the connection failed: {e}"))
                    })?;
                    if n == 0 {
                        break;
                    }
                    let chunk = buffer.get(..n).unwrap_or(&[]);
                    verifier.feed(&mut hasher, &mut size, chunk)?;
                    sink.append(chunk)?;
                }
                Ok(())
            })();
            match outcome {
                Ok(()) => {}
                Err(e @ Error::Transport(_)) => return Err(e),
                Err(e) => {
                    sink.reset()?;
                    return Err(e);
                }
            }
            if let Err(e) = verifier.finish(hasher, size) {
                sink.reset()?;
                return Err(e);
            }
            return sink.commit();
        }
        Err(Error::document(format!(
            "{url}: the download could not be resumed"
        )))
    }

    fn on_origin_or_absolute(&self, address: &str) -> Result<String> {
        let base = url::Url::parse(&format!("{}/", self.root))
            .map_err(|_| Error::document("the server's address"))?;
        base.join(address)
            .map(Into::into)
            .map_err(|_| Error::field(format!("{:?} is not an address", clip(address, 100)), "url"))
    }

    /// An app's file, checked against its `sha256` and `size` (SPEC.md § 6.1,
    /// § 6.6).
    ///
    /// # Errors
    ///
    /// As [`download`](Self::download).
    pub fn download_app(
        &mut self,
        app: &crate::generated::models::App,
        sink: &mut dyn DownloadSink,
    ) -> Result<()> {
        let size = u64::try_from(app.size).map_err(|_| Error::field("a negative size", "size"))?;
        self.download(
            &app.file,
            sink,
            Expected {
                sha256: &app.sha256,
                size,
            },
            true,
        )
    }
}

/// Sets a member of a JSON object.
fn set(object: &mut Value, name: &str, value: Value) {
    if let Some(map) = object.as_object_mut() {
        map.insert(name.to_owned(), value);
    }
}

/// A base path on the server's origin.
fn check_base(base: &str) -> Result<String> {
    if !base.starts_with('/') || base.starts_with("//") || base.contains(['?', '#']) {
        return Err(Error::document(format!(
            "base {:?} is not a path on the server's origin",
            clip(base, 80)
        )));
    }
    Ok(base.trim_end_matches('/').to_owned())
}

/// A document read from a body within SPEC.md § 13's limits; a newer `schema`
/// is [`Error::NewerSchema`].
fn document<D: DeserializeOwned>(body: &[u8], what: &str) -> Result<D> {
    let value = load_json(body, JSON_DOCUMENT, what)?;
    let schema = schema_of(&value, what)?;
    if schema > SCHEMA {
        return Err(Error::NewerSchema {
            what: what.to_owned(),
            schema,
        });
    }
    serde_json::from_value(value).map_err(|e| Error::field(clip(&e.to_string(), 160), what))
}

/// An HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`) as Unix seconds.
#[allow(clippy::many_single_char_names)]
fn parse_http_date(text: &str) -> Option<f64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_, day, month, year, time, zone] = parts.as_slice() else {
        return None;
    };
    if *zone != "GMT" {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| m == month)?;
    let mut hms = time.split(':').map(|n| n.parse::<i64>().ok());
    let (h, m, s) = (hms.next()??, hms.next()??, hms.next()??);
    let (y, d) = (year.parse::<i64>().ok()?, day.parse::<i64>().ok()?);
    // Days from the civil date (Howard Hinnant's algorithm).
    let mo = i64::try_from(month).ok()? + 1;
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    #[allow(clippy::cast_precision_loss)]
    Some((days * 86_400 + h * 3600 + m * 60 + s) as f64)
}
