//! An HTTP transport over `reqwest` (blocking) and `rustls`, with the
//! server's key pinned (SPEC.md § 5.3). Feature `http`.
//!
//! Each TLS connection is checked as its handshake ends, before a byte of
//! the request is written: a key other than the one pinned fails the
//! handshake and the request fails with [`Error::PinMismatch`], nothing sent.
//!
//! - `verify` true and no pin: the certificate must chain to a CA (the
//!   Mozilla roots, plus `ca`).
//! - a pin (the SHA-256 of the key's `SubjectPublicKeyInfo`, hex): the
//!   connection must be over that key, whatever a CA says.
//! - `verify` false and no pin: any key; the one seen is on the answer
//!   (`Response::spki`) so that a client pins it (pairing, § 5.3).

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use reqwest::blocking::Client as Http;
use reqwest::redirect::Policy;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::error::{Error, Result};
use crate::limits::clip;
use crate::spki::{check_pin, is_sha256_hex, spki_sha256};
use crate::transport::{Headers, Request, Response, Transport};

const MARK: &str = "lantern-pin-mismatch";

#[derive(Debug, Default)]
struct State {
    pin: Mutex<Option<String>>,
    seen: Mutex<Option<String>>,
}

#[derive(Debug)]
struct PinVerifier {
    state: Arc<State>,
    verify: bool,
    inner: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let seen = spki_sha256(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("no key in the certificate: {e}")))?;
        *self
            .state
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(seen.clone());
        let pin = self
            .state
            .pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match pin {
            Some(pinned) if check_pin(&seen, &pinned) => Ok(ServerCertVerified::assertion()),
            Some(pinned) => Err(rustls::Error::General(format!(
                "{MARK} seen={seen} pinned={pinned}"
            ))),
            None if self.verify => {
                self.inner
                    .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            }
            None => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// What an [`HttpTransport`] is made with.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// False: a server no CA vouches for, whose key the client reads to pin
    /// it (pairing, SPEC.md § 5.3).
    pub verify: bool,
    /// The key pinned (SHA-256 of its SPKI, hex): every connection is over it,
    /// or fails.
    pub pin: Option<String>,
    /// CA certificates to trust beyond the Mozilla roots (DER).
    pub ca: Vec<Vec<u8>>,
    /// The wait to connect, and the TCP keep-alive that ends a connection
    /// the server stopped answering. (`reqwest`'s blocking client has no
    /// timeout between two reads of a body, and a total one would cut a
    /// large download.)
    pub timeout: Duration,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            verify: true,
            pin: None,
            ca: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Sends requests with `reqwest`; pins a LAN server's key.
#[derive(Debug)]
pub struct HttpTransport {
    http: Http,
    state: Arc<State>,
    verify: bool,
}

impl HttpTransport {
    /// A transport.
    ///
    /// # Errors
    ///
    /// [`Error::Document`] for a pin that is not a SHA-256 in hex or a CA that
    /// is not DER; [`Error::Transport`] when the TLS stack cannot be built.
    pub fn new(options: &HttpOptions) -> Result<Self> {
        if let Some(pin) = &options.pin
            && !is_sha256_hex(&pin.to_ascii_lowercase())
        {
            return Err(Error::field(
                "pin is the SHA-256 of the server key's SPKI, hex",
                "pin",
            ));
        }
        let provider = Arc::new(ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in &options.ca {
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(|e| Error::field(format!("not a CA certificate: {e}"), "ca"))?;
        }
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| Error::Transport(format!("TLS: {e}")))?;
        let state = Arc::new(State {
            pin: Mutex::new(options.pin.as_ref().map(|p| p.to_ascii_lowercase())),
            seen: Mutex::new(None),
        });
        let verifier = PinVerifier {
            state: state.clone(),
            verify: options.verify,
            inner,
            provider: provider.clone(),
        };
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Transport(format!("TLS: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let http = Http::builder()
            .use_preconfigured_tls(config)
            .redirect(Policy::none())
            .connect_timeout(options.timeout)
            .tcp_keepalive(options.timeout)
            .timeout(None)
            .build()
            .map_err(|e| Error::Transport(format!("HTTP client: {e}")))?;
        Ok(Self {
            http,
            state,
            verify: options.verify,
        })
    }

    /// The key pinned now.
    #[must_use]
    pub fn pin(&self) -> Option<String> {
        self.state
            .pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn failure(url: &str, error: &reqwest::Error) -> Error {
    let mut text = String::new();
    let mut at: Option<&dyn std::error::Error> = Some(error);
    while let Some(e) = at {
        let _ = write!(text, "{e}: ");
        at = e.source();
    }
    if let Some(rest) = text.split(MARK).nth(1) {
        let field = |name: &str| {
            rest.split(name)
                .nth(1)
                .and_then(|r| r.split(|c: char| !c.is_ascii_hexdigit()).next())
                .unwrap_or("")
                .to_owned()
        };
        return Error::PinMismatch {
            seen: field("seen="),
            pinned: field("pinned="),
        };
    }
    Error::Transport(format!("{url}: {}", clip(text.trim_end_matches(": "), 300)))
}

impl Transport for HttpTransport {
    fn send(&self, request: &Request, _timeout: Duration) -> Result<Response> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| Error::field("not an HTTP method", "method"))?;
        let mut builder = self.http.request(method, &request.url);
        for (name, value) in request.headers.iter() {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }
        *self
            .state
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let sent = builder.send().map_err(|e| failure(&request.url, &e))?;
        let mut headers = Headers::new();
        for (name, value) in sent.headers() {
            if let Ok(v) = value.to_str() {
                headers.add(name.as_str(), v);
            }
        }
        let spki = request
            .url
            .starts_with("https:")
            .then(|| {
                self.state
                    .seen
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            })
            .flatten();
        Ok(Response {
            status: sent.status().as_u16(),
            headers,
            spki,
            body: Box::new(sent),
        })
    }

    fn pin_seen(&self, spki: &str) {
        let mut pin = self
            .state
            .pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.verify && pin.is_none() {
            *pin = Some(spki.to_ascii_lowercase());
        }
    }
}
