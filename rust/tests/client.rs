//! The client against a scripted server: the handshake, signed requests (and
//! the clock mended after a refusal), pairing, lists, and downloads.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lantern_protocol::client::{AppsOptions, Client, ClientOptions, Entropy, MissingOptions};
use lantern_protocol::digest::sha256_hex;
use lantern_protocol::download::{DownloadSink, Expected, MemorySink};
use lantern_protocol::error::{Error, Result};
use lantern_protocol::problem::ProblemKind;
use lantern_protocol::signatures::{
    DeviceKey, NonceCache, RequestHeaders, VerifyOptions, received_uri, verify_request,
};
use lantern_protocol::transport::{Headers, Request, Response, Transport};
use serde_json::{Value, json};

type Handler = dyn Fn(&Request, usize) -> Result<Response> + Send + Sync;

#[derive(Clone)]
struct Fake {
    seen: Arc<Mutex<Vec<Request>>>,
    handler: Arc<Handler>,
}

impl Fake {
    fn new(handler: impl Fn(&Request, usize) -> Result<Response> + Send + Sync + 'static) -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            handler: Arc::new(handler),
        }
    }
    fn requests(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request, _timeout: Duration) -> Result<Response> {
        let n = {
            let mut seen = self.seen.lock().unwrap();
            seen.push(request.clone());
            seen.len() - 1
        };
        (self.handler)(request, n)
    }
}

struct Counter;
impl Entropy for Counter {
    fn fill(&self, buffer: &mut [u8]) {
        static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        buffer.fill(n);
    }
}

#[allow(clippy::unnecessary_wraps)]
fn reply(status: u16, content_type: &str, body: &[u8], extra: &[(&str, &str)]) -> Result<Response> {
    let mut headers = Headers::new();
    headers.set("Content-Type", content_type);
    for (k, v) in extra {
        headers.set(k, *v);
    }
    Ok(Response {
        status,
        headers,
        spki: Some("ab".repeat(32)),
        body: Box::new(Cursor::new(body.to_vec())),
    })
}

#[allow(clippy::unnecessary_wraps)]
fn json_reply(status: u16, value: &Value) -> Result<Response> {
    reply(
        status,
        "application/json",
        value.to_string().as_bytes(),
        &[],
    )
}

fn example(name: &str) -> Value {
    let path = format!(
        "{}/../spec/examples/v1/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn options(now: f64) -> ClientOptions {
    let mut o = ClientOptions::new(Arc::new(Counter));
    o.clock = Arc::new(move || now);
    o.platform = Some("switch".to_owned());
    o
}

const URL: &str = "https://shelf.example.org";

fn serve(request: &Request) -> Option<Result<Response>> {
    let path = request.url.strip_prefix(URL)?;
    match path {
        "/.well-known/lantern" => Some(json_reply(200, &example("handshake"))),
        p if p.starts_with("/api/lantern/v1/apps") => Some(json_reply(200, &example("apps"))),
        _ => None,
    }
}

#[test]
fn the_handshake_gives_the_base_and_what_is_offered() {
    let fake = Fake::new(|r, _| serve(r).unwrap());
    let mut client = Client::new(URL, fake.clone(), options(1_793_345_400.0)).unwrap();
    let hello = client.handshake().unwrap();
    assert_eq!(hello.base, "/api/lantern");
    assert!(client.offers("library").unwrap());
    assert!(!client.offers("requests").unwrap());
    let sent = &fake.requests()[0];
    assert_eq!(sent.url, "https://shelf.example.org/.well-known/lantern");
    assert!(
        sent.headers
            .get("Accept-Schema")
            .unwrap()
            .contains("library=1")
    );
    assert_eq!(sent.headers.get("Lantern-Platform"), Some("switch"));
    assert!(!sent.headers.contains("Authorization"));
}

#[test]
fn plain_http_is_for_loopback_only() {
    let fake = Fake::new(|r, _| serve(r).unwrap());
    let refused = Client::new("http://shelf.example.org", fake.clone(), options(0.0));
    assert!(matches!(refused, Err(Error::InsecureTransport(_))));
    assert!(Client::new("http://127.0.0.1:8080", fake, options(0.0)).is_ok());
}

#[test]
fn a_bound_token_signs_and_the_server_takes_it() {
    let key = DeviceKey::from_seed([7u8; 32]);
    let public = *key.public_key();
    let now = 1_793_345_400.0;
    let cache = Arc::new(Mutex::new(NonceCache::default()));
    let checked = cache.clone();
    let fake = Fake::new(move |r, _| {
        if let Some(answer) = serve(r)
            && !r.url.contains("/apps")
        {
            return answer;
        }
        let uri = received_uri(
            "https",
            "shelf.example.org",
            r.url.strip_prefix(URL).unwrap(),
        )
        .unwrap();
        let headers = RequestHeaders {
            authorization: r.headers.get("Authorization"),
            content_digest: r.headers.get("Content-Digest"),
            signature_input: r.headers.get("Signature-Input"),
            signature: r.headers.get("Signature"),
        };
        let mut nonces = checked.lock().unwrap();
        let outcome = verify_request(
            &r.method,
            &uri,
            &headers,
            &public,
            VerifyOptions {
                with_token: headers.authorization.is_some(),
                with_body: !r.body.is_empty(),
                nonces: &mut nonces,
                skew: 300,
                now,
            },
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        json_reply(200, &example("apps"))
    });
    let mut client = Client::new(URL, fake.clone(), options(now)).unwrap();
    client.set_token(Some("et_example"), Some(key)).unwrap();
    let page = client.apps(&AppsOptions::default()).unwrap();
    assert!(!page.items.is_empty());
    let missing = client
        .missing(
            &[("0100ABCD00010000".to_owned(), 0)],
            &["update", "dlc"],
            &MissingOptions::default(),
        )
        .unwrap();
    assert!(!missing.items.is_empty());
    let requests = fake.requests();
    let posted = requests.last().unwrap();
    assert_eq!(posted.method, "POST");
    assert!(posted.headers.get("Content-Digest").is_some());
    assert!(posted.url.contains("/apps/missing"));
    let body: Value = serde_json::from_slice(&posted.body).unwrap();
    assert_eq!(body["want"], json!(["update", "dlc"]));
}

#[test]
fn a_clock_that_was_off_is_mended_after_signature_expired() {
    let key = DeviceKey::from_seed([9u8; 32]);
    let server_time = 1_793_345_400.0;
    let fake = Fake::new(move |r, n| {
        if r.url.ends_with("/.well-known/lantern") {
            return serve(r).unwrap();
        }
        if r.headers.contains("Signature") && n == 1 {
            let problem = json!({ "schema": 1, "status": 401, "code": "signature_expired", "title": "expired" });
            return reply(
                401,
                "application/problem+json",
                problem.to_string().as_bytes(),
                &[("Date", "Tue, 29 Oct 2026 12:30:00 GMT")],
            );
        }
        json_reply(200, &example("apps"))
    });
    // The handshake sees no Date, so the client keeps its own (wrong) clock.
    let mut client = Client::new(URL, fake.clone(), options(server_time - 4000.0)).unwrap();
    client.handshake().unwrap();
    client.set_token(Some("et_example"), Some(key)).unwrap();
    client.apps(&AppsOptions::default()).unwrap();
    let requests = fake.requests();
    assert_eq!(requests.len(), 3, "one try, one retry");
    let created = |r: &Request| -> f64 {
        let input = r.headers.get("Signature-Input").unwrap();
        input
            .split("created=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    assert!((created(&requests[1]) - (server_time - 4000.0)).abs() < 2.0);
    // 2026-10-29 12:30:00 GMT is 1793277000.
    assert!((created(&requests[2]) - 1_793_277_000.0).abs() < 2.0);
}

#[test]
fn a_server_error_is_its_status_and_a_newer_schema_is_absent() {
    let fake = Fake::new(|r, _| {
        if r.url.ends_with("/.well-known/lantern") {
            return serve(r).unwrap();
        }
        if r.url.contains("page_size=1") {
            return json_reply(200, &json!({ "schema": 99, "items": [] }));
        }
        let problem = json!({ "schema": 1, "status": 404, "code": "something_new", "detail": "no \u{7}such" });
        reply(
            404,
            "application/problem+json",
            problem.to_string().as_bytes(),
            &[],
        )
    });
    let mut client = Client::new(URL, fake, options(0.0)).unwrap();
    match client.apps(&AppsOptions::default()) {
        Err(Error::Problem(p)) => {
            assert_eq!(p.kind, ProblemKind::NotFound);
            assert_eq!(p.code, None);
            assert_eq!(p.detail.as_deref(), Some("no such"));
        }
        other => panic!("{other:?}"),
    }
    let newer = AppsOptions {
        page_size: Some(1),
        ..AppsOptions::default()
    };
    assert!(matches!(
        client.apps(&newer),
        Err(Error::NewerSchema { schema: 99, .. })
    ));
}

#[test]
fn a_redirect_is_never_followed() {
    let fake = Fake::new(|r, _| {
        if r.url.ends_with("/.well-known/lantern") {
            return serve(r).unwrap();
        }
        reply(
            302,
            "text/plain",
            b"",
            &[("Location", "https://elsewhere.example.org/")],
        )
    });
    let mut client = Client::new(URL, fake, options(0.0)).unwrap();
    assert!(matches!(
        client.apps(&AppsOptions::default()),
        Err(Error::UnexpectedResponse {
            status: Some(302),
            ..
        })
    ));
}

#[test]
fn pairing_polls_until_the_token_arrives() {
    let key = DeviceKey::from_seed([3u8; 32]);
    let fake = Fake::new(|r, n| {
        if let Some(answer) = serve(r)
            && r.url.ends_with("/.well-known/lantern")
        {
            return answer;
        }
        if r.method == "POST" {
            return json_reply(200, &example("pairing-code"));
        }
        if r.url.ends_with("/pairing/p_4Fh2") && n < 3 {
            return reply(202, "application/json", b"", &[]);
        }
        json_reply(200, &example("pairing-token"))
    });
    let mut client = Client::new(URL, fake.clone(), options(1000.0)).unwrap();
    let pairing = client
        .pair("Test console", &["library", "saves"], Some(key), None)
        .unwrap();
    assert_eq!(pairing.code(), "KQ4M-7TXD");
    assert_eq!(
        pairing.fingerprint().as_deref(),
        Some("ABAB ABAB ABAB ABAB")
    );
    assert_eq!(
        pairing.poll_url,
        "https://shelf.example.org/api/lantern/v1/pairing/p_4Fh2"
    );
    assert!(client.poll_pairing(&pairing).unwrap().is_none());
    let token = client.poll_pairing(&pairing).unwrap().unwrap();
    assert_eq!(token.token, "et_c8V1nQ0xYb");
    // The request that created the pairing carries no token, and no signature.
    let requests = fake.requests();
    let created = requests.iter().find(|r| r.method == "POST").unwrap();
    assert!(!created.headers.contains("Authorization"));
    assert!(!created.headers.contains("Signature"));
    // The poll is signed by the key being paired, without a token.
    let polled = requests
        .iter()
        .rev()
        .find(|r| r.method == "GET" && r.url.contains("/pairing/"))
        .unwrap();
    assert!(polled.headers.contains("Signature"));
    assert!(!polled.headers.contains("Authorization"));
}

fn file_server(body: &'static [u8]) -> Fake {
    Fake::new(move |r, _| {
        if r.url.ends_with("/.well-known/lantern") {
            return serve(r).unwrap();
        }
        if let Some(range) = r.headers.get("Range") {
            let from: usize = range
                .trim_start_matches("bytes=")
                .trim_end_matches('-')
                .parse()
                .unwrap();
            let tail = body.get(from..).unwrap();
            return reply(
                206,
                "application/octet-stream",
                tail,
                &[(
                    "Content-Range",
                    &format!("bytes {from}-{}/{}", body.len() - 1, body.len()),
                )],
            );
        }
        reply(200, "application/octet-stream", body, &[])
    })
}

#[test]
fn a_download_resumes_and_is_checked() {
    let body: &'static [u8] = b"the quick brown fox jumps over the lazy dog";
    let sum = sha256_hex(body);
    let fake = file_server(body);
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client.set_token(Some("et_example"), None).unwrap();
    let mut sink = MemorySink::new();
    sink.append(&body[..10]).unwrap();
    let expected = Expected {
        sha256: &sum,
        size: body.len() as u64,
    };
    client
        .download("/files/x", &mut sink, expected, true)
        .unwrap();
    assert_eq!(sink.bytes(), body);
    assert!(sink.committed());
    let sent = fake.requests().pop().unwrap();
    assert_eq!(sent.headers.get("Range"), Some("bytes=10-"));
    assert_eq!(sent.headers.get("Authorization"), Some("Bearer et_example"));
}

#[test]
fn a_file_that_is_not_what_its_document_says_is_not_kept() {
    let body: &'static [u8] = b"tampered";
    let fake = file_server(body);
    let mut client = Client::new(URL, fake, options(0.0)).unwrap();
    let mut sink = MemorySink::new();
    let wrong = "0".repeat(64);
    let err = client
        .download(
            "/files/x",
            &mut sink,
            Expected {
                sha256: &wrong,
                size: 8,
            },
            true,
        )
        .unwrap_err();
    assert!(matches!(err, Error::Integrity(_)), "{err:?}");
    assert!(sink.bytes().is_empty());
    assert!(!sink.committed());
    // More than the size says is refused as it arrives.
    let sum = sha256_hex(body);
    let err = client
        .download(
            "/files/x",
            &mut sink,
            Expected {
                sha256: &sum,
                size: 4,
            },
            true,
        )
        .unwrap_err();
    assert!(matches!(err, Error::Integrity(_)));
}

#[test]
fn credentials_stay_on_the_servers_origin() {
    let body: &'static [u8] = b"mirrored";
    let fake = file_server(body);
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client
        .set_token(Some("et_example"), Some(DeviceKey::from_seed([1u8; 32])))
        .unwrap();
    let sum = sha256_hex(body);
    let mut sink = MemorySink::new();
    client
        .download(
            "https://mirror.example.net/f/x",
            &mut sink,
            Expected {
                sha256: &sum,
                size: 8,
            },
            false,
        )
        .unwrap();
    let sent = fake.requests().pop().unwrap();
    assert_eq!(sent.url, "https://mirror.example.net/f/x");
    for name in [
        "Authorization",
        "Signature",
        "Signature-Input",
        "Content-Digest",
    ] {
        assert!(!sent.headers.contains(name), "{name} went to another host");
    }
}
