//! A server that means harm: what the client does when the other side lies,
//! floods or never stops. None of these may hang, run out of memory or
//! overflow the stack; each ends in an error.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use lantern_protocol::client::{AppsOptions, Client, ClientOptions, Entropy};
use lantern_protocol::digest::sha256_hex;
use lantern_protocol::download::{Expected, MemorySink};
use lantern_protocol::error::{Error, Result};
use lantern_protocol::transport::{Headers, Request, Response, Transport};

const URL: &str = "https://shelf.example.org";

struct Zero;
impl Entropy for Zero {
    fn fill(&self, buffer: &mut [u8]) {
        buffer.fill(7);
    }
}

/// A body that never ends.
struct Endless(u8);
impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(self.0);
        Ok(buf.len())
    }
}

struct Hostile {
    content_type: &'static str,
    status: u16,
    body: fn(&Request) -> Box<dyn Read + Send>,
}

impl Transport for Hostile {
    fn send(&self, request: &Request, _timeout: Duration) -> Result<Response> {
        let mut headers = Headers::new();
        headers.set("Content-Type", self.content_type);
        Ok(Response {
            status: self.status,
            headers,
            spki: None,
            body: (self.body)(request),
        })
    }
}

fn client(hostile: Hostile) -> Client<Hostile> {
    let mut options = ClientOptions::new(Arc::new(Zero));
    options.clock = Arc::new(|| 1_793_345_400.0);
    Client::new(URL, hostile, options).unwrap()
}

fn bytes(data: Vec<u8>) -> Box<dyn Read + Send> {
    Box::new(io::Cursor::new(data))
}

#[test]
fn a_body_that_never_ends_is_cut_off() {
    let mut c = client(Hostile {
        content_type: "application/json",
        status: 200,
        body: |_| Box::new(Endless(b' ')),
    });
    assert!(c.handshake().is_err());
}

#[test]
fn a_document_nested_without_end_is_refused_without_overflowing() {
    let mut c = client(Hostile {
        content_type: "application/json",
        status: 200,
        body: |_| bytes(vec![b'['; 1 << 20]),
    });
    assert!(c.handshake().is_err());
    let mut c = client(Hostile {
        content_type: "application/json",
        status: 200,
        body: |_| {
            let mut doc = "{\"a\":".repeat(10_000).into_bytes();
            doc.extend(b"1");
            doc.extend("}".repeat(10_000).into_bytes());
            bytes(doc)
        },
    });
    assert!(c.handshake().is_err());
}

#[test]
fn what_is_not_json_is_not_taken_for_it() {
    struct Fixed(&'static str, &'static [u8]);
    impl Transport for Fixed {
        fn send(&self, _request: &Request, _timeout: Duration) -> Result<Response> {
            let mut headers = Headers::new();
            headers.set("Content-Type", self.0);
            Ok(Response {
                status: 200,
                headers,
                spki: None,
                body: bytes(self.1.to_vec()),
            })
        }
    }
    for (content_type, body) in [
        ("text/html", &b"<html></html>"[..]),
        ("application/json", &b"not json"[..]),
        ("application/json", &b"\xff\xfe\x00"[..]),
        ("application/json", &b"{\"lantern\": 1e999}"[..]),
        ("application/json", &b""[..]),
    ] {
        let mut options = ClientOptions::new(Arc::new(Zero));
        options.clock = Arc::new(|| 1_793_345_400.0);
        let mut c = Client::new(URL, Fixed(content_type, body), options).unwrap();
        assert!(c.handshake().is_err(), "{content_type} {body:?}");
    }
}

#[test]
fn a_listing_that_never_stops_is_given_up_on() {
    // Every page names a new cursor; the client does not follow for ever.
    struct Pages;
    impl Transport for Pages {
        fn send(&self, request: &Request, _timeout: Duration) -> Result<Response> {
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json");
            let body = if request.url.ends_with("/.well-known/lantern") {
                serde_json::json!({"schema": 1, "lantern": "0.11", "base": "/api/lantern",
                    "name": "Hostile", "uid": "hostile", "features": []})
            } else {
                let cursor = sha256_hex(request.url.as_bytes());
                serde_json::json!({"schema": 1, "items": [], "next": cursor})
            };
            Ok(Response {
                status: 200,
                headers,
                spki: None,
                body: bytes(body.to_string().into_bytes()),
            })
        }
    }
    let mut options = ClientOptions::new(Arc::new(Zero));
    options.clock = Arc::new(|| 1_793_345_400.0);
    let mut c = Client::new(URL, Pages, options).unwrap();
    assert!(c.all_apps(&AppsOptions::default()).is_err());
}

#[test]
fn a_download_that_never_ends_is_refused_at_its_size() {
    let mut c = client(Hostile {
        content_type: "application/octet-stream",
        status: 200,
        body: |r| {
            if r.url.ends_with("/.well-known/lantern") {
                bytes(b"{}".to_vec())
            } else {
                Box::new(Endless(0))
            }
        },
    });
    let mut sink = MemorySink::new();
    let sum = sha256_hex(b"");
    let err = c
        .download(
            "/files/x",
            &mut sink,
            Expected {
                sha256: &sum,
                size: 1024,
            },
            true,
        )
        .unwrap_err();
    assert!(matches!(err, Error::Integrity(_)), "{err:?}");
    assert!(!sink.committed());
    assert!(sink.bytes().len() <= 1024 + 64 * 1024);
}

#[test]
fn a_server_that_answers_everything_with_an_error_gives_an_error() {
    for status in [301, 400, 401, 403, 404, 429, 500, 503] {
        let mut c = client(Hostile {
            content_type: "application/problem+json",
            status,
            body: |_| bytes(vec![b'{'; 100]),
        });
        assert!(c.handshake().is_err(), "{status}");
    }
}
