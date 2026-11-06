//! The HTTP transport against local servers: a TLS one with a self-signed
//! key (pinned, mismatched, unpinned) and a plain one on loopback.
#![cfg(feature = "http")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lantern_protocol::client::{AppsOptions, Client, ClientOptions, Entropy};
use lantern_protocol::error::Error;
use lantern_protocol::http_transport::{HttpOptions, HttpTransport};
use lantern_protocol::spki::spki_sha256;
use lantern_protocol::transport::{Headers, Request, Transport};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn example(name: &str) -> String {
    let path = format!(
        "{}/../spec/examples/v1/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).unwrap()
}

fn answer(request: &str) -> Vec<u8> {
    let first = request.lines().next().unwrap_or("");
    let body = if first.contains("/.well-known/lantern") {
        example("handshake")
    } else {
        example("apps")
    };
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn read_request(stream: &mut impl Read) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        out.push(byte[0]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A TLS server with a fresh self-signed key: its port, its key's SPKI
/// fingerprint, and the number of requests it read.
fn tls_server() -> (u16, String, Arc<AtomicUsize>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der = certified.cert.der().to_vec();
    let spki = spki_sha256(&der).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der)], key)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            let Ok(mut connection) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            let counted = counted.clone();
            std::thread::spawn(move || {
                let mut tls = rustls::Stream::new(&mut connection, &mut tcp);
                let request = read_request(&mut tls);
                if request.is_empty() {
                    return;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = tls.write_all(&answer(&request));
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    (port, spki, requests)
}

fn get(transport: &HttpTransport, url: &str) -> Result<u16, Error> {
    let request = Request {
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: Headers::new(),
        body: Vec::new(),
    };
    transport
        .send(&request, Duration::from_secs(5))
        .map(|r| r.status)
}

#[test]
fn a_server_no_ca_vouches_for_gives_its_key_to_be_pinned() {
    let (port, spki, _) = tls_server();
    let url = format!("https://localhost:{port}/x");
    // Strict: a self-signed certificate is refused.
    let strict = HttpTransport::new(&HttpOptions::default()).unwrap();
    assert!(matches!(get(&strict, &url), Err(Error::Transport(_))));
    // Not verified: any key, and the one seen is reported.
    let open = HttpTransport::new(&HttpOptions {
        verify: false,
        ..HttpOptions::default()
    })
    .unwrap();
    let request = Request {
        method: "GET".to_owned(),
        url: url.clone(),
        headers: Headers::new(),
        body: Vec::new(),
    };
    let response = open.send(&request, Duration::from_secs(5)).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.spki.as_deref(), Some(spki.as_str()));
    // Pinned after pairing: the next connection must be over that key.
    open.pin_seen(&spki);
    assert_eq!(open.pin().as_deref(), Some(spki.as_str()));
    assert_eq!(get(&open, &url).unwrap(), 200);
}

#[test]
fn a_key_other_than_the_pinned_one_fails_before_anything_is_sent() {
    let (port, _spki, requests) = tls_server();
    let wrong = "ab".repeat(32);
    let pinned = HttpTransport::new(&HttpOptions {
        pin: Some(wrong.clone()),
        ..HttpOptions::default()
    })
    .unwrap();
    match get(&pinned, &format!("https://localhost:{port}/x")) {
        Err(Error::PinMismatch { seen, pinned }) => {
            assert_eq!(pinned, wrong);
            assert_eq!(seen.len(), 64);
        }
        other => panic!("{other:?}"),
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "the request reached the server"
    );
}

#[test]
fn a_pin_must_be_a_sha256() {
    let bad = HttpTransport::new(&HttpOptions {
        pin: Some("nope".to_owned()),
        ..HttpOptions::default()
    });
    assert!(matches!(bad, Err(Error::Document { .. })));
}

struct Counter;
impl Entropy for Counter {
    fn fill(&self, buffer: &mut [u8]) {
        buffer.fill(1);
    }
}

#[test]
fn the_client_reads_a_library_over_pinned_tls() {
    let (port, spki, _) = tls_server();
    let transport = HttpTransport::new(&HttpOptions {
        pin: Some(spki),
        ..HttpOptions::default()
    })
    .unwrap();
    let options = ClientOptions::new(Arc::new(Counter));
    let mut client = Client::new(&format!("https://localhost:{port}"), transport, options).unwrap();
    let hello = client.handshake().unwrap();
    assert_eq!(hello.base, "/api/lantern");
    assert!(
        !client
            .apps(&AppsOptions::default())
            .unwrap()
            .items
            .is_empty()
    );
}

#[test]
fn plain_http_on_loopback_and_no_redirect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            let request = read_request(&mut tcp);
            let reply = if request.contains("/moved") {
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                answer(&request)
            };
            let _ = tcp.write_all(&reply);
        }
    });
    let transport = HttpTransport::new(&HttpOptions::default()).unwrap();
    assert_eq!(
        get(&transport, &format!("http://127.0.0.1:{port}/x")).unwrap(),
        200
    );
    assert_eq!(
        get(&transport, &format!("http://127.0.0.1:{port}/moved")).unwrap(),
        302
    );
}
