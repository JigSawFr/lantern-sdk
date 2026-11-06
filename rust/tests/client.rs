//! The client against a scripted server: the handshake, signed requests (and
//! the clock mended after a refusal), pairing, lists, and downloads.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lantern_protocol::client::{
    AppsOptions, Client, ClientOptions, Entropy, HomebrewOptions, MissingOptions,
};
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

fn library_server() -> Fake {
    Fake::new(|r, _| {
        let path = r.url.strip_prefix(URL).unwrap_or(&r.url);
        let route = path.split('?').next().unwrap_or(path);
        match route {
            "/.well-known/lantern" => json_reply(200, &example("handshake")),
            "/api/lantern/v1/changes" => json_reply(200, &example("changes")),
            "/api/lantern/v1/sections" => json_reply(200, &example("sections")),
            "/api/lantern/v1/titles" => json_reply(200, &example("titles")),
            "/api/lantern/v1/titles/changes" => json_reply(200, &example("title-changes")),
            p if p.starts_with("/api/lantern/v1/titles/") => json_reply(200, &example("title")),
            _ => reply(404, "application/problem+json", b"{}", &[]),
        }
    })
}

#[test]
fn changes_sections_and_titles_are_read() {
    let fake = library_server();
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    let changes = client.changes(Some("t1"), Some("switch")).unwrap();
    assert!(!changes.since.is_empty());
    assert!(!client.sections().unwrap().sections.is_empty());
    let one = client.title("0100ABCD00010000", None).unwrap();
    assert!(!one.name.is_empty());
    let many = client
        .titles(&["0100ABCD00010000", "x"], Some("switch"))
        .unwrap();
    assert!(!many.titles.is_empty());
    let moved = client.title_changes(None, None).unwrap();
    assert!(!moved.since.is_empty());
    let urls: Vec<String> = fake.requests().into_iter().map(|r| r.url).collect();
    assert!(urls.contains(&format!(
        "{URL}/api/lantern/v1/changes?platform=switch&since=t1"
    )));
    assert!(urls.iter().any(|u| u.ends_with("/titles/0100ABCD00010000")));
    assert!(urls.iter().any(
        |u| u.contains("/titles?platform=switch&ids=0100ABCD00010000%2Cx")
            || u.contains("/titles?platform=switch&ids=0100ABCD00010000,x")
    ));
}

#[test]
fn the_ids_of_titles_are_checked_before_anything_is_sent() {
    let fake = library_server();
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    assert!(client.titles(&[], None).is_err());
    let many: Vec<String> = (0..101).map(|n| n.to_string()).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    assert!(client.titles(&refs, None).is_err());
    assert!(client.titles(&["a,b"], None).is_err());
    assert!(client.title("", None).is_err());
    assert!(client.title("a\nb", None).is_err());
    assert!(fake.requests().is_empty());
}

#[test]
fn a_title_with_a_newer_schema_is_absent() {
    let mut newer = example("title");
    newer["schema"] = json!(99);
    let fake = Fake::new(move |r, _| {
        if r.url.ends_with("/.well-known/lantern") {
            return serve(r).unwrap();
        }
        json_reply(200, &newer)
    });
    let mut client = Client::new(URL, fake, options(0.0)).unwrap();
    let err = client.title("0100ABCD00010000", None).unwrap_err();
    assert!(matches!(err, Error::NewerSchema { .. }), "{err:?}");
}

#[test]
fn homebrew_is_listed_read_and_updated() {
    let fake = Fake::new(|r, _| {
        if r.url.contains("/homebrew/updates") {
            return json_reply(200, &example("homebrew-page"));
        }
        if r.url.contains("/homebrew?") || r.url.ends_with("/homebrew") {
            return json_reply(200, &example("homebrew-page"));
        }
        if r.url.contains("/homebrew/") {
            return json_reply(200, &example("homebrew"));
        }
        serve(r).unwrap()
    });
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    let o = HomebrewOptions {
        kind: Some("tool".to_owned()),
        q: Some("frost".to_owned()),
        ..HomebrewOptions::default()
    };
    assert!(!client.homebrew_list(&o).unwrap().items.is_empty());
    let entry = client.homebrew("org.example.frostline", None).unwrap();
    assert_eq!(entry.id, "org.example.frostline");
    let page = client
        .homebrew_updates(&[("org.example.frostline".to_owned(), 10300)], &o)
        .unwrap();
    assert!(!page.items.is_empty());
    let sent = fake.requests();
    let post = sent.iter().find(|r| r.method == "POST").unwrap();
    let body: Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["installed"][0]["build"], 10300);
    assert!(
        sent.iter()
            .any(|r| r.url.contains("kind=tool") && r.url.contains("q=frost"))
    );
}

#[test]
fn a_kind_that_is_not_a_word_is_refused_before_it_is_sent() {
    let fake = Fake::new(|r, _| serve(r).unwrap());
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    for bad in ["", "Tool", "1tool", "a-b", &"x".repeat(33)] {
        let o = HomebrewOptions {
            kind: Some(bad.to_owned()),
            ..HomebrewOptions::default()
        };
        assert!(client.homebrew_list(&o).is_err(), "{bad}");
    }
    assert!(
        client
            .homebrew_updates(&[], &HomebrewOptions::default())
            .is_err()
    );
    assert!(fake.requests().is_empty());
}

#[test]
fn cheats_are_listed_read_checked_and_written() {
    let text: &'static [u8] = b"[Endless lamp oil]\n04000000 0123A4B0 00000063\n";
    let set = json!({"id": "cs_1", "platform": "switch", "title_id": "0100ABCD00010000",
        "build_id": "4A1B2C3D4E5F6071", "size": text.len(), "sha256": sha256_hex(text)});
    let listing = json!({"schema": 1, "cheats": [set.clone()]});
    let created = {
        let mut c = set.clone();
        c["schema"] = json!(1);
        c
    };
    let fake = Fake::new(move |r, _| match (r.method.as_str(), r.url.as_str()) {
        ("GET", u) if u.contains("/cheats/cs_1") => reply(200, "text/plain", text, &[]),
        ("GET", u) if u.contains("/cheats") => json_reply(200, &listing),
        ("POST", u) if u.ends_with("/cheats") => json_reply(201, &created),
        ("PUT" | "DELETE", _) => reply(204, "text/plain", b"", &[]),
        _ => serve(r).unwrap(),
    });
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client.set_token(Some("et_example"), None).unwrap();
    let sets = client
        .cheat_sets("0100ABCD00010000", Some("4A1B2C3D4E5F6071"), None)
        .unwrap();
    assert_eq!(sets.cheats.len(), 1);
    assert_eq!(client.cheat_text(&sets.cheats[0]).unwrap(), text);
    let mut write = example_write();
    assert_eq!(client.cheat_add(&write).unwrap().id, "cs_1");
    client.cheat_replace("cs_1", &write).unwrap();
    client.cheat_delete("cs_1").unwrap();
    // Over a limit: nothing is sent.
    let before = fake.requests().len();
    write.text = "x".repeat((1 << 20) + 1);
    assert!(client.cheat_add(&write).is_err());
    write.text.clear();
    write.note = Some("n".repeat(121));
    assert!(client.cheat_replace("cs_1", &write).is_err());
    assert_eq!(fake.requests().len(), before);
    // A text that is not what the set says is refused.
    let mut wrong = sets.cheats[0].clone();
    wrong.sha256 = "0".repeat(64);
    assert!(matches!(
        client.cheat_text(&wrong).unwrap_err(),
        Error::Integrity(_)
    ));
}

fn example_write() -> lantern_protocol::generated::models::CheatWrite {
    serde_json::from_value(example("cheat-write")).unwrap()
}

#[test]
fn requests_are_listed_made_and_withdrawn() {
    let fake = Fake::new(|r, _| match r.method.as_str() {
        "GET" if r.url.contains("/requests") => json_reply(200, &example("requests")),
        "POST" => json_reply(201, &example("request")),
        "DELETE" => reply(204, "text/plain", b"", &[]),
        _ => serve(r).unwrap(),
    });
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client.set_token(Some("et_example"), None).unwrap();
    assert_eq!(client.requests(None).unwrap().requests.len(), 2);
    let made = client.request_title("0100EFEF00020000", None).unwrap();
    assert_eq!(made.id, "r_12");
    client.request_withdraw("r_12").unwrap();
    assert!(client.request_title("", None).is_err());
    let post = fake
        .requests()
        .into_iter()
        .find(|r| r.method == "POST")
        .unwrap();
    let body: Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["title_id"], "0100EFEF00020000");
}

fn save_meta() -> lantern_protocol::client::SaveMeta {
    lantern_protocol::client::SaveMeta {
        kind: Some("account".to_owned()),
        game_version_code: Some(196_608),
        profile: Some("Léa".to_owned()),
        note: Some("Chapter 4".to_owned()),
        ..Default::default()
    }
}

#[test]
fn a_save_goes_in_one_request_with_its_digest() {
    let fake = Fake::new(|r, _| match r.method.as_str() {
        "POST" => json_reply(201, &example("save")),
        _ => serve(r).unwrap(),
    });
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client.set_token(Some("et_example"), None).unwrap();
    let zip = b"PK\x03\x04 pretend archive";
    let saved = client
        .save_upload("0100ABCD00010000", zip, &save_meta(), None)
        .unwrap();
    assert_eq!(saved.save_id, "s_03");
    let sent = fake.requests().pop().unwrap();
    assert_eq!(sent.headers.get("Content-Type"), Some("application/zip"));
    assert_eq!(
        sent.headers.get("Content-Digest").unwrap(),
        lantern_protocol::digest::content_digest(zip)
    );
    assert_eq!(sent.headers.get("Lantern-Profile"), Some("L%C3%A9a"));
    assert_eq!(sent.headers.get("Lantern-Game-Version"), Some("196608"));
    assert_eq!(sent.body, zip);
    // A kind the specification does not know, and a missing platform.
    let mut bad = save_meta();
    bad.kind = Some("weird".to_owned());
    assert!(
        client
            .save_upload("0100ABCD00010000", zip, &bad, None)
            .is_err()
    );
    let mut bare = options(0.0);
    bare.platform = None;
    let mut client = Client::new(URL, Fake::new(|r, _| serve(r).unwrap()), bare).unwrap();
    assert!(
        client
            .save_upload("0100ABCD00010000", zip, &save_meta(), None)
            .is_err()
    );
}

#[test]
fn a_cut_upload_is_resumed_where_the_server_stands() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let held = Arc::new(AtomicU64::new(0));
    let cut = Arc::new(AtomicU64::new(0));
    let archive: Vec<u8> = (0..2500u32).map(|n| (n % 251) as u8).collect();
    let total = archive.len() as u64;
    let (h, c) = (held.clone(), cut.clone());
    let fake = Fake::new(move |r, _| {
        let upload = format!("{URL}/api/lantern/v1/uploads/u_1");
        match (r.method.as_str(), r.url.as_str()) {
            ("POST", u) if u.contains("/uploads") && !u.contains("/uploads/") => {
                let mut doc = example("upload");
                doc["upload"] = json!(upload);
                doc["chunk_size"] = json!(1000);
                doc["offset"] = json!(0);
                json_reply(201, &doc)
            }
            ("PATCH", _) => {
                let offset: u64 = r.headers.get("Upload-Offset").unwrap().parse().unwrap();
                if offset != h.load(Ordering::SeqCst) {
                    return reply(
                        409,
                        "application/problem+json",
                        br#"{"schema":1,"status":409,"code":"conflict"}"#,
                        &[],
                    );
                }
                // The second chunk is lost on its way, after the server took it.
                if offset == 1000 && c.fetch_add(1, Ordering::SeqCst) == 0 {
                    h.store(2000, Ordering::SeqCst);
                    return Err(Error::Transport("connection reset".to_owned()));
                }
                let now = offset + r.body.len() as u64;
                h.store(now, Ordering::SeqCst);
                if now == total {
                    return json_reply(201, &example("save"));
                }
                reply(
                    204,
                    "text/plain",
                    b"",
                    &[("Upload-Offset", &now.to_string())],
                )
            }
            ("HEAD", _) => reply(
                204,
                "text/plain",
                b"",
                &[
                    ("Upload-Offset", &h.load(Ordering::SeqCst).to_string()),
                    ("Upload-Length", &total.to_string()),
                    ("Lantern-Chunk-Size", "1000"),
                ],
            ),
            _ => serve(r).unwrap(),
        }
    });
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client.set_token(Some("et_example"), None).unwrap();
    let saved = client
        .save_upload_resumable("0100ABCD00010000", &archive, &save_meta(), None, 3)
        .unwrap();
    assert_eq!(saved.save_id, "s_03");
    let patches: Vec<String> = fake
        .requests()
        .into_iter()
        .filter(|r| r.method == "PATCH")
        .map(|r| r.headers.get("Upload-Offset").unwrap().to_owned())
        .collect();
    assert_eq!(patches, ["0", "1000", "2000"]);
    // An upload address on another host is refused.
    let mut elsewhere = example("upload");
    elsewhere["upload"] = json!("https://evil.example.net/u");
    let other = Fake::new(move |r, _| {
        if r.method == "POST" {
            return json_reply(201, &elsewhere);
        }
        serve(r).unwrap()
    });
    let mut client = Client::new(URL, other, options(0.0)).unwrap();
    assert!(
        client
            .upload_start("0100ABCD00010000", &archive, &save_meta(), None)
            .is_err()
    );
}

#[test]
fn saves_are_listed_downloaded_and_deleted() {
    let body: &'static [u8] = b"PK archive bytes";
    let mut save = example("save");
    save["size"] = json!(body.len());
    save["sha256"] = json!(sha256_hex(body));
    let listing = json!({"schema": 1, "saves": [save]});
    let fake = Fake::new(move |r, _| match r.method.as_str() {
        "DELETE" => reply(204, "text/plain", b"", &[]),
        "GET" if r.url.contains("/saves/0100") => reply(200, "application/zip", body, &[]),
        "GET" if r.url.contains("/saves") => json_reply(200, &listing),
        _ => serve(r).unwrap(),
    });
    let mut client = Client::new(URL, fake.clone(), options(0.0)).unwrap();
    client.set_token(Some("et_example"), None).unwrap();
    let saves = client.saves(Some("0100ABCD00010000"), None).unwrap();
    assert_eq!(saves.saves.len(), 1);
    let mut sink = MemorySink::new();
    client
        .save_download(&saves.saves[0], &mut sink, true)
        .unwrap();
    assert_eq!(sink.bytes(), body);
    assert!(sink.committed());
    client
        .save_delete("0100ABCD00010000", "s_03", None)
        .unwrap();
    assert!(client.save_delete("a/b\n", "s_03", None).is_err());
}
