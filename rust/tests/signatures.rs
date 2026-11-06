//! Signed requests against `vectors/signatures.json` and
//! `vectors/ed25519-refused.json`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

use lantern_protocol::bytes::{from_base64, from_hex};
use lantern_protocol::signatures::{
    DeviceKey, NonceCache, RequestHeaders, VerifyOptions, accept_signature, ed25519_verify,
    parse_accept_signature, received_uri, target_uri, verify_request,
};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = format!("{}/../spec/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn key(file: &Value) -> DeviceKey {
    let seed: [u8; 32] = from_hex(file["key"]["seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    DeviceKey::from_seed(seed)
}

fn header<'a>(request: &'a Value, name: &str) -> Option<&'a str> {
    request["headers"][name].as_str()
}

fn check(request: &Value, key: &DeviceKey, cache: &mut NonceCache, now: f64) -> Result<(), String> {
    let headers = RequestHeaders {
        authorization: header(request, "Authorization"),
        content_digest: header(request, "Content-Digest"),
        signature_input: header(request, "Signature-Input"),
        signature: header(request, "Signature"),
    };
    let uri = target_uri(request["uri"].as_str().unwrap()).unwrap();
    verify_request(
        request["method"].as_str().unwrap(),
        &uri,
        &headers,
        key.public_key(),
        VerifyOptions {
            with_token: headers.authorization.is_some(),
            with_body: !request["body"].as_str().unwrap().is_empty(),
            nonces: cache,
            skew: 300,
            now,
        },
    )
    .map(|_| ())
    .map_err(|r| r.code.to_owned())
}

#[test]
fn the_key_of_the_vectors() {
    let file = vectors("signatures");
    let key = key(&file);
    assert_eq!(
        key.public_key_base64(),
        file["key"]["public_key"].as_str().unwrap()
    );
    assert_eq!(key.keyid(), file["key"]["keyid"].as_str().unwrap());
    assert_eq!(
        key.fingerprint(),
        file["key"]["short_fingerprint"].as_str().unwrap()
    );
}

#[test]
fn signed_requests_match_the_vectors() {
    let file = vectors("signatures");
    let key = key(&file);
    let created = file["server_time"].as_u64().unwrap();
    for case in file["accepted"].as_array().unwrap() {
        let input = header(case, "Signature-Input").unwrap();
        let nonce = input
            .split("nonce=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap();
        let signed = key
            .sign_request(
                case["method"].as_str().unwrap(),
                case["uri"].as_str().unwrap(),
                header(case, "Authorization"),
                case["body"].as_str().unwrap().as_bytes(),
                created,
                nonce,
            )
            .unwrap();
        let name = case["name"].as_str().unwrap();
        assert_eq!(signed.signature_input, input, "{name}");
        assert_eq!(
            signed.signature,
            header(case, "Signature").unwrap(),
            "{name}"
        );
        assert_eq!(
            signed.content_digest.as_deref(),
            header(case, "Content-Digest"),
            "{name}"
        );
    }
}

#[test]
fn a_server_takes_the_accepted_and_refuses_the_rest() {
    let file = vectors("signatures");
    let key = key(&file);
    let now = file["server_time"].as_f64().unwrap();
    let mut cache = NonceCache::default();
    for case in file["accepted"].as_array().unwrap() {
        check(case, &key, &mut cache, now).unwrap_or_else(|c| panic!("{}: {c}", case["name"]));
    }
    for case in file["refused"].as_array().unwrap() {
        let mut fresh = NonceCache::default();
        if let Some(after) = case.get("after") {
            for name in after.as_array().unwrap() {
                let earlier = file["accepted"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|a| a["name"] == *name)
                    .unwrap();
                check(earlier, &key, &mut fresh, now).unwrap();
            }
        }
        // "created 301 s before": the server's clock is the one of the file
        let got = check(&case["request"], &key, &mut fresh, now).unwrap_err();
        assert_eq!(got, case["code"].as_str().unwrap(), "{}", case["name"]);
    }
}

#[test]
fn small_order_and_malleable_signatures_are_refused() {
    let file = vectors("ed25519-refused");
    for case in file["cases"].as_array().unwrap() {
        let public = from_hex(case["public_key"].as_str().unwrap()).unwrap();
        let signature = from_hex(case["signature"].as_str().unwrap()).unwrap();
        let message = case["message"].as_str().unwrap().as_bytes();
        assert_eq!(
            ed25519_verify(&public, message, &signature),
            case["verifies"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    let small: Vec<Vec<u8>> = file["small_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| from_hex(s.as_str().unwrap()).unwrap())
        .collect();
    for a in &small {
        for r in &small {
            let mut signature = r.clone();
            signature.extend([0u8; 32]);
            for m in file["messages"].as_array().unwrap() {
                assert!(!ed25519_verify(
                    a,
                    m.as_str().unwrap().as_bytes(),
                    &signature
                ));
            }
        }
    }
}

#[test]
fn target_uris_and_accept_signature() {
    assert_eq!(
        target_uri("HTTPS://Shelf.Example.org:443/a/b?x=%2F&y=1#frag").unwrap(),
        "https://shelf.example.org/a/b?x=%2F&y=1"
    );
    assert_eq!(target_uri("http://h:8080").unwrap(), "http://h:8080/");
    assert!(target_uri("ftp://h/").is_err());
    assert!(target_uri("https://u@h/").is_err());
    assert_eq!(
        received_uri("https", "Shelf.example.org", "/x?y").unwrap(),
        "https://shelf.example.org/x?y"
    );
    let header = accept_signature(true, true, Some("abc"));
    let parsed = parse_accept_signature(Some(&header)).unwrap();
    assert_eq!(
        parsed.components,
        ["@method", "@target-uri", "authorization", "content-digest"]
    );
    assert_eq!(parsed.keyid.as_deref(), Some("abc"));
    assert_eq!(parsed.alg.as_deref(), Some("ed25519"));
    assert!(parse_accept_signature(Some("sig=()")).is_none());
    let _ = from_base64("AA==");
}
