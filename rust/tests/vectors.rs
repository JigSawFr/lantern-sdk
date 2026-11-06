//! The specification's test vectors (`spec/vectors/`), the same ones the other
//! languages read.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use lantern_protocol::bytes::{from_base64, from_hex, to_base64, to_hex};
use lantern_protocol::canonical::canonical_json;
use lantern_protocol::digest::{content_digest, digest_sha256, format_digest, sha256_hex};
use lantern_protocol::spki::{short, spki_sha256_pem};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = format!("{}/../spec/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

#[test]
fn canonical_json_vectors() {
    let file = vectors("canonical-json");
    for case in file["cases"].as_array().unwrap() {
        let value: Value = serde_json::from_str(text(case, "json")).unwrap();
        let canonical = canonical_json(&value).unwrap();
        assert_eq!(canonical, text(case, "canonical"), "{}", text(case, "name"));
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            text(case, "sha256"),
            "{}",
            text(case, "name")
        );
    }
}

#[test]
fn spki_vectors() {
    let file = vectors("spki");
    for cert in file["certificates"].as_array().unwrap() {
        let fingerprint = spki_sha256_pem(text(cert, "pem")).unwrap();
        assert_eq!(
            fingerprint,
            text(cert, "spki_sha256"),
            "{}",
            text(cert, "name")
        );
        assert_eq!(
            short(&fingerprint).unwrap(),
            text(cert, "short"),
            "{}",
            text(cert, "name")
        );
    }
}

#[test]
fn spki_refuses_what_is_not_a_certificate() {
    assert!(spki_sha256_pem("nothing").is_err());
    assert!(lantern_protocol::spki::spki_sha256(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(lantern_protocol::spki::spki_sha256(&[]).is_err());
}

#[test]
fn digest_round_trip() {
    let body = b"hello";
    let field = content_digest(body);
    assert_eq!(digest_sha256(Some(&field)).unwrap(), sha256_hex(body));
    assert_eq!(format_digest(&sha256_hex(body)).unwrap(), field);
    assert_eq!(digest_sha256(None), None);
    assert_eq!(digest_sha256(Some("sha-256=:AAAA:")), None);
    assert_eq!(digest_sha256(Some("md5=:AAAA:")), None);
    assert!(format_digest("zz").is_none());
}

#[test]
fn bytes_forms() {
    for sample in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        assert_eq!(from_base64(&to_base64(sample)).unwrap(), sample);
        assert_eq!(from_hex(&to_hex(sample)).unwrap(), sample);
    }
    assert_eq!(to_base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(to_base64(b"fo"), "Zm8=");
    assert!(from_base64("Zm8").is_none());
    assert!(from_base64("Zm=8").is_none());
    assert!(from_base64("Zg==Zg==").is_none());
    assert!(from_hex("abc").is_none());
    assert!(from_hex("zz").is_none());
}
