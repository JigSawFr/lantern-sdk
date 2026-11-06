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

fn code(platform: &str, version: &Value) -> Result<u64, lantern_protocol::Error> {
    use lantern_protocol::profiles::{app_ver_code, n3ds_version_name, switch_version_code};
    let as_text = || {
        version
            .as_str()
            .map_or_else(|| version.to_string(), str::to_owned)
    };
    match platform {
        "switch" => switch_version_code(&as_text()).map(u64::from),
        "vita" | "ps4" => app_ver_code(&as_text()).map(u64::from),
        "3ds" => {
            let n = u32::try_from(version.as_u64().unwrap_or(u64::MAX)).unwrap_or(u32::MAX);
            n3ds_version_name(n).map(|_| u64::from(n))
        }
        _ => version
            .as_u64()
            .ok_or_else(|| lantern_protocol::Error::document("not a version")),
    }
}

#[test]
fn version_code_vectors() {
    let file = vectors("version-codes");
    for case in file["cases"].as_array().unwrap() {
        let platform = text(case, "platform");
        let expected = case["version_code"].as_u64().unwrap();
        assert_eq!(
            code(platform, &case["version"]).unwrap(),
            expected,
            "{platform} {}",
            case["version"]
        );
        if platform == "3ds" {
            let name =
                lantern_protocol::profiles::n3ds_version_name(u32::try_from(expected).unwrap())
                    .unwrap();
            assert_eq!(Some(name.as_str()), case["version_name"].as_str());
        }
    }
    for case in file["refused"].as_array().unwrap() {
        assert!(
            code(text(case, "platform"), &case["version"]).is_err(),
            "{}",
            text(case, "why")
        );
    }
}

#[test]
fn app_install_vectors() {
    // The vectors give an app's decisive fields only: the others are filled in.
    fn app_of(mut value: Value) -> lantern_protocol::generated::models::App {
        value["sha256"] = Value::from("0".repeat(64));
        value["file"] = Value::from("file");
        serde_json::from_value(value).unwrap()
    }
    use lantern_protocol::generated::models::App;
    use lantern_protocol::variants::{InstallDecision, install_decision, prefer_variant};
    let file = vectors("app-requires");
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    };
    for case in file["install"].as_array().unwrap() {
        let app = app_of(case["app"].clone());
        let installed: Vec<App> = case["installed"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(app_of)
            .collect();
        let (formats, satisfies) = (strings(&case["formats"]), strings(&case["satisfies"]));
        let formats: Vec<&str> = formats.iter().map(String::as_str).collect();
        let satisfies: Vec<&str> = satisfies.iter().map(String::as_str).collect();
        let name = text(case, "name");
        match install_decision(&app, &formats, &satisfies, &installed) {
            InstallDecision::Install => {
                assert_eq!(text(case, "decision"), "install", "{name}");
                assert_eq!(case["reasons"].as_u64(), Some(0), "{name}");
            }
            InstallDecision::Unavailable(reasons) => {
                assert_eq!(text(case, "decision"), "unavailable", "{name}");
                assert_eq!(
                    case["reasons"].as_u64(),
                    Some(reasons.len() as u64),
                    "{name}"
                );
            }
        }
    }
    let variants: Vec<App> = file["variants"]["apps"]
        .as_array()
        .unwrap()
        .iter()
        .cloned()
        .map(app_of)
        .collect();
    assert_eq!(
        prefer_variant(&variants).unwrap().id,
        text(&file["variants"], "preferred")
    );
    assert!(prefer_variant(&[]).is_none());
}
