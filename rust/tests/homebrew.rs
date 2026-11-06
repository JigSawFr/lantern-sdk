//! Homebrew (SPEC.md § 8): the paths, manifests and signatures of the
//! specification's vectors, and the pinned key.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use lantern_protocol::generated::models::{Homebrew, ManifestEntry, Package, Signature};
use lantern_protocol::homebrew::{
    PinCheck, check_manifest, check_package, check_path, check_pin, manifest_canonical,
    manifest_digest, packages_for, signature_ok, signed_bytes,
};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = format!("{}/../spec/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn manifest(value: &Value) -> Vec<ManifestEntry> {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn the_paths_of_the_vectors() {
    let file = vectors("paths");
    for case in file["paths"].as_array().unwrap() {
        let path = case["path"].as_str().unwrap();
        let accepted = case["accepted"].as_bool().unwrap();
        assert_eq!(
            check_path(path).is_ok(),
            accepted,
            "{} ({})",
            case["why"],
            path.len()
        );
    }
    for case in file["manifests"].as_array().unwrap() {
        let accepted = case["accepted"].as_bool().unwrap();
        assert_eq!(
            check_manifest(&manifest(&case["manifest"])).is_ok(),
            accepted,
            "{}",
            case["why"]
        );
    }
}

#[test]
fn paths_the_same_when_case_and_form_are_ignored_are_one() {
    let entry = |path: &str| {
        let mut e = ManifestEntry::default();
        path.clone_into(&mut e.path);
        e.size = 1;
        e.sha256 = "1".repeat(64);
        e
    };
    // É and é; e + combining acute and é; ß and ss.
    for (a, b) in [
        ("/switch/x/\u{c9}.txt", "/switch/x/\u{e9}.txt"),
        ("/switch/x/e\u{301}.txt", "/switch/x/\u{e9}.txt"),
        ("/switch/x/stra\u{df}e", "/switch/x/STRASSE"),
    ] {
        assert!(check_manifest(&[entry(a), entry(b)]).is_err(), "{a} {b}");
    }
    assert!(check_manifest(&[entry("/a/b"), entry("/a/c")]).is_ok());
}

#[test]
fn a_manifest_has_the_digest_of_the_vectors() {
    for case in vectors("homebrew-signatures")["manifests"]
        .as_array()
        .unwrap()
    {
        let m = manifest(&case["manifest"]);
        assert_eq!(manifest_canonical(&m), case["canonical"].as_str().unwrap());
        assert_eq!(
            manifest_digest(&m),
            case["manifest_sha256"].as_str().unwrap()
        );
    }
}

fn entry_of(case: &Value) -> (Homebrew, Package, Signature) {
    let e = &case["entry"];
    let mut entry = Homebrew::default();
    e["id"].as_str().unwrap().clone_into(&mut entry.id);
    e["platform"]
        .as_str()
        .unwrap()
        .clone_into(&mut entry.platform);
    entry.build = e["build"].as_i64().unwrap();
    let mut package = Package::default();
    e["package"]["sha256"]
        .as_str()
        .unwrap()
        .clone_into(&mut package.sha256);
    e["package"]["manifest_sha256"]
        .as_str()
        .unwrap()
        .clone_into(&mut package.manifest_sha256);
    let signature: Signature = serde_json::from_value(case["signature"].clone()).unwrap();
    (entry, package, signature)
}

#[test]
fn the_signatures_of_the_vectors() {
    for case in vectors("homebrew-signatures")["signed"].as_array().unwrap() {
        let (entry, package, signature) = entry_of(case);
        assert_eq!(
            signed_bytes(&entry, &package),
            case["signed_bytes"].as_str().unwrap()
        );
        assert_eq!(
            signature_ok(&entry, &package, &signature),
            case["verifies"].as_bool().unwrap()
        );
    }
}

#[test]
fn a_package_is_checked_against_its_manifest_and_its_signature() {
    let file = vectors("homebrew-signatures");
    let case = &file["signed"][0];
    let (mut entry, mut package, signature) = entry_of(case);
    package.manifest = Some(manifest(&file["manifests"][0]["manifest"]));
    package.signature = Some(signature);
    assert!(check_package(&entry, &package).is_ok());
    // A manifest that is not the one the digest names.
    let mut wrong = package.clone();
    wrong.manifest.as_mut().unwrap()[0].size += 1;
    assert!(check_package(&entry, &wrong).is_err());
    // Another build: the signature no longer covers it.
    entry.build += 1;
    assert!(check_package(&entry, &package).is_err());
}

#[test]
fn only_the_packages_for_this_architecture_are_taken() {
    let mut entry = Homebrew::default();
    entry.package.arch = Some(vec!["aarch64".to_owned()]);
    let mut other = Package::default();
    other.arch = Some(vec!["x86_64".to_owned(), "future_arch".to_owned()]);
    let any = Package::default();
    entry.packages = Some(vec![other, any]);
    assert_eq!(packages_for(&entry, "aarch64").len(), 2);
    assert_eq!(packages_for(&entry, "x86_64").len(), 2);
    assert_eq!(packages_for(&entry, "riscv64").len(), 1);
}

#[test]
fn a_key_is_pinned_at_the_first_install_and_a_change_is_shown() {
    let key = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
    let other = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    assert_eq!(check_pin(None, Some(key)), PinCheck::First);
    assert_eq!(check_pin(Some(Some(key)), Some(key)), PinCheck::Same);
    assert_eq!(check_pin(Some(None), None), PinCheck::Same);
    let PinCheck::Changed { pinned, offered } = check_pin(Some(Some(key)), Some(other)) else {
        panic!("a new key is a change");
    };
    assert!(pinned.is_some() && offered.is_some() && pinned != offered);
    // Unsigned after a signed one, and signed after an unsigned one.
    assert!(matches!(
        check_pin(Some(Some(key)), None),
        PinCheck::Changed { offered: None, .. }
    ));
    assert!(matches!(
        check_pin(Some(None), Some(key)),
        PinCheck::Changed { pinned: None, .. }
    ));
}
