//! Every example of the specification reads into its struct and writes back
//! unchanged: nothing is lost, the fields this version does not know included
//! (SPEC.md § 3.2).

use std::fs;
use std::path::Path;

use lantern_protocol::generated::round_trip;
use serde_json::{Value, json};

#[test]
fn every_example_of_the_specification_round_trips() {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/examples/v1");
    let mut seen = 0;
    for entry in
        fs::read_dir(&folder).expect("the specification's examples (git submodule update --init)")
    {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            continue; // `invalid/`: documents that must be refused, not read
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a name")
            .to_owned();
        let value: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("a file")).expect("JSON");
        let back = round_trip(&name, value.clone())
            .unwrap_or_else(|| panic!("{name} is not a document"))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back, value, "{name} changed on the way");
        seen += 1;
    }
    assert!(seen >= 40, "only {seen} examples");
}

#[test]
fn a_field_this_version_does_not_know_is_kept() {
    let page = json!({"schema": 1, "items": [], "next": null, "from_the_future": {"a": [1, 2]}});
    let back = round_trip("apps", page.clone())
        .expect("a document")
        .expect("reads");
    assert_eq!(back, page);
}

#[test]
fn a_null_stays_null_and_an_absence_stays_absent() {
    let with = json!({"schema": 1, "titles": [], "unknown": [], "next": null});
    let without = json!({"schema": 1, "titles": [], "unknown": []});
    for page in [with, without] {
        let back = round_trip("titles", page.clone())
            .expect("a document")
            .expect("reads");
        assert_eq!(back, page);
    }
}
