//! Any bytes read as a document: never a panic, and what is read is written
//! back in canonical JSON that reads again to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = lantern_protocol::limits::load_json(data, 1 << 20, "fuzz") {
        if let Ok(canonical) = lantern_protocol::canonical::canonical_json(&value) {
            let again: serde_json::Value =
                serde_json::from_str(&canonical).expect("canonical JSON is JSON");
            assert_eq!(
                lantern_protocol::canonical::canonical_json(&again).expect("and again canonical"),
                canonical
            );
        }
        for name in ["apps", "titles", "handshake", "homebrew", "problem"] {
            let _ = lantern_protocol::generated::models::round_trip(name, value.clone());
        }
    }
});
