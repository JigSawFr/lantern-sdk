//! The header values and the encodings read from outside.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = lantern_protocol::digest::parse_digest(data);
    let _ = lantern_protocol::digest::digest_sha256(Some(data));
    let _ = lantern_protocol::bytes::from_base64(data);
    let _ = lantern_protocol::bytes::from_hex(data);
    let _ = lantern_protocol::spki::pem_to_der(data);
    let _ = lantern_protocol::spki::short(data);
    let _ = lantern_protocol::profiles::switch_version_code(data);
    let _ = lantern_protocol::profiles::app_ver_code(data);
    let _ = lantern_protocol::profiles::switch_ids(data);
    let _ = lantern_protocol::uid::is_uuid(data);
    let _ = lantern_protocol::limits::printable(data, 64);
});
