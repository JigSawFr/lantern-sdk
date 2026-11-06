//! The platform profiles (SPEC.md Annex A).

#![allow(clippy::unwrap_used)]

use lantern_protocol::profiles::{
    SwitchKind, app_id_ok, cheat_path, profile, roots, single_file_path, switch_ids,
    switch_update_id, title_id_ok,
};
use lantern_protocol::uid::{is_uuid, uuid_v4, uuid_v7};
use lantern_protocol::variants::requires_of_name;
use lantern_protocol::vocabulary::{is_homebrew_id, is_platform};

#[test]
fn every_pattern_compiles() {
    for platform in ["switch", "3ds", "vita", "ps4", "android", "linux"] {
        assert!(profile(platform).is_some(), "{platform}");
    }
    assert!(profile("ios").is_none());
    assert!(is_platform("switch") && !is_platform("Switch"));
    assert!(
        is_homebrew_id("org.example.frostline")
            && !is_homebrew_id("frostline")
            && !is_homebrew_id("Org.example")
    );
}

#[test]
fn switch_ids_split_into_title_and_kind() {
    assert_eq!(
        switch_ids("0100ABCD00010000").unwrap(),
        ("0100ABCD00010000".to_owned(), SwitchKind::Base)
    );
    assert_eq!(
        switch_ids("0100ABCD00010800").unwrap(),
        ("0100ABCD00010000".to_owned(), SwitchKind::Update)
    );
    assert_eq!(switch_ids("0100ABCD00010001").unwrap().1, SwitchKind::Dlc);
    assert!(switch_ids("nope").is_err());
    assert_eq!(
        switch_update_id("0100ABCD00010000").unwrap(),
        "0100ABCD00010800"
    );
    assert!(switch_update_id("0100ABCD00010800").is_err());
}

#[test]
fn ids_are_checked_by_platform() {
    assert!(title_id_ok("switch", "0100ABCD00010000"));
    assert!(!title_id_ok("switch", "0100ABCD00010800"));
    assert!(title_id_ok("some-new-platform", "anything-goes_1"));
    assert!(!title_id_ok("some-new-platform", "no spaces"));
    assert!(app_id_ok("switch", "0100ABCD00010800", Some("update")));
    assert!(!app_id_ok("switch", "0100ABCD00010800", Some("base")));
    assert!(app_id_ok("switch", "0100ABCD00010800", None));
    assert!(app_id_ok("android", "org.example.game", None));
}

#[test]
fn paths_and_roots_take_the_homebrew_id() {
    let switch = profile("switch").unwrap();
    assert_eq!(
        single_file_path(switch, "nro", "org.x.y", "").unwrap(),
        "/switch/org.x.y/org.x.y.nro"
    );
    assert_eq!(single_file_path(switch, "zip", "org.x.y", ""), None);
    let (free, consent) = roots(switch, "org.x.y");
    assert_eq!(free, ["/switch/org.x.y/", "/config/org.x.y/"]);
    assert_eq!(consent, ["/atmosphere/", "/switch/.overlays/"]);
}

#[test]
fn cheats_go_where_the_profile_says() {
    assert_eq!(
        cheat_path("switch", "0100ABCD00010000", Some(&"A".repeat(40)), None).unwrap(),
        format!(
            "/atmosphere/contents/0100ABCD00010000/cheats/{}.txt",
            "A".repeat(16)
        )
    );
    assert!(cheat_path("switch", "0100ABCD00010000", None, None).is_err());
    assert!(cheat_path("linux", "x", None, None).is_err());
    assert_eq!(
        cheat_path("3ds", "0004000212345600", None, None).unwrap(),
        "/cheats/0004000212345600.txt"
    );
}

#[test]
fn a_lz4_nsp_requires_the_compression_layer() {
    assert_eq!(
        requires_of_name("switch", "dir/Game [LZ4].NSP").unwrap(),
        ["fs-compression", "sigpatch"]
    );
    assert_eq!(requires_of_name("switch", "Game.nsp"), None);
    assert_eq!(requires_of_name("3ds", "Game [LZ4].nsp"), None);
}

#[test]
fn uids_are_uuids_of_their_version() {
    let v4 = uuid_v4([0xff; 16]);
    assert!(is_uuid(&v4));
    assert_eq!(v4, "ffffffff-ffff-4fff-bfff-ffffffffffff");
    let v7 = uuid_v7(0x0123_4567_89ab, [0; 10]);
    assert_eq!(v7, "01234567-89ab-7000-8000-000000000000");
    assert!(!is_uuid("6f1c2a8e-…") && !is_uuid("6f1c2a8e1c2a8e1c2a8e1c2a8e1c2a8e1c2a"));
}
