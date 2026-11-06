//! The rules every document is read by: the `schema` rule (SPEC.md § 3.2),
//! the limits (§ 13) and the error answers (§ 12).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use lantern_protocol::documents::{SCHEMA, parse, read};
use lantern_protocol::generated::models::Titles;
use lantern_protocol::limits::{clip, load_json, printable};
use lantern_protocol::problem::{ProblemKind, problem_error};
use serde_json::json;

#[test]
fn a_newer_schema_is_absent() {
    let doc = json!({"schema": 2, "titles": [], "unknown": []});
    assert!(read::<Titles>(doc, SCHEMA, "titles").unwrap().is_none());
}

#[test]
fn a_known_schema_is_read_and_keeps_what_it_does_not_know() {
    let doc = json!({"schema": 1, "titles": [], "unknown": [], "from_the_future": {"a": 1}});
    let titles = read::<Titles>(doc, SCHEMA, "titles").unwrap().unwrap();
    assert_eq!(titles.extra["from_the_future"], json!({"a": 1}));
    let back = serde_json::to_value(&titles).unwrap();
    assert_eq!(back["from_the_future"], json!({"a": 1}));
}

#[test]
fn a_document_without_schema_is_refused() {
    for doc in [
        json!({"titles": [], "unknown": []}),
        json!({"schema": 0}),
        json!({"schema": "1"}),
        json!({"schema": 1.5}),
        json!([]),
    ] {
        assert!(read::<Titles>(doc, SCHEMA, "titles").is_err());
    }
}

#[test]
fn bytes_are_read_within_the_limits() {
    assert!(
        parse::<Titles>(
            br#"{"schema":1,"titles":[],"unknown":[]}"#,
            SCHEMA,
            "titles"
        )
        .unwrap()
        .is_some()
    );
    assert!(parse::<Titles>(b"\xef\xbb\xbf{\"schema\":1}", SCHEMA, "titles").is_err());
    assert!(parse::<Titles>(b"\xff", SCHEMA, "titles").is_err());
    assert!(parse::<Titles>(b"{", SCHEMA, "titles").is_err());
}

#[test]
fn what_is_not_ijson_is_refused() {
    assert!(load_json(br#"{"a":1,"a":2}"#, 1000, "d").is_err());
    assert!(load_json(br#"{"a":{"a":1},"b":{"a":1}}"#, 1000, "d").is_ok());
    assert!(load_json(br#"{"n":9007199254740993}"#, 1000, "d").is_err());
    assert!(load_json(br#"{"n":-9007199254740991}"#, 1000, "d").is_ok());
    assert!(load_json(br#"{"n":18446744073709551616}"#, 1000, "d").is_err());
    assert!(load_json(br#"{"n":1.0e30}"#, 1000, "d").is_ok());
    assert!(load_json(br#"{"s":"\ud800"}"#, 1000, "d").is_err());
    assert!(load_json(b"[1,2,3]", 3, "d").is_err());
}

#[test]
fn depth_and_strings_are_bounded() {
    let deep = format!("{}1{}", "[".repeat(17), "]".repeat(17));
    assert!(load_json(deep.as_bytes(), 1000, "d").is_err());
    let fine = format!("{}1{}", "[".repeat(16), "]".repeat(16));
    assert!(load_json(fine.as_bytes(), 1000, "d").is_ok());
    let long_name = format!(r#"{{"name":"{}"}}"#, "x".repeat(513));
    assert!(load_json(long_name.as_bytes(), 10_000, "d").is_err());
    let long_string = format!(r#"{{"other":"{}"}}"#, "x".repeat(4097));
    assert!(load_json(long_string.as_bytes(), 10_000, "d").is_err());
    // a hostile depth never reaches the parser
    let hostile = "[".repeat(1_000_000);
    assert!(load_json(hostile.as_bytes(), usize::MAX, "d").is_err());
}

#[test]
fn text_is_clipped_on_a_boundary_and_stripped() {
    assert_eq!(clip("héllo", 2), "h");
    assert_eq!(clip("héllo", 3), "hé");
    assert_eq!(printable("a\u{7}b\nc\u{9f}d", 100), "ab\ncd");
}

#[test]
fn an_answer_is_read_by_its_status() {
    let body = br#"{"schema":1,"status":404,"code":"not_found","detail":"no such\u0007 title"}"#;
    let e = problem_error(404, body, None);
    assert_eq!(e.kind, ProblemKind::NotFound);
    assert_eq!(e.code.as_deref(), Some("not_found"));
    assert_eq!(e.detail.as_deref(), Some("no such title"));

    let unknown = br#"{"schema":1,"status":409,"code":"a_code_from_the_future"}"#;
    let e = problem_error(409, unknown, None);
    assert_eq!(e.kind, ProblemKind::Conflict);
    assert_eq!(e.code, None);
    assert!(e.problem.is_some());

    let e = problem_error(429, b"not json", Some(" 30 "));
    assert_eq!(e.kind, ProblemKind::SlowDown);
    assert_eq!(e.retry_after, Some(30));
    assert!(e.problem.is_none());
    assert_eq!(problem_error(503, b"", Some("-1")).retry_after, None);
    assert_eq!(problem_error(503, b"", None).kind, ProblemKind::Unavailable);
    assert_eq!(problem_error(502, b"", None).kind, ProblemKind::ServerError);
    assert_eq!(problem_error(418, b"", None).kind, ProblemKind::Other);
}

#[test]
fn signature_and_frozen_codes_refine_their_status() {
    let sig = br#"{"schema":1,"status":401,"code":"signature_replayed"}"#;
    let e = problem_error(401, sig, None);
    assert_eq!(e.kind, ProblemKind::SignatureReplayed);
    assert!(e.kind.is_signature());
    let frozen = br#"{"schema":1,"status":403,"code":"account_frozen"}"#;
    assert_eq!(
        problem_error(403, frozen, None).kind,
        ProblemKind::AccountFrozen
    );
    assert_eq!(
        problem_error(401, b"", None).kind,
        ProblemKind::Unauthorized
    );
}
