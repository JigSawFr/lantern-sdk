//! Any answer a server could send: a status, a body and a `Retry-After`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (u16, &[u8], Option<&str>)| {
    let (status, body, retry_after) = data;
    let _ = lantern_protocol::problem::problem_error(status, body, retry_after);
});
