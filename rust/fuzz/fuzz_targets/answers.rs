//! Any answer a server could send: a status, a body and a `Retry-After`; and
//! any datagram that claims to be a discovery reply.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (u16, &[u8], Option<&str>)| {
    let (status, body, retry_after) = data;
    let _ = lantern_protocol::problem::problem_error(status, body, retry_after);
    let _ = lantern_protocol::discovery::read_reply(body, std::net::Ipv4Addr::LOCALHOST.into());
});
