//! LAN discovery: the replies a client reads, and the datagram over UDP on
//! loopback.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use lantern_protocol::discovery::{
    Datagram, REQUEST, UdpDatagram, directed_broadcast, discover, read_reply,
};

const LOOP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn reply(extra: &str) -> Vec<u8> {
    format!(
        r#"{{"schema":1,"lantern":"server","port":8443,"versions":[1],"uid":"6f1c2a8e","name":"Living room shelf","base":"/api/lantern"{extra}}}"#
    )
    .into_bytes()
}

#[test]
fn a_reply_is_read_and_a_hint_only() {
    let found = read_reply(&reply(""), LOOP).unwrap();
    assert_eq!(found.url, "https://127.0.0.1:8443/");
    assert_eq!(found.base, "/api/lantern");
    assert_eq!(found.versions, [1]);
    let v6 = read_reply(&reply(""), "::1".parse().unwrap()).unwrap();
    assert_eq!(v6.url, "https://[::1]:8443/");
    let default = String::from_utf8(reply("")).unwrap().replace("8443", "443");
    assert_eq!(
        read_reply(default.as_bytes(), LOOP).unwrap().url,
        "https://127.0.0.1/"
    );
    let named = String::from_utf8(reply(""))
        .unwrap()
        .replace("Living room shelf", "A\\nB\\u0007C");
    assert_eq!(read_reply(named.as_bytes(), LOOP).unwrap().name, "A BC");
}

#[test]
fn a_reply_that_is_not_one_is_left_out() {
    let text = String::from_utf8(reply("")).unwrap();
    for bad in [
        text.replace("\"schema\":1", "\"schema\":2"),
        text.replace("\"server\"", "\"peer\""),
        text.replace("8443", "0"),
        text.replace("8443", "70000"),
        text.replace("[1]", "[]"),
        text.replace("[1]", "[0]"),
        text.replace("/api/lantern", "//evil.example.org"),
        text.replace("/api/lantern", "/a?b"),
        text.replace("6f1c2a8e", ""),
        "not json".to_owned(),
        "[]".to_owned(),
    ] {
        assert!(read_reply(bad.as_bytes(), LOOP).is_none(), "{bad}");
    }
    let big = reply(&format!(",\"x\":\"{}\"", "a".repeat(1300)));
    assert!(read_reply(&big, LOOP).is_none());
    assert!(read_reply(&[0xff, 0xfe], LOOP).is_none());
}

#[test]
fn the_broadcast_address_of_a_network() {
    let b = |a: &str, p| {
        directed_broadcast(a.parse().unwrap(), p)
            .unwrap()
            .to_string()
    };
    assert_eq!(b("192.168.1.20", 24), "192.168.1.255");
    assert_eq!(b("10.1.2.3", 8), "10.255.255.255");
    assert_eq!(b("10.1.2.3", 32), "10.1.2.3");
    assert_eq!(b("10.1.2.3", 0), "255.255.255.255");
    assert!(directed_broadcast(Ipv4Addr::LOCALHOST, 33).is_err());
}

#[test]
fn discovery_over_udp_takes_one_reply_per_server() {
    let server = UdpDatagram::bind(SocketAddr::new(LOOP, 0)).unwrap();
    let target = server.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        let (n, _) = server
            .recv_from(&mut buffer, Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], REQUEST);
    });
    let client = UdpDatagram::bind(SocketAddr::new(LOOP, 0)).unwrap();
    let client_addr = client.local_addr().unwrap();
    // The server above checks the request; replies come from a helper socket.
    let found = {
        let answerer = UdpDatagram::bind(SocketAddr::new(LOOP, 0)).unwrap();
        answerer.send_to(b"nonsense", client_addr).unwrap();
        answerer.send_to(&reply(""), client_addr).unwrap();
        answerer.send_to(&reply(""), client_addr).unwrap();
        discover(&client, &[target], Duration::from_millis(500)).unwrap()
    };
    handle.join().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "Living room shelf");
}
