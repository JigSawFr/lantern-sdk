//! LAN discovery (SPEC.md § 4.1): the datagram a client sends on UDP 47115,
//! and the replies it reads.
//!
//! Discovery is a hint: it gives an address and a name, nothing more. A reply
//! proves nothing; the client trusts a server only through TLS and pairing
//! (§ 5, L-4.1-5). A reply is read by the `schema` rule: one of a newer
//! schema is absent, and a reply this library cannot read is left out.
//!
//! The sockets are the caller's: [`Datagram`] is the one thing this module
//! needs of them, and [`UdpDatagram`] is the standard library's.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::documents::SCHEMA;
use crate::error::{Error, Result};
use crate::limits::{DATAGRAM, NAME, printable};

/// The UDP port.
pub const PORT: u16 = 47115;
/// The request a client sends (SPEC.md § 4.1).
pub const REQUEST: &[u8] = br#"{"schema":1,"lantern":"discover"}"#;
/// The request that also asks the peers of the network (SPEC.md § 19.5).
pub const PEERS_REQUEST: &[u8] = br#"{"schema":1,"lantern":"discover","peers":true}"#;
/// The DNS-SD service type (RFC 6763).
pub const SERVICE: &str = "_lantern._tcp.local.";

/// A server that answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The reply's source address.
    pub address: IpAddr,
    /// Its HTTPS port.
    pub port: u16,
    /// Its handshake's `uid`.
    pub uid: String,
    /// Its `name`, bounded and on one line.
    pub name: String,
    /// Its `base` path.
    pub base: String,
    /// Its `versions`.
    pub versions: Vec<i64>,
    /// The server's address, for the handshake over TLS.
    pub url: String,
}

/// The broadcast address of `address`'s network (`192.168.1.255` for
/// `192.168.1.20`/24): where a client sends the datagram, since some consoles
/// drop `255.255.255.255`.
///
/// # Errors
///
/// When `prefix` is above 32.
pub fn directed_broadcast(address: Ipv4Addr, prefix: u8) -> Result<Ipv4Addr> {
    if prefix > 32 {
        return Err(Error::field(
            format!("{address}/{prefix} is not an IPv4 network"),
            "prefix",
        ));
    }
    let host_bits = 32 - u32::from(prefix);
    let mask = if host_bits == 32 {
        u32::MAX
    } else {
        (1u32 << host_bits) - 1
    };
    Ok(Ipv4Addr::from(u32::from(address) | mask))
}

fn base_ok(base: &str) -> bool {
    base.starts_with('/')
        && !base.starts_with("//")
        && base.len() <= 256
        && base.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !base.contains(['?', '#', '\\'])
}

fn whole(value: Option<&Value>, low: i64, high: i64) -> Option<i64> {
    value?.as_i64().filter(|n| (low..=high).contains(n))
}

/// A server's reply (SPEC.md § 4.1), or `None` when it is not one this
/// library reads: above 1200 bytes, not UTF-8 JSON, of a newer schema, not a
/// server's, or with a field not of its form.
#[must_use]
pub fn read_reply(data: &[u8], address: IpAddr) -> Option<Found> {
    if data.len() > DATAGRAM {
        return None;
    }
    let doc: Value = serde_json::from_str(std::str::from_utf8(data).ok()?).ok()?;
    let object = doc.as_object()?;
    whole(object.get("schema"), 1, SCHEMA)?;
    if object.get("lantern")?.as_str()? != "server" {
        return None;
    }
    let uid = object.get("uid")?.as_str()?;
    if uid.is_empty() || uid.len() > 64 {
        return None;
    }
    let name = object.get("name")?.as_str()?;
    let base = object.get("base")?.as_str().filter(|b| base_ok(b))?;
    let port = u16::try_from(whole(object.get("port"), 1, 65535)?).ok()?;
    let versions: Vec<i64> = object
        .get("versions")?
        .as_array()?
        .iter()
        .map(|v| v.as_i64().filter(|n| *n >= 1))
        .collect::<Option<_>>()?;
    if versions.is_empty() {
        return None;
    }
    let host = match address {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{a}]"),
    };
    let url = if port == 443 {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{port}/")
    };
    Some(Found {
        address,
        port,
        uid: uid.to_owned(),
        name: printable(name, NAME).replace('\n', " "),
        base: base.to_owned(),
        versions,
        url,
    })
}

/// The socket discovery needs.
pub trait Datagram {
    /// Sends `data` to `target`.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when it cannot.
    fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<()>;
    /// Waits up to `wait` for a datagram: the bytes read into `buffer` and the
    /// address they came from, or `None` when nothing came.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the socket fails.
    fn recv_from(&self, buffer: &mut [u8], wait: Duration) -> Result<Option<(usize, IpAddr)>>;
}

/// The standard library's UDP socket, with broadcast on.
#[derive(Debug)]
pub struct UdpDatagram {
    socket: UdpSocket,
}

impl UdpDatagram {
    /// A socket on any free port of `bind`.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the socket cannot be made.
    pub fn bind(bind: SocketAddr) -> Result<Self> {
        let io = |e: std::io::Error| Error::Transport(format!("UDP: {e}"));
        let socket = UdpSocket::bind(bind).map_err(io)?;
        socket.set_broadcast(true).map_err(io)?;
        Ok(Self { socket })
    }

    /// The socket's own address.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when it cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| Error::Transport(format!("UDP: {e}")))
    }
}

impl Datagram for UdpDatagram {
    fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<()> {
        self.socket
            .send_to(data, target)
            .map(|_| ())
            .map_err(|e| Error::Transport(format!("UDP: {e}")))
    }

    fn recv_from(&self, buffer: &mut [u8], wait: Duration) -> Result<Option<(usize, IpAddr)>> {
        self.socket
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(|e| Error::Transport(format!("UDP: {e}")))?;
        match self.socket.recv_from(buffer) {
            Ok((n, from)) => Ok(Some((n, from.ip()))),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(Error::Transport(format!("UDP: {e}"))),
        }
    }
}

/// Sends the request to each of `targets` (an address and the port, usually
/// [`PORT`]) and collects the servers that answer within `wait`, one per
/// `uid` (the first reply wins).
///
/// # Errors
///
/// [`Error::Transport`] when the socket fails.
pub fn discover(
    socket: &dyn Datagram,
    targets: &[SocketAddr],
    wait: Duration,
) -> Result<Vec<Found>> {
    for target in targets {
        socket.send_to(REQUEST, *target)?;
    }
    let deadline = Instant::now() + wait;
    let mut found: Vec<Found> = Vec::new();
    // One byte more than a datagram may hold, to tell an oversized one.
    let mut buffer = vec![0u8; DATAGRAM + 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(found);
        }
        let Some((n, from)) = socket.recv_from(&mut buffer, left)? else {
            return Ok(found);
        };
        let Some(data) = buffer.get(..n) else {
            continue;
        };
        if let Some(server) = read_reply(data, from)
            && !found.iter().any(|f| f.uid == server.uid)
        {
            found.push(server);
        }
    }
}
