//! Outbound TCP connect shared by the proxy and `doctor`.
//!
//! Tokio's `TcpStream::connect` (and `std::net::TcpStream::connect_timeout`)
//! call `connect` only after setting `FIONBIO`. Some corporate Winsock filters
//! answer that non-blocking connect with WSAEACCES (10013). A blocking
//! `connect` to the same proxy succeeds. On Windows we also `bind` port 0
//! first: an implicit ephemeral bind can land in a Hyper-V excluded range and
//! fail with the same 10013.

use std::io;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Windows `WSAEACCES`. Returned for non-blocking connect and for an ephemeral
/// port that sits in an excluded range.
#[cfg(windows)]
const WSAEACCES: i32 = 10013;
#[cfg(windows)]
const WSAEACCES_ATTEMPTS: u32 = 16;

pub(crate) async fn connect(host: &str, port: u16) -> Result<TcpStream> {
    let host_owned = host.to_string();
    let host_err = host_owned.clone();
    let std_stream = tokio::task::spawn_blocking(move || connect_blocking(host_owned, port))
        .await
        .map_err(|e| Error::Upstream {
            host: host_err.clone(),
            port,
            message: format!("connect task: {e}"),
        })??;
    TcpStream::from_std(std_stream).map_err(|e| Error::Upstream {
        host: host_err,
        port,
        message: format!("from_std: {} [raw_os_error={:?}]", e, e.raw_os_error()),
    })
}

fn connect_blocking(host: String, port: u16) -> Result<std::net::TcpStream> {
    let addrs = match (host.as_str(), port).to_socket_addrs() {
        Ok(iter) => prefer_ipv4(iter.collect()),
        Err(e) => {
            return Err(Error::Upstream {
                host,
                port,
                message: format!("dns: {}", io_msg(&e)),
            });
        }
    };
    if addrs.is_empty() {
        return Err(Error::Upstream {
            host,
            port,
            message: "dns: no addresses".into(),
        });
    }

    let mut errors = Vec::new();
    for addr in addrs {
        match connect_addr(addr) {
            Ok(stream) => return Ok(stream),
            Err(e) => errors.push(format!("{addr}: {}", io_msg(&e))),
        }
    }
    Err(Error::Upstream {
        host,
        port,
        message: errors.join("; "),
    })
}

fn prefer_ipv4(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in addrs {
        if addr.is_ipv4() {
            v4.push(addr);
        } else {
            v6.push(addr);
        }
    }
    v4.append(&mut v6);
    v4
}

fn connect_addr(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
    #[cfg(windows)]
    {
        let mut last = None;
        for _ in 0..WSAEACCES_ATTEMPTS {
            match connect_addr_once(addr) {
                Ok(stream) => return Ok(stream),
                Err(e) if e.raw_os_error() == Some(WSAEACCES) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("connect failed without an error")))
    }
    #[cfg(not(windows))]
    {
        connect_addr_once(addr)
    }
}

fn connect_addr_once(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    #[cfg(windows)]
    {
        // SO_SNDTIMEO bounds a blocking connect. Flipping FIONBIO (what
        // `connect_timeout` does) is the call these filters reject.
        socket.set_write_timeout(Some(CONNECT_TIMEOUT))?;
        let local = SocketAddr::new(unspecified(addr), 0);
        socket.bind(&SockAddr::from(local))?;
        socket.connect(&SockAddr::from(addr))?;
        socket.set_write_timeout(None)?;
    }
    #[cfg(not(windows))]
    {
        socket.connect_timeout(&SockAddr::from(addr), CONNECT_TIMEOUT)?;
    }
    socket.set_nonblocking(true)?;
    let stream = std::net::TcpStream::from(socket);
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

#[cfg(windows)]
fn unspecified(addr: SocketAddr) -> IpAddr {
    if addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

fn io_msg(err: &io::Error) -> String {
    format!("{err} [raw_os_error={:?}]", err.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::prefer_ipv4;
    use std::net::SocketAddr;

    #[test]
    fn prefer_ipv4_keeps_family_order() {
        let a: SocketAddr = "1.1.1.1:8080".parse().unwrap();
        let b: SocketAddr = "8.8.8.8:8080".parse().unwrap();
        let c: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let d: SocketAddr = "[2001:db8::2]:8080".parse().unwrap();
        assert_eq!(prefer_ipv4(vec![c, a, d, b]), vec![a, b, c, d]);
    }

    #[tokio::test]
    async fn connects_to_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let stream = super::connect("127.0.0.1", port).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn refused_reports_os_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let err = super::connect("127.0.0.1", port).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(&format!("127.0.0.1:{port}")), "{msg}");
        assert!(msg.contains("raw_os_error=Some("), "{msg}");
    }
}
