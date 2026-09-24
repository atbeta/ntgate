//! Outbound TCP connect shared by the proxy and `doctor`.
//!
//! On Windows every 0.2.1 attempt set `SO_SNDTIMEO` before `connect`. A corporate
//! Winsock filter can answer that with WSAEACCES (10013) for every socket
//! type. The first attempt is now a bare blocking `socket()` + `connect()`
//! with no socket options. Later attempts are `std::net`, a bind to a fixed
//! local port, and a non-overlapped socket. The error names the syscall.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(not(windows))]
use std::time::Duration;

#[cfg(not(windows))]
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

#[cfg(not(windows))]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

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
            Err(e) => errors.push(format!("{addr}: {}", describe(&e))),
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
        connect_addr_windows(addr)
    }
    #[cfg(not(windows))]
    {
        connect_addr_unix(addr)
    }
}

#[cfg(not(windows))]
fn connect_addr_unix(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.connect_timeout(&SockAddr::from(addr), CONNECT_TIMEOUT)?;
    socket.set_nonblocking(true)?;
    let stream = std::net::TcpStream::from(socket);
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

#[cfg(windows)]
fn connect_addr_windows(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
    let mut notes = Vec::new();
    for attempt in [
        blocking::bare,
        blocking::std_connect,
        blocking::pinned,
        blocking::nooverlap,
    ] {
        match attempt(addr) {
            Ok(stream) => return Ok(stream),
            Err(fail) if fail.is_acces() => notes.push(fail.to_string()),
            Err(fail) => return Err(fail.into_io()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "ntgate {} still WSAEACCES: {}",
            env!("CARGO_PKG_VERSION"),
            notes.join(" | ")
        ),
    ))
}

#[cfg(windows)]
mod blocking {
    use std::io;
    use std::mem::{MaybeUninit, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::windows::io::FromRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, FIONBIO, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, INVALID_SOCKET,
        IPPROTO_TCP, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKET,
        SOCKET_ERROR, WSADATA, WSAEACCES, WSAEADDRINUSE, WSAGetLastError, WSASocketW, WSAStartup,
        bind, closesocket, connect, ioctlsocket, socket,
    };

    use super::io_msg;

    pub(super) struct Fail {
        step: String,
        err: io::Error,
    }

    impl Fail {
        fn new(step: impl Into<String>, err: io::Error) -> Self {
            Self {
                step: step.into(),
                err,
            }
        }

        pub(super) fn is_acces(&self) -> bool {
            self.err.raw_os_error() == Some(WSAEACCES)
        }

        pub(super) fn into_io(self) -> io::Error {
            io::Error::other(self.to_string())
        }
    }

    impl std::fmt::Display for Fail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.step, io_msg(&self.err))
        }
    }

    struct Sock(SOCKET);

    impl Drop for Sock {
        fn drop(&mut self) {
            unsafe {
                closesocket(self.0);
            }
        }
    }

    pub(super) fn bare(addr: SocketAddr) -> Result<std::net::TcpStream, Fail> {
        let sock = Sock::open(addr, true).map_err(|e| Fail::new("bare/socket", e))?;
        sock.connect_to(addr)
            .map_err(|e| Fail::new("bare/connect", e))?;
        sock.into_std().map_err(|e| Fail::new("bare/nonblock", e))
    }

    pub(super) fn std_connect(addr: SocketAddr) -> Result<std::net::TcpStream, Fail> {
        let stream = std::net::TcpStream::connect(addr).map_err(|e| Fail::new("std/connect", e))?;
        stream
            .set_nonblocking(true)
            .map_err(|e| Fail::new("std/nonblock", e))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    pub(super) fn pinned(addr: SocketAddr) -> Result<std::net::TcpStream, Fail> {
        // Fixed ports avoid the ephemeral allocator, which returns 10013 when
        // every port it hands out sits in a Hyper-V excluded range.
        const PORTS: &[u16] = &[
            49152, 50000, 52000, 54000, 56000, 58000, 60000, 62000, 20000, 25000, 30000, 35000,
            40000, 45000,
        ];
        let mut acces = 0u32;
        let mut in_use = 0u32;
        let mut last = None;
        for port in PORTS {
            let sock = Sock::open(addr, true).map_err(|e| Fail::new("pin/socket", e))?;
            match sock.bind_port(addr, *port) {
                Ok(()) => {
                    sock.connect_to(addr)
                        .map_err(|e| Fail::new(format!("pin{port}/connect"), e))?;
                    return sock
                        .into_std()
                        .map_err(|e| Fail::new(format!("pin{port}/nonblock"), e));
                }
                Err(e) if e.raw_os_error() == Some(WSAEACCES) => {
                    acces += 1;
                    last = Some(e);
                }
                Err(e) if e.raw_os_error() == Some(WSAEADDRINUSE) => in_use += 1,
                Err(e) => return Err(Fail::new(format!("pin{port}/bind"), e)),
            }
        }
        let _ = last;
        if acces > 0 {
            Err(Fail::new(
                format!("pin bind WSAEACCES x{acces} in-use x{in_use}"),
                io::Error::from_raw_os_error(WSAEACCES),
            ))
        } else {
            Err(Fail::new(
                format!("pin in-use x{in_use}"),
                io::Error::new(io::ErrorKind::AddrInUse, "no free local port"),
            ))
        }
    }

    pub(super) fn nooverlap(addr: SocketAddr) -> Result<std::net::TcpStream, Fail> {
        let sock = Sock::open(addr, false).map_err(|e| Fail::new("nooverlap/socket", e))?;
        sock.connect_to(addr)
            .map_err(|e| Fail::new("nooverlap/connect", e))?;
        sock.into_std()
            .map_err(|e| Fail::new("nooverlap/nonblock", e))
    }

    impl Sock {
        fn open(addr: SocketAddr, overlapped: bool) -> io::Result<Self> {
            ensure_wsa();
            let af = af(addr);
            let sock = if overlapped {
                unsafe { socket(af, SOCK_STREAM, IPPROTO_TCP) }
            } else {
                // dwFlags = 0: WSASocketW does not set WSA_FLAG_OVERLAPPED.
                // socket() always does, which some filters reject with 10013.
                unsafe { WSASocketW(af, SOCK_STREAM, IPPROTO_TCP, std::ptr::null(), 0, 0) }
            };
            if sock == INVALID_SOCKET {
                return Err(ws_err());
            }
            Ok(Self(sock))
        }

        fn bind_port(&self, remote: SocketAddr, port: u16) -> io::Result<()> {
            let local = match remote {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            };
            with_sockaddr(local, |ptr, len| unsafe { bind(self.0, ptr, len) })
        }

        fn connect_to(&self, addr: SocketAddr) -> io::Result<()> {
            with_sockaddr(addr, |ptr, len| unsafe { connect(self.0, ptr, len) })
        }

        fn into_std(self) -> io::Result<std::net::TcpStream> {
            let mut nb = 1u32;
            let rc = unsafe { ioctlsocket(self.0, FIONBIO, &mut nb) };
            win_rc(rc)?;
            let raw = self.0 as std::os::windows::io::RawSocket;
            std::mem::forget(self);
            let stream = unsafe { std::net::TcpStream::from_raw_socket(raw) };
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
    }

    fn win_rc(rc: i32) -> io::Result<()> {
        if rc == SOCKET_ERROR {
            Err(ws_err())
        } else {
            Ok(())
        }
    }

    fn ws_err() -> io::Error {
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    fn af(addr: SocketAddr) -> i32 {
        if addr.is_ipv4() {
            AF_INET as i32
        } else {
            AF_INET6 as i32
        }
    }

    fn with_sockaddr(
        addr: SocketAddr,
        op: impl FnOnce(*const SOCKADDR, i32) -> i32,
    ) -> io::Result<()> {
        let rc = match addr {
            SocketAddr::V4(v4) => {
                let bits = IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.ip().octets()),
                };
                let sin = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: v4.port().to_be(),
                    sin_addr: IN_ADDR { S_un: bits },
                    sin_zero: [0; 8],
                };
                op(
                    (&sin as *const SOCKADDR_IN).cast(),
                    size_of::<SOCKADDR_IN>() as i32,
                )
            }
            SocketAddr::V6(v6) => {
                let sin = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: v6.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: v6.scope_id(),
                    },
                };
                op(
                    (&sin as *const SOCKADDR_IN6).cast(),
                    size_of::<SOCKADDR_IN6>() as i32,
                )
            }
        };
        win_rc(rc)
    }

    fn ensure_wsa() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| unsafe {
            let mut data = MaybeUninit::<WSADATA>::uninit();
            let _ = WSAStartup(0x0202, data.as_mut_ptr());
        });
    }
}

fn io_msg(err: &io::Error) -> String {
    format!("{err} [raw_os_error={:?}]", err.raw_os_error())
}

fn describe(err: &io::Error) -> String {
    let msg = err.to_string();
    if err.raw_os_error().is_none() {
        msg
    } else {
        io_msg(err)
    }
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
