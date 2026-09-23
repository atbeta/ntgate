//! Outbound TCP connect shared by the proxy and `doctor`.
//!
//! Tokio connects only after setting `FIONBIO`. Some corporate Winsock filters
//! answer that with WSAEACCES (10013). On Windows the first attempt is the
//! classic `socket()` + blocking `connect()` used by curl and cntlm (no
//! `WSA_FLAG_NO_HANDLE_INHERIT`, no pre-bind). If that still returns 10013,
//! retry with an explicit `bind` to port 0 (Hyper-V excluded ephemeral ports)
//! and finally a non-overlapped `WSASocketW`.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

#[cfg(not(windows))]
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Windows `WSAEACCES`. Non-blocking connect and excluded ephemeral ports.
#[cfg(windows)]
const WSAEACCES: i32 = 10013;

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
    for n in 1..=4 {
        match blocking::plain(addr) {
            Ok(stream) => return Ok(stream),
            Err(e) if is_wsaeacces(&e) && n < 4 => {}
            Err(e) if is_wsaeacces(&e) => notes.push(format!("plain x4: {}", io_msg(&e))),
            Err(e) => return Err(e),
        }
    }
    for n in 1..=8 {
        match blocking::bind0(addr) {
            Ok(stream) => return Ok(stream),
            Err(e) if is_wsaeacces(&e) && n < 8 => {}
            Err(e) if is_wsaeacces(&e) => notes.push(format!("bind0 x8: {}", io_msg(&e))),
            Err(e) => return Err(e),
        }
    }
    match blocking::nooverlap(addr) {
        Ok(stream) => return Ok(stream),
        Err(e) if is_wsaeacces(&e) => notes.push(format!("nooverlap: {}", io_msg(&e))),
        Err(e) => return Err(e),
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
fn is_wsaeacces(err: &io::Error) -> bool {
    err.raw_os_error() == Some(WSAEACCES)
}

#[cfg(windows)]
mod blocking {
    use std::io;
    use std::mem::{MaybeUninit, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::windows::io::FromRawSocket;
    use std::time::Duration;

    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, FIONBIO, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, INVALID_SOCKET,
        IPPROTO_TCP, SO_SNDTIMEO, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
        SOCKET, SOCKET_ERROR, SOL_SOCKET, WSADATA, WSAGetLastError, WSASocketW, WSAStartup, bind,
        closesocket, connect, ioctlsocket, setsockopt, socket,
    };

    use super::CONNECT_TIMEOUT;

    struct Sock(SOCKET);

    impl Drop for Sock {
        fn drop(&mut self) {
            unsafe {
                closesocket(self.0);
            }
        }
    }

    pub(super) fn plain(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
        let sock = Sock::open(addr, true)?;
        finish(sock, addr)
    }

    pub(super) fn bind0(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
        let sock = Sock::open(addr, true)?;
        sock.bind_any(addr)?;
        finish(sock, addr)
    }

    pub(super) fn nooverlap(addr: SocketAddr) -> io::Result<std::net::TcpStream> {
        let sock = Sock::open(addr, false)?;
        finish(sock, addr)
    }

    fn finish(sock: Sock, addr: SocketAddr) -> io::Result<std::net::TcpStream> {
        sock.set_send_timeout(Some(CONNECT_TIMEOUT))?;
        sock.connect_to(addr)?;
        sock.set_send_timeout(None)?;
        sock.into_std()
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

        fn bind_any(&self, remote: SocketAddr) -> io::Result<()> {
            let local = match remote {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            with_sockaddr(local, |ptr, len| unsafe { bind(self.0, ptr, len) })
        }

        fn connect_to(&self, addr: SocketAddr) -> io::Result<()> {
            with_sockaddr(addr, |ptr, len| unsafe { connect(self.0, ptr, len) })
        }

        fn set_send_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            // Windows SO_SNDTIMEO is milliseconds. 0 means wait forever, and it
            // also bounds a blocking connect.
            let ms = timeout.map_or(0, |d| d.as_millis().min(u32::MAX as u128) as u32);
            let rc = unsafe {
                setsockopt(
                    self.0,
                    SOL_SOCKET,
                    SO_SNDTIMEO,
                    (&ms as *const u32).cast(),
                    size_of::<u32>() as i32,
                )
            };
            win_rc(rc)
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
