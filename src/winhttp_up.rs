//! Upstream proxy via WinHTTP. Raw `connect()` to this proxy is rejected with
//! WSAEACCES (10013) for every socket style, while loopback connects succeed.
//! WinHTTP is the stack Windows itself uses for the system proxy, and it
//! attaches the current logon session for Negotiate/NTLM.

#![cfg(windows)]

use std::ptr;

use tokio::net::TcpStream;
use windows_sys::Win32::Foundation::{FALSE, GetLastError, TRUE};
use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_RESEND_REQUEST, ERROR_WINHTTP_TIMEOUT, WINHTTP_ACCESS_TYPE_NO_PROXY,
    WINHTTP_AUTH_SCHEME_NEGOTIATE, WINHTTP_AUTH_SCHEME_NTLM, WINHTTP_AUTH_TARGET_PROXY,
    WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW, WINHTTP_OPTION_AUTOLOGON_POLICY,
    WINHTTP_OPTION_CONNECT_TIMEOUT, WINHTTP_OPTION_RECEIVE_TIMEOUT, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetCredentials, WinHttpSetOption, WinHttpWriteData,
};
use windows_sys::Win32::Networking::WinSock::{
    SOCKET, WSAEWOULDBLOCK, WSAGetLastError, recv, send,
};

use crate::error::{Error, Result};

unsafe impl Send for Handles {}

struct Handles {
    session: *mut core::ffi::c_void,
    connect: *mut core::ffi::c_void,
    request: *mut core::ffi::c_void,
}

impl Drop for Handles {
    fn drop(&mut self) {
        unsafe {
            if !self.request.is_null() {
                WinHttpCloseHandle(self.request);
            }
            if !self.connect.is_null() {
                WinHttpCloseHandle(self.connect);
            }
            if !self.session.is_null() {
                WinHttpCloseHandle(self.session);
            }
        }
    }
}

struct Tunnel {
    handles: Handles,
    status: u32,
}

pub async fn probe(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
) -> Result<String> {
    let proxy_host = proxy_host.to_string();
    let dest_host = dest_host.to_string();
    let tunnel = tokio::task::spawn_blocking(move || {
        Tunnel::open(
            &proxy_host,
            proxy_port,
            &dest_host,
            dest_port,
            dest_port == 443,
        )
    })
    .await
    .map_err(|e| Error::msg(format!("winhttp task: {e}")))??;
    if (200..400).contains(&tunnel.status) {
        Ok(format!("winhttp HTTP {}", tunnel.status))
    } else {
        Err(Error::Upstream {
            host: "winhttp".into(),
            port: proxy_port,
            message: format!("HTTP {}", tunnel.status),
        })
    }
}

pub async fn forward(
    client: &mut TcpStream,
    leftover: &mut Vec<u8>,
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    is_connect: bool,
) -> Result<()> {
    let proxy_host = proxy_host.to_string();
    let dest_host = dest_host.to_string();
    let mut tunnel = tokio::task::spawn_blocking(move || {
        Tunnel::open(&proxy_host, proxy_port, &dest_host, dest_port, is_connect)
    })
    .await
    .map_err(|e| Error::msg(format!("winhttp task: {e}")))??;

    if is_connect {
        if tunnel.status != 200 {
            return Err(Error::Upstream {
                host: "winhttp".into(),
                port: proxy_port,
                message: format!("CONNECT HTTP {}", tunnel.status),
            });
        }
        crate::io::write_all(client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let preface = std::mem::take(leftover);
        let sock = std::os::windows::io::AsRawSocket::as_raw_socket(client);
        tokio::task::spawn_blocking(move || tunnel.pump(sock, &preface))
            .await
            .map_err(|e| Error::msg(format!("winhttp pump: {e}")))?
    } else {
        let body = tokio::task::spawn_blocking(move || tunnel.read_response())
            .await
            .map_err(|e| Error::msg(format!("winhttp read: {e}")))??;
        crate::io::write_all(client, &body).await
    }
}

impl Tunnel {
    fn open(
        proxy_host: &str,
        proxy_port: u16,
        dest_host: &str,
        dest_port: u16,
        is_connect: bool,
    ) -> Result<Self> {
        let agent = wide("ntgate");
        let session = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                ptr::null(),
                ptr::null(),
                0,
            )
        };
        if session.is_null() {
            return Err(winhttp_err("WinHttpOpen"));
        }
        let timeout = 20_000u32;
        unsafe {
            WinHttpSetOption(
                session,
                WINHTTP_OPTION_CONNECT_TIMEOUT,
                &timeout as *const u32 as *const _,
                4,
            );
        }
        let host = wide(proxy_host);
        let connect = unsafe { WinHttpConnect(session, host.as_ptr(), proxy_port, 0) };
        if connect.is_null() {
            unsafe { WinHttpCloseHandle(session) };
            return Err(winhttp_err("WinHttpConnect"));
        }
        let (verb, object) = if is_connect {
            ("CONNECT".to_string(), format!("{dest_host}:{dest_port}"))
        } else {
            (
                "GET".to_string(),
                format!("http://{dest_host}:{dest_port}/"),
            )
        };
        let verb_w = wide(&verb);
        let object_w = wide(&object);
        let request = unsafe {
            WinHttpOpenRequest(
                connect,
                verb_w.as_ptr(),
                object_w.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
            )
        };
        if request.is_null() {
            unsafe {
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
            }
            return Err(winhttp_err("WinHttpOpenRequest"));
        }
        let handles = Handles {
            session,
            connect,
            request,
        };
        let policy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
        unsafe {
            WinHttpSetOption(
                request,
                WINHTTP_OPTION_AUTOLOGON_POLICY,
                &policy as *const u32 as *const _,
                4,
            );
            WinHttpSetCredentials(
                request,
                WINHTTP_AUTH_TARGET_PROXY,
                WINHTTP_AUTH_SCHEME_NEGOTIATE,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            );
            WinHttpSetCredentials(
                request,
                WINHTTP_AUTH_TARGET_PROXY,
                WINHTTP_AUTH_SCHEME_NTLM,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            );
        }
        send_with_resend(request)?;
        if unsafe { WinHttpReceiveResponse(request, ptr::null_mut()) } == FALSE {
            return Err(winhttp_err("WinHttpReceiveResponse"));
        }
        let status = status_code(request)?;
        Ok(Self { handles, status })
    }

    fn write_all(&self, data: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < data.len() {
            let mut wrote = 0u32;
            let ok = unsafe {
                WinHttpWriteData(
                    self.handles.request,
                    data[off..].as_ptr().cast(),
                    data[off..].len().min(u32::MAX as usize) as u32,
                    &mut wrote,
                )
            };
            if ok == FALSE {
                return Err(winhttp_err("WinHttpWriteData"));
            }
            if wrote == 0 {
                return Err(Error::msg("winhttp write returned 0"));
            }
            off += wrote as usize;
        }
        Ok(())
    }

    fn read_response(&self) -> Result<Vec<u8>> {
        let mut headers = query_raw_headers(self.handles.request)?;
        if !headers.ends_with(b"\r\n\r\n") {
            headers.extend_from_slice(b"\r\n\r\n");
        }
        let mut body = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let mut n = 0u32;
            let ok = unsafe {
                WinHttpReadData(
                    self.handles.request,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut n,
                )
            };
            if ok == FALSE {
                let err = unsafe { GetLastError() };
                if err == ERROR_WINHTTP_TIMEOUT {
                    break;
                }
                return Err(winhttp_err("WinHttpReadData"));
            }
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n as usize]);
        }
        headers.extend_from_slice(&body);
        Ok(headers)
    }

    fn pump(&mut self, client: std::os::windows::io::RawSocket, preface: &[u8]) -> Result<()> {
        if !preface.is_empty() {
            self.write_all(preface)?;
        }
        let ms = 50u32;
        unsafe {
            WinHttpSetOption(
                self.handles.request,
                WINHTTP_OPTION_RECEIVE_TIMEOUT,
                &ms as *const u32 as *const _,
                4,
            );
        }
        let sock = client as SOCKET;
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = unsafe { recv(sock, buf.as_mut_ptr().cast(), buf.len() as i32, 0) };
            if n > 0 {
                self.write_all(&buf[..n as usize])?;
            } else if n == 0 {
                break;
            } else {
                let err = unsafe { WSAGetLastError() };
                if err != WSAEWOULDBLOCK {
                    break;
                }
            }
            let mut nread = 0u32;
            let ok = unsafe {
                WinHttpReadData(
                    self.handles.request,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut nread,
                )
            };
            if ok == FALSE {
                let err = unsafe { GetLastError() };
                if err == ERROR_WINHTTP_TIMEOUT {
                    continue;
                }
                break;
            }
            if nread == 0 {
                break;
            }
            let mut sent = 0usize;
            let chunk = &buf[..nread as usize];
            while sent < chunk.len() {
                let w = unsafe {
                    send(
                        sock,
                        chunk[sent..].as_ptr().cast(),
                        (chunk.len() - sent) as i32,
                        0,
                    )
                };
                if w > 0 {
                    sent += w as usize;
                } else {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

fn send_with_resend(request: *mut core::ffi::c_void) -> Result<()> {
    for _ in 0..6 {
        let ok = unsafe { WinHttpSendRequest(request, ptr::null(), 0, ptr::null(), 0, 0, 0) };
        if ok == TRUE {
            return Ok(());
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_WINHTTP_RESEND_REQUEST {
            return Err(Error::msg(format!("WinHttpSendRequest failed: {err}")));
        }
    }
    Err(Error::msg("WinHttpSendRequest exceeded auth rounds"))
}

fn status_code(request: *mut core::ffi::c_void) -> Result<u32> {
    let mut status = 0u32;
    let mut len = 4u32;
    let mut index = 0u32;
    let ok = unsafe {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            &mut status as *mut u32 as *mut _,
            &mut len,
            &mut index,
        )
    };
    if ok == FALSE {
        return Err(winhttp_err("WinHttpQueryHeaders status"));
    }
    Ok(status)
}

fn query_raw_headers(request: *mut core::ffi::c_void) -> Result<Vec<u8>> {
    let mut len = 0u32;
    let mut index = 0u32;
    unsafe {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            ptr::null(),
            ptr::null_mut(),
            &mut len,
            &mut index,
        );
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u16; (len as usize / 2).max(1)];
    index = 0;
    let ok = unsafe {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            ptr::null(),
            buf.as_mut_ptr().cast(),
            &mut len,
            &mut index,
        )
    };
    if ok == FALSE {
        return Err(winhttp_err("WinHttpQueryHeaders"));
    }
    let n = (len as usize / 2).saturating_sub(1);
    Ok(String::from_utf16_lossy(&buf[..n]).into_bytes())
}

fn winhttp_err(what: &str) -> Error {
    Error::msg(format!("{what} failed: {}", unsafe { GetLastError() }))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
