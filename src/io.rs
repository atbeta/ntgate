use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::http1::{self, ClientRequest, ServerResponse};

pub async fn read_until_double_crlf(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    max: usize,
) -> Result<Vec<u8>> {
    loop {
        if let Some(pos) = find_header_end(leftover) {
            let head = leftover[..pos].to_vec();
            leftover.drain(..pos);
            return Ok(head);
        }
        if leftover.len() > max {
            return Err(Error::Http("header block too large".into()));
        }
        let mut tmp = [0u8; 8192];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::Http("peer closed before sending headers".into()));
        }
        leftover.extend_from_slice(&tmp[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

pub async fn read_client_request(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    max_body: usize,
) -> Result<ClientRequest> {
    let head = read_until_double_crlf(stream, leftover, 64 * 1024).await?;
    let mut req = http1::parse_request_head(&head)?;
    if req.is_connect() {
        // TLS ClientHello (or any bytes pipelined after CONNECT) stays in
        // leftover and is spliced after the 200. Never treat it as an HTTP body
        // or NTLM handshake will send it as request payload.
        return Ok(req);
    }
    if http1::is_chunked(&req.headers) {
        req.body = read_chunked(stream, leftover, max_body).await?;
        return Ok(req);
    }
    if let Some(len) = http1::content_length(&req.headers) {
        if len > max_body {
            return Err(Error::Http(format!(
                "request body {len} exceeds max_buffered_body {max_body}"
            )));
        }
        req.body = read_exact_from(stream, leftover, len).await?;
    }
    Ok(req)
}

pub async fn read_response_head(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
) -> Result<ServerResponse> {
    let head = read_until_double_crlf(stream, leftover, 64 * 1024).await?;
    http1::parse_response_head(&head)
}

pub async fn discard_body(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    headers: &[(String, String)],
) -> Result<()> {
    if http1::is_chunked(headers) {
        let _ = read_chunked(stream, leftover, 8 * 1024 * 1024).await?;
        return Ok(());
    }
    if let Some(len) = http1::content_length(headers) {
        let _ = read_exact_from(stream, leftover, len).await?;
    }
    Ok(())
}

pub async fn read_exact_from(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    len: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let take = leftover.len().min(len);
    out.extend_from_slice(&leftover[..take]);
    leftover.drain(..take);
    while out.len() < len {
        let mut tmp = vec![0u8; (len - out.len()).min(32 * 1024)];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::Http("unexpected eof reading body".into()));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

async fn read_chunked(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    max: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(stream, leftover).await?;
        let size_str = line
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches('\r');
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Error::Http(format!("bad chunk size {size_str:?}")))?;
        if size == 0 {
            let _ = read_line(stream, leftover).await?;
            break;
        }
        if body.len() + size > max {
            return Err(Error::Http("chunked body too large".into()));
        }
        body.extend(read_exact_from(stream, leftover, size).await?);
        let _ = read_line(stream, leftover).await?;
    }
    Ok(body)
}

async fn read_line(stream: &mut TcpStream, leftover: &mut Vec<u8>) -> Result<String> {
    loop {
        if let Some(pos) = leftover.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&leftover[..pos]).into_owned();
            leftover.drain(..pos + 2);
            return Ok(line);
        }
        let mut tmp = [0u8; 1024];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::Http("eof reading chunk line".into()));
        }
        leftover.extend_from_slice(&tmp[..n]);
        if leftover.len() > 16 * 1024 {
            return Err(Error::Http("chunk line too long".into()));
        }
    }
}

pub async fn write_all(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn splice(left: &mut TcpStream, right: &mut TcpStream) -> Result<()> {
    let _ = tokio::io::copy_bidirectional(left, right).await?;
    Ok(())
}

/// Copy `count` bytes from leftover+src to dst, then copy the rest of src if `until_close`.
pub async fn copy_fixed(
    src: &mut TcpStream,
    leftover: &mut Vec<u8>,
    dst: &mut TcpStream,
    count: usize,
) -> Result<()> {
    let take = leftover.len().min(count);
    if take > 0 {
        dst.write_all(&leftover[..take]).await?;
        leftover.drain(..take);
    }
    let mut remaining = count - take;
    let mut buf = [0u8; 32 * 1024];
    while remaining > 0 {
        let n = src.read(&mut buf[..remaining.min(32 * 1024)]).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        remaining -= n;
    }
    dst.flush().await?;
    Ok(())
}

pub async fn copy_chunked(
    src: &mut TcpStream,
    leftover: &mut Vec<u8>,
    dst: &mut TcpStream,
) -> Result<()> {
    loop {
        let line = read_line(src, leftover).await?;
        dst.write_all(line.as_bytes()).await?;
        dst.write_all(b"\r\n").await?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Error::Http(format!("bad chunk size {size_str:?}")))?;
        if size == 0 {
            // trailers
            loop {
                let t = read_line(src, leftover).await?;
                dst.write_all(t.as_bytes()).await?;
                dst.write_all(b"\r\n").await?;
                if t.is_empty() {
                    break;
                }
            }
            break;
        }
        let data = read_exact_from(src, leftover, size).await?;
        dst.write_all(&data).await?;
        let _crlf = read_line(src, leftover).await?;
        dst.write_all(b"\r\n").await?;
    }
    dst.flush().await?;
    Ok(())
}

pub async fn copy_until_close(
    src: &mut TcpStream,
    leftover: &mut Vec<u8>,
    dst: &mut TcpStream,
) -> Result<()> {
    if !leftover.is_empty() {
        dst.write_all(leftover).await?;
        leftover.clear();
    }
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
    }
    dst.flush().await?;
    Ok(())
}

pub async fn forward_body(
    src: &mut TcpStream,
    leftover: &mut Vec<u8>,
    dst: &mut TcpStream,
    headers: &[(String, String)],
) -> Result<()> {
    if http1::is_chunked(headers) {
        copy_chunked(src, leftover, dst).await
    } else if let Some(len) = http1::content_length(headers) {
        copy_fixed(src, leftover, dst, len).await
    } else {
        copy_until_close(src, leftover, dst).await
    }
}

pub async fn send_simple(stream: &mut TcpStream, status: u16, msg: &str) -> Result<()> {
    let reason = http1::status_reason(status);
    let body = format!("{msg}\n");
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_all(stream, resp.as_bytes()).await
}
