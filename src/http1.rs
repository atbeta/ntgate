use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct HttpHead {
    pub first_line: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ClientRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ClientRequest {
    pub fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// Destination host and port for PAC / noproxy / CONNECT.
    pub fn destination(&self) -> Result<(String, u16)> {
        if self.is_connect() {
            return crate::config::parse_host_port(&self.target).map_err(Error::Http);
        }
        if let Some(rest) = self
            .target
            .strip_prefix("http://")
            .or_else(|| self.target.strip_prefix("https://"))
        {
            let (authority, _) = rest.split_once('/').unwrap_or((rest, ""));
            if authority.contains(':') {
                return crate::config::parse_host_port(authority).map_err(Error::Http);
            }
            let default = if self.target.starts_with("https://") {
                443
            } else {
                80
            };
            return Ok((authority.to_string(), default));
        }
        let host = self
            .header("host")
            .ok_or_else(|| Error::Http("missing Host header".into()))?;
        if host.contains(':') {
            crate::config::parse_host_port(host).map_err(Error::Http)
        } else {
            Ok((host.to_string(), 80))
        }
    }

    pub fn origin_form_target(&self) -> String {
        if self.is_connect() {
            return self.target.clone();
        }
        if let Some(rest) = self.target.strip_prefix("http://") {
            if let Some((_, path)) = rest.split_once('/') {
                return format!("/{path}");
            }
            return "/".into();
        }
        self.target.clone()
    }
}

#[derive(Debug, Clone)]
pub struct ServerResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

pub fn parse_request_head(raw: &[u8]) -> Result<ClientRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(raw) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(Error::Http("incomplete request head".into()));
        }
        Err(e) => return Err(Error::Http(format!("request parse: {e}"))),
    }
    let method = req
        .method
        .ok_or_else(|| Error::Http("missing method".into()))?
        .to_string();
    let target = req
        .path
        .ok_or_else(|| Error::Http("missing target".into()))?
        .to_string();
    let version = match req.version {
        Some(1) => "HTTP/1.1",
        Some(0) => "HTTP/1.0",
        _ => "HTTP/1.1",
    }
    .to_string();
    Ok(ClientRequest {
        method,
        target,
        version,
        headers: owned_headers(req.headers),
        body: Vec::new(),
    })
}

pub fn parse_response_head(raw: &[u8]) -> Result<ServerResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);
    match res.parse(raw) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(Error::Http("incomplete response head".into()));
        }
        Err(e) => return Err(Error::Http(format!("response parse: {e}"))),
    }
    Ok(ServerResponse {
        version: match res.version {
            Some(1) => "HTTP/1.1".into(),
            Some(0) => "HTTP/1.0".into(),
            _ => "HTTP/1.1".into(),
        },
        status: res
            .code
            .ok_or_else(|| Error::Http("missing status".into()))?,
        reason: res.reason.unwrap_or("").to_string(),
        headers: owned_headers(res.headers),
    })
}

fn owned_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

pub fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn content_length(headers: &[(String, String)]) -> Option<usize> {
    find_header(headers, "content-length")?.parse().ok()
}

pub fn is_chunked(headers: &[(String, String)]) -> bool {
    find_header(headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
}

pub fn connection_close(headers: &[(String, String)]) -> bool {
    find_header(headers, "connection").is_some_and(|v| {
        v.to_ascii_lowercase()
            .split(',')
            .any(|p| p.trim() == "close")
    })
}

pub fn proxy_authenticate(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("proxy-authenticate"))
        .map(|(_, v)| v.clone())
        .collect()
}

/// Pick Negotiate over NTLM over Basic. Returns (scheme, optional b64 token).
pub fn pick_proxy_auth(challenges: &[String]) -> Option<(String, Option<String>)> {
    let mut best: Option<(u8, String, Option<String>)> = None;
    for raw in challenges {
        let mut parts = raw.split_whitespace();
        let scheme = parts.next()?.to_string();
        let token = parts.next().map(ToString::to_string);
        let rank = match scheme.to_ascii_lowercase().as_str() {
            "negotiate" => 3,
            "ntlm" => 2,
            "basic" => 1,
            _ => 0,
        };
        if rank == 0 {
            continue;
        }
        if best.as_ref().is_none_or(|(r, _, _)| rank > *r) {
            best = Some((rank, scheme, token));
        }
    }
    best.map(|(_, s, t)| (s, t))
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

pub fn encode_request(req: &ClientRequest, extra: &[(&str, &str)], include_body: bool) -> Vec<u8> {
    let mut out = format!("{} {} {}\r\n", req.method, req.target, req.version).into_bytes();
    for (k, v) in &req.headers {
        if is_hop_by_hop(k) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (k, v) in extra {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let body = if include_body { &req.body } else { &[][..] };
    if !include_body && !req.body.is_empty() {
        out.extend_from_slice(b"Content-Length: 0\r\n");
    } else if find_header(&req.headers, "content-length").is_none() && !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Forward an upstream response to the client, keeping body framing headers.
pub fn encode_response_to_client(res: &ServerResponse) -> Vec<u8> {
    let reason = if res.reason.is_empty() {
        status_reason(res.status)
    } else {
        res.reason.as_str()
    };
    let mut out = format!("{} {} {}\r\n", res.version, res.status, reason).into_bytes();
    for (k, v) in &res.headers {
        if k.eq_ignore_ascii_case("proxy-authenticate")
            || k.eq_ignore_ascii_case("proxy-authorization")
            || k.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

pub fn encode_response(res: &ServerResponse, extra: &[(&str, &str)]) -> Vec<u8> {
    let reason = if res.reason.is_empty() {
        status_reason(res.status)
    } else {
        res.reason.as_str()
    };
    let mut out = format!("{} {} {}\r\n", res.version, res.status, reason).into_bytes();
    for (k, v) in &res.headers {
        if is_hop_by_hop(k) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (k, v) in extra {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

pub fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        407 => "Proxy Authentication Required",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect() {
        let raw = b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n";
        let req = parse_request_head(raw).unwrap();
        assert!(req.is_connect());
        assert_eq!(req.destination().unwrap(), ("github.com".into(), 443));
    }

    #[test]
    fn parse_absolute_get() {
        let raw = b"GET http://example.com/foo HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
        let req = parse_request_head(raw).unwrap();
        assert_eq!(req.destination().unwrap(), ("example.com".into(), 80));
        assert_eq!(req.origin_form_target(), "/foo");
    }

    #[test]
    fn pick_negotiate() {
        let ch = vec!["NTLM".into(), "Negotiate aaaa".into()];
        let (scheme, token) = pick_proxy_auth(&ch).unwrap();
        assert_eq!(scheme, "Negotiate");
        assert_eq!(token.as_deref(), Some("aaaa"));
    }
}
