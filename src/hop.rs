//! PAC / IE proxy-list parsers. Evaluation of PAC JS on Windows is in `resolve`.

use crate::config::parse_host_port;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hop {
    Direct,
    Http { host: String, port: u16 },
}

impl Hop {
    pub fn display(&self) -> String {
        match self {
            Hop::Direct => "DIRECT".into(),
            Hop::Http { host, port } => format!("{host}:{port}"),
        }
    }
}

/// Parse a PAC `FindProxyForURL` result, e.g. `PROXY a:8080; PROXY b:8080; DIRECT`.
pub fn parse_pac_result(raw: &str) -> Result<Vec<Hop>> {
    let mut hops = Vec::new();
    for token in raw.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (kind, rest) = token
            .split_once(char::is_whitespace)
            .map(|(k, r)| (k, r.trim()))
            .unwrap_or((token, ""));
        match kind.to_ascii_uppercase().as_str() {
            "DIRECT" => hops.push(Hop::Direct),
            "PROXY" | "HTTP" | "HTTPS" => {
                hops.push(http_hop(rest)?);
            }
            "SOCKS" | "SOCKS4" | "SOCKS5" => {
                tracing::debug!("skipping SOCKS hop from PAC: {token}");
            }
            other => {
                // IE-style `host:port` without a keyword.
                if other.contains(':') || rest.contains(':') {
                    let spec = if rest.is_empty() { token } else { rest };
                    hops.push(http_hop(spec)?);
                } else {
                    return Err(Error::Http(format!("unknown PAC token {token:?}")));
                }
            }
        }
    }
    if hops.is_empty() {
        hops.push(Hop::Direct);
    }
    Ok(hops)
}

/// Parse WinHTTP / IE `lpszProxy` values such as `proxy:8080` or
/// `http=proxy:8080;https=proxy:8080`.
pub fn parse_ie_proxy_list(raw: &str) -> Result<Vec<Hop>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(vec![Hop::Direct]);
    }
    if raw.to_ascii_uppercase().contains("DIRECT") || raw.to_ascii_uppercase().contains("PROXY ") {
        return parse_pac_result(raw);
    }
    let mut hops = Vec::new();
    for part in raw.split([';', ' ', '\t']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let spec = part.split_once('=').map(|(_, v)| v.trim()).unwrap_or(part);
        if spec.is_empty() {
            continue;
        }
        hops.push(http_hop(spec)?);
    }
    if hops.is_empty() {
        hops.push(Hop::Direct);
    }
    Ok(hops)
}

fn http_hop(spec: &str) -> Result<Hop> {
    let spec = spec
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (host, port) = parse_host_port(spec).or_else(|_| {
        if spec.contains(':') {
            Err(Error::Http(format!("invalid proxy address {spec:?}")))
        } else {
            Ok((spec.to_string(), 80))
        }
    })?;
    Ok(Hop::Http { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_failover_list() {
        let hops = parse_pac_result("PROXY proxy.xxx.com:8080; PROXY backup:8080; DIRECT").unwrap();
        assert_eq!(
            hops,
            vec![
                Hop::Http {
                    host: "proxy.xxx.com".into(),
                    port: 8080
                },
                Hop::Http {
                    host: "backup".into(),
                    port: 8080
                },
                Hop::Direct
            ]
        );
    }

    #[test]
    fn ie_scheme_map() {
        let hops = parse_ie_proxy_list("http=proxy.xxx.com:8080;https=proxy.xxx.com:8080").unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].display(), "proxy.xxx.com:8080");
    }

    #[test]
    fn socks_is_skipped() {
        let hops = parse_pac_result("SOCKS 127.0.0.1:1080; PROXY p:8080").unwrap();
        assert_eq!(
            hops,
            vec![Hop::Http {
                host: "p".into(),
                port: 8080
            }]
        );
    }
}
