use tokio::net::TcpStream;

use crate::auth;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::hop::Hop;
use crate::http1::{self, ClientRequest};
use crate::resolve::{self, Resolver};

pub async fn run(cfg: &Config) -> Result<()> {
    println!("listen      {}", cfg.listen);
    println!("mode        {:?}", cfg.mode);
    println!("test_url    {}", cfg.test_url);
    println!("auth        {:?}", cfg.auth);

    let resolver = Resolver::new(cfg.clone());
    let dest = dest_from_test_url(&cfg.test_url)?;
    println!("target      {}:{}", dest.0, dest.1);

    let url = resolve::url_for_destination(&dest.0, dest.1, dest.1 == 443);
    let hops = resolver.hops_for(&url, &dest.0)?;
    println!(
        "hops        {}",
        hops.iter()
            .map(Hop::display)
            .collect::<Vec<_>>()
            .join(" -> ")
    );

    let mut last = None;
    for hop in &hops {
        match probe(cfg, hop, &dest).await {
            Ok(msg) => {
                println!("ok          {msg}");
                return Ok(());
            }
            Err(e) => {
                println!("fail        {} ({e})", hop.display());
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::msg("no hop succeeded")))
}

fn dest_from_test_url(url: &str) -> Result<(String, u16)> {
    let url = url.trim();
    if let Some(rest) = url.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or(rest);
        if host.contains(':') {
            crate::config::parse_host_port(host).map_err(Error::Config)
        } else {
            Ok((host.to_string(), 443))
        }
    } else if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or(rest);
        if host.contains(':') {
            crate::config::parse_host_port(host).map_err(Error::Config)
        } else {
            Ok((host.to_string(), 80))
        }
    } else {
        Err(Error::Config(format!(
            "test_url must be http(s)://... ({url})"
        )))
    }
}

async fn probe(cfg: &Config, hop: &Hop, dest: &(String, u16)) -> Result<String> {
    match hop {
        Hop::Direct => {
            let _ = connect(&dest.0, dest.1).await?;
            Ok(format!("direct TCP {}:{}", dest.0, dest.1))
        }
        Hop::Http { host, port } => {
            let mut up = connect(host, *port).await?;
            let mut leftover = Vec::new();
            let req = if dest.1 == 443 {
                ClientRequest {
                    method: "CONNECT".into(),
                    target: format!("{}:{}", dest.0, dest.1),
                    version: "HTTP/1.1".into(),
                    headers: vec![("Host".into(), format!("{}:{}", dest.0, dest.1))],
                    body: Vec::new(),
                }
            } else {
                ClientRequest {
                    method: "GET".into(),
                    target: cfg.test_url.clone(),
                    version: "HTTP/1.1".into(),
                    headers: vec![
                        ("Host".into(), dest.0.clone()),
                        ("User-Agent".into(), "cntlm-next/0.1".into()),
                    ],
                    body: Vec::new(),
                }
            };
            let resp =
                auth::authenticate_and_send(&mut up, &mut leftover, &req, host, cfg.auth).await?;
            if resp.status >= 200 && resp.status < 400 {
                Ok(format!(
                    "{}:{} -> HTTP {} {}",
                    host, port, resp.status, resp.reason
                ))
            } else if resp.status == 407 {
                Err(Error::Auth(format!(
                    "still 407 after handshake ({})",
                    http1::proxy_authenticate(&resp.headers).join(", ")
                )))
            } else {
                Err(Error::Upstream {
                    host: host.clone(),
                    port: *port,
                    message: format!("{} {}", resp.status, resp.reason),
                })
            }
        }
    }
}

async fn connect(host: &str, port: u16) -> Result<TcpStream> {
    TcpStream::connect((host, port))
        .await
        .map_err(|e| Error::Upstream {
            host: host.into(),
            port,
            message: e.to_string(),
        })
}
