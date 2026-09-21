use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use crate::auth;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::hop::Hop;
use crate::http1::{self, ClientRequest};
use crate::io;
use crate::resolve::{self, Resolver};

pub async fn run(cfg: Config) -> Result<()> {
    let addr = cfg.listen_addr()?;
    if !addr.ip().is_loopback() {
        tracing::warn!("listen {addr} is not loopback; other hosts will share your SSO session");
    }
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr} (mode={:?})", cfg.mode);
    let resolver = Arc::new(Resolver::new(cfg.clone()));
    loop {
        let (client, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(&cfg, &resolver, client).await {
                tracing::debug!("{peer}: {e}");
            }
        });
    }
}

async fn handle_client(cfg: &Config, resolver: &Resolver, mut client: TcpStream) -> Result<()> {
    let mut leftover = Vec::new();
    let req = match io::read_client_request(&mut client, &mut leftover, cfg.max_buffered_body).await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("read request: {e}");
            return Ok(());
        }
    };
    let (host, port) = match req.destination() {
        Ok(hp) => hp,
        Err(e) => {
            io::send_simple(&mut client, 400, &e.to_string()).await?;
            return Ok(());
        }
    };
    let url = resolve::url_for_destination(&host, port, req.is_connect());
    let hops = match resolver.hops_for(&url, &host) {
        Ok(h) => h,
        Err(e) => {
            io::send_simple(&mut client, 502, &e.to_string()).await?;
            return Ok(());
        }
    };
    tracing::debug!(
        "{} {} via [{}]",
        req.method,
        req.target,
        hops.iter().map(Hop::display).collect::<Vec<_>>().join(", ")
    );

    let mut last_err: Option<Error> = None;
    for hop in &hops {
        match try_hop(cfg, resolver, hop, &req, &host, port, &mut client).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!("hop {} failed: {e}", hop.display());
                resolver.mark_bad(hop);
                last_err = Some(e);
            }
        }
    }
    let msg = last_err
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no upstream proxy available".into());
    io::send_simple(&mut client, 502, &msg).await
}

async fn try_hop(
    cfg: &Config,
    _resolver: &Resolver,
    hop: &Hop,
    req: &ClientRequest,
    dest_host: &str,
    dest_port: u16,
    client: &mut TcpStream,
) -> Result<()> {
    match hop {
        Hop::Direct => {
            let mut dest = connect(dest_host, dest_port).await?;
            if req.is_connect() {
                io::write_all(client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                if !req.body.is_empty() {
                    io::write_all(&mut dest, &req.body).await?;
                }
                io::splice(client, &mut dest).await
            } else {
                let mut origin = req.clone();
                origin.target = req.origin_form_target();
                io::write_all(&mut dest, &http1::encode_request(&origin, &[], true)).await?;
                io::splice(client, &mut dest).await
            }
        }
        Hop::Http { host, port } => {
            let mut upstream = connect(host, *port).await?;
            let mut up_left = Vec::new();
            let resp =
                auth::authenticate_and_send(&mut upstream, &mut up_left, req, host, cfg.auth)
                    .await?;
            if req.is_connect() {
                if resp.status != 200 {
                    io::discard_body(&mut upstream, &mut up_left, &resp.headers).await?;
                    return Err(Error::Upstream {
                        host: host.clone(),
                        port: *port,
                        message: format!("CONNECT failed: {} {}", resp.status, resp.reason),
                    });
                }
                io::write_all(client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                if !req.body.is_empty() {
                    io::write_all(&mut upstream, &req.body).await?;
                }
                if !up_left.is_empty() {
                    io::write_all(client, &up_left).await?;
                    up_left.clear();
                }
                io::splice(client, &mut upstream).await
            } else {
                io::write_all(client, &http1::encode_response_to_client(&resp)).await?;
                io::forward_body(&mut upstream, &mut up_left, client, &resp.headers).await
            }
        }
    }
}

async fn connect(host: &str, port: u16) -> Result<TcpStream> {
    let timeout = Duration::from_secs(20);
    match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(Error::Upstream {
            host: host.into(),
            port,
            message: e.to_string(),
        }),
        Err(_) => Err(Error::Upstream {
            host: host.into(),
            port,
            message: "connect timed out".into(),
        }),
    }
}
