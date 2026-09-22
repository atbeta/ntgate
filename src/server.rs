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
            if let Err(e) = handle_client(&cfg, resolver, client).await {
                tracing::debug!("{peer}: {e}");
            }
        });
    }
}

async fn handle_client(cfg: &Config, resolver: Arc<Resolver>, mut client: TcpStream) -> Result<()> {
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
    let hops = {
        let resolver = resolver.clone();
        let url = url.clone();
        let host = host.clone();
        match tokio::task::spawn_blocking(move || resolver.hops_for(&url, &host)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                io::send_simple(&mut client, 502, &e.to_string()).await?;
                return Ok(());
            }
            Err(e) => {
                io::send_simple(&mut client, 502, &format!("resolver task: {e}")).await?;
                return Ok(());
            }
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
        match try_hop(cfg, hop, &req, &host, port, &mut client, &mut leftover).await {
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
    hop: &Hop,
    req: &ClientRequest,
    dest_host: &str,
    dest_port: u16,
    client: &mut TcpStream,
    leftover: &mut Vec<u8>,
) -> Result<()> {
    match hop {
        Hop::Direct => {
            let mut dest = connect(dest_host, dest_port).await?;
            if req.is_connect() {
                io::write_all(client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                flush_preface(&mut dest, leftover).await?;
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
                flush_preface(&mut upstream, leftover).await?;
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

async fn flush_preface(dest: &mut TcpStream, leftover: &mut Vec<u8>) -> Result<()> {
    if leftover.is_empty() {
        return Ok(());
    }
    io::write_all(dest, leftover).await?;
    leftover.clear();
    Ok(())
}

async fn connect(host: &str, port: u16) -> Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let host_s = host.to_string();
    let std_stream = tokio::task::spawn_blocking(move || -> std::io::Result<std::net::TcpStream> {
        let addr = (&*host_s, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addresses to connect to")
            })?;
        std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(20))
    })
    .await
    .map_err(|e| Error::Upstream {
        host: host.into(),
        port,
        message: format!("connect join: {e}"),
    })?
    .map_err(|e| Error::Upstream {
        host: host.into(),
        port,
        message: format!("{e} [raw_os_error={:?}]", e.raw_os_error()),
    })?;
    std_stream
        .set_nonblocking(true)
        .map_err(|e| Error::Upstream {
            host: host.into(),
            port,
            message: format!("set_nonblocking: {e}"),
        })?;
    let _ = std_stream.set_nodelay(true);
    TcpStream::from_std(std_stream).map_err(|e| Error::Upstream {
        host: host.into(),
        port,
        message: e.to_string(),
    })
}
