use tokio::net::TcpStream;

use crate::config::AuthMode;
use crate::error::{Error, Result};
use crate::http1::{self, ClientRequest, ServerResponse};
use crate::io;

pub async fn authenticate_and_send(
    upstream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    req: &ClientRequest,
    proxy_host: &str,
    auth_mode: AuthMode,
) -> Result<ServerResponse> {
    let mut extra: Vec<(String, String)> = vec![
        ("Proxy-Connection".into(), "Keep-Alive".into()),
        ("Connection".into(), "Keep-Alive".into()),
    ];

    io::write_all(
        upstream,
        &http1::encode_request(
            req,
            &extra
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            req.is_connect() || req.body.is_empty(),
        ),
    )
    .await?;

    let mut resp = io::read_response_head(upstream, leftover).await?;
    if resp.status != 407 {
        return Ok(resp);
    }

    io::discard_body(upstream, leftover, &resp.headers).await?;

    let challenges = http1::proxy_authenticate(&resp.headers);
    let (scheme, initial_token) = http1::pick_proxy_auth(&challenges).ok_or_else(|| {
        Error::Auth(format!(
            "407 without NTLM/Negotiate (headers={:?})",
            challenges
        ))
    })?;

    let scheme = match auth_mode {
        AuthMode::Negotiate => "Negotiate".to_string(),
        AuthMode::Ntlm => "NTLM".to_string(),
        AuthMode::Auto => scheme,
    };

    let mut session = backend::create(proxy_host, &scheme)?;
    // Some proxies put a token on the first 407; feed it if present.
    if let Some(tok) = initial_token.as_deref()
        && !tok.is_empty()
        && session.needs_challenge()
    {
        // first 407 with empty token is normal for NTLM type1
        let _ = tok;
    }

    for round in 0..6 {
        let challenge = if round == 0 {
            None
        } else {
            http1::pick_proxy_auth(&http1::proxy_authenticate(&resp.headers)).and_then(|(_, t)| t)
        };
        let token = session.step(challenge.as_deref())?;
        extra.retain(|(k, _)| !k.eq_ignore_ascii_case("proxy-authorization"));
        extra.push(("Proxy-Authorization".into(), format!("{scheme} {token}")));
        let include_body = req.is_connect() || session.is_complete() || req.body.is_empty();
        io::write_all(
            upstream,
            &http1::encode_request(
                req,
                &extra
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
                include_body,
            ),
        )
        .await?;
        resp = io::read_response_head(upstream, leftover).await?;
        if resp.status != 407 {
            return Ok(resp);
        }
        io::discard_body(upstream, leftover, &resp.headers).await?;
        if http1::connection_close(&resp.headers) {
            return Err(Error::Auth(
                "proxy closed the connection during NTLM handshake".into(),
            ));
        }
    }
    Err(Error::Auth(
        "NTLM/Negotiate handshake exceeded 6 rounds".into(),
    ))
}

pub trait AuthSession {
    fn step(&mut self, challenge_b64: Option<&str>) -> Result<String>;
    fn is_complete(&self) -> bool;
    fn needs_challenge(&self) -> bool {
        false
    }
}

pub mod backend {
    use super::AuthSession;
    #[cfg(not(windows))]
    use crate::error::Error;
    use crate::error::Result;

    pub fn create(proxy_host: &str, scheme: &str) -> Result<Box<dyn AuthSession + Send>> {
        #[cfg(windows)]
        {
            Ok(Box::new(crate::auth::sspi::SspiSession::new(
                proxy_host, scheme,
            )?))
        }
        #[cfg(not(windows))]
        {
            let _ = (proxy_host, scheme);
            Err(Error::Unsupported(
                "SSPI current-user auth is only available on Windows",
            ))
        }
    }
}
