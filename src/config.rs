use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Follow the current user's WinHTTP / IE proxy settings (PAC, WPAD, or static).
    #[default]
    System,
    /// Evaluate an explicit PAC URL or file path.
    Pac,
    /// Always use `upstream`.
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Auto,
    Negotiate,
    Ntlm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: String,
    pub mode: Mode,
    /// `host:port` for `mode = "proxy"`.
    pub upstream: Option<String>,
    /// PAC URL (`http://...`) or filesystem path for `mode = "pac"`.
    pub pac: Option<String>,
    pub auth: AuthMode,
    pub noproxy: Vec<String>,
    pub test_url: String,
    /// Minutes to skip a PAC-selected proxy after connect/auth failure.
    pub blacklist_timeout: u64,
    /// Max buffered request body during NTLM handshake (bytes).
    pub max_buffered_body: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3128".into(),
            mode: Mode::System,
            upstream: None,
            pac: None,
            auth: AuthMode::Auto,
            noproxy: vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "::1".into(),
                "10.0.0.0/8".into(),
                "192.168.0.0/16".into(),
                "172.16.0.0/12".into(),
            ],
            test_url: "https://example.com".into(),
            blacklist_timeout: 30,
            max_buffered_body: 1_048_576,
        }
    }
}

impl Config {
    pub fn load_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let cfg: Self = toml::from_str(&raw)
            .map_err(|e| Error::Config(format!("invalid TOML in {}: {e}", path.display())))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        self.listen_addr()?;
        match self.mode {
            Mode::Proxy => {
                let up = self.upstream.as_deref().ok_or_else(|| {
                    Error::Config("mode=proxy requires upstream = \"host:port\"".into())
                })?;
                parse_host_port(up).map_err(Error::Config)?;
            }
            Mode::Pac => {
                if self.pac.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(Error::Config(
                        "mode=pac requires pac = \"http://...\" or a file path".into(),
                    ));
                }
            }
            Mode::System => {}
        }
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen
            .parse()
            .map_err(|e| Error::Config(format!("invalid listen {}: {e}", self.listen)))
    }

    pub fn upstream_addr(&self) -> Result<(String, u16)> {
        let up = self
            .upstream
            .as_deref()
            .ok_or_else(|| Error::Config("upstream is not set".into()))?;
        parse_host_port(up).map_err(Error::Config)
    }
}

pub fn parse_host_port(input: &str) -> std::result::Result<(String, u16), String> {
    let input = input.trim();
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Some((host, port)) = input.rsplit_once(':')
        && !host.is_empty()
        && !host.starts_with('[')
        && let Ok(port) = port.parse::<u16>()
    {
        return Ok((host.trim_matches(['[', ']']).to_string(), port));
    }
    Err(format!("expected host:port, got {input:?}"))
}

pub fn default_config_path() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("dev", "cntlm-next", "cntlm-next") {
        return dirs.data_local_dir().join("config.toml");
    }
    PathBuf::from("config.toml")
}

pub fn default_log_path() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("dev", "cntlm-next", "cntlm-next") {
        return dirs.data_local_dir().join("cntlm-next.log");
    }
    PathBuf::from("cntlm-next.log")
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn write_example_if_missing(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    ensure_parent(path)?;
    std::fs::write(path, include_str!("../config.example.toml"))?;
    Ok(true)
}

pub fn looks_like_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_ok() {
        assert_eq!(
            parse_host_port("proxy.xxx.com:8080").unwrap(),
            ("proxy.xxx.com".into(), 8080)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:3128").unwrap(),
            ("127.0.0.1".into(), 3128)
        );
    }

    #[test]
    fn default_config_roundtrip() {
        let cfg = Config::default();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:3128");
        assert_eq!(parsed.mode, Mode::System);
    }

    #[test]
    fn proxy_mode_requires_upstream() {
        let cfg = Config {
            mode: Mode::Proxy,
            upstream: None,
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }
}
