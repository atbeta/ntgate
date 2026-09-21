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
        let mut cfg: Self = toml::from_str(&raw)
            .map_err(|e| Error::Config(format!("invalid TOML in {}: {e}", path.display())))?;
        if matches!(cfg.mode, Mode::Pac)
            && let Some(pac) = cfg.pac.as_deref()
        {
            let base = path.parent();
            if let Some(fs) = local_pac_path(pac, base)
                && !fs.is_file()
            {
                return Err(Error::Config(format!(
                    "PAC file not found: {}",
                    fs.display()
                )));
            }
            cfg.pac = Some(normalize_pac_url(pac, base)?);
        }
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

/// Turn a PAC location into the URL WinHTTP expects (`http(s)://` or `file://`).
/// Relative paths are resolved against `base_dir` (the config file's directory).
pub fn normalize_pac_url(pac: &str, base_dir: Option<&Path>) -> Result<String> {
    let pac = pac.trim();
    if pac.is_empty() {
        return Err(Error::Config("pac is empty".into()));
    }
    if is_pac_remote_or_file_url(pac) {
        return Ok(pac.to_string());
    }
    let path = local_pac_path(pac, base_dir)
        .ok_or_else(|| Error::Config(format!("cannot resolve PAC path {pac:?}")))?;
    Ok(path_to_file_url(&path))
}

fn is_pac_remote_or_file_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("file:")
}

fn is_windows_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn is_unc_path(s: &str) -> bool {
    s.starts_with("\\\\")
}

fn local_pac_path(pac: &str, base_dir: Option<&Path>) -> Option<PathBuf> {
    let pac = pac.trim();
    if pac.is_empty() || is_pac_remote_or_file_url(pac) {
        return None;
    }
    if is_windows_drive_path(pac) || is_unc_path(pac) {
        return Some(PathBuf::from(pac));
    }
    let p = Path::new(pac);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    if let Some(base) = base_dir {
        return Some(base.join(p));
    }
    Some(
        std::env::current_dir()
            .ok()
            .map(|d| d.join(p))
            .unwrap_or_else(|| p.to_path_buf()),
    )
}

fn path_to_file_url(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    let encoded = encode_file_url_path(&raw);
    if let Some(rest) = encoded.strip_prefix("//") {
        format!("file://{rest}")
    } else if encoded.starts_with('/') {
        format!("file://{encoded}")
    } else {
        format!("file:///{encoded}")
    }
}

fn encode_file_url_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            '%' => out.push_str("%25"),
            '#' => out.push_str("%23"),
            _ => out.push(c),
        }
    }
    out
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
    if let Some(dirs) = directories::ProjectDirs::from("dev", "ntgate", "ntgate") {
        return dirs.data_local_dir().join("config.toml");
    }
    PathBuf::from("config.toml")
}

pub fn default_log_path() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("dev", "ntgate", "ntgate") {
        return dirs.data_local_dir().join("ntgate.log");
    }
    PathBuf::from("ntgate.log")
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

    #[test]
    fn pac_http_url_unchanged() {
        assert_eq!(
            normalize_pac_url("http://pac.xxx.com/proxy.pac", None).unwrap(),
            "http://pac.xxx.com/proxy.pac"
        );
    }

    #[test]
    fn pac_windows_path_becomes_file_url() {
        assert_eq!(
            normalize_pac_url(r"C:\Users\a\proxy.pac", None).unwrap(),
            "file:///C:/Users/a/proxy.pac"
        );
        assert_eq!(
            normalize_pac_url(r"C:\Users\a\my pac.pac", None).unwrap(),
            "file:///C:/Users/a/my%20pac.pac"
        );
        assert_eq!(
            normalize_pac_url(r"\\files\pac\proxy.pac", None).unwrap(),
            "file://files/pac/proxy.pac"
        );
    }

    #[test]
    fn pac_relative_uses_config_dir() {
        assert_eq!(
            normalize_pac_url("proxy.pac", Some(Path::new(r"D:\cfg"))).unwrap(),
            "file:///D:/cfg/proxy.pac"
        );
    }

    #[test]
    fn load_relative_pac_file() {
        let dir = std::env::temp_dir().join(format!("ntgate-pac-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("proxy.pac"),
            "function FindProxyForURL(){return \"DIRECT\";}\n",
        )
        .unwrap();
        let cfg_path = dir.join("config.toml");
        std::fs::write(
            &cfg_path,
            "mode = \"pac\"\npac = \"proxy.pac\"\nlisten = \"127.0.0.1:3128\"\n",
        )
        .unwrap();
        let cfg = Config::load_path(&cfg_path).unwrap();
        let pac = cfg.pac.expect("pac");
        assert!(pac.starts_with("file://"), "{pac}");
        assert!(
            pac.ends_with("/proxy.pac") || pac.ends_with("proxy.pac"),
            "{pac}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_pac_file_errors() {
        let dir = std::env::temp_dir().join(format!("ntgate-pac-missing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.toml");
        std::fs::write(
            &cfg_path,
            "mode = \"pac\"\npac = \"no-such.pac\"\nlisten = \"127.0.0.1:3128\"\n",
        )
        .unwrap();
        let err = Config::load_path(&cfg_path).unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
