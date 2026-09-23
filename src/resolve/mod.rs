use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{Config, Mode};
#[cfg(not(windows))]
use crate::error::Error;
use crate::error::Result;
use crate::hop::{self, Hop};
use crate::noproxy;

#[cfg(windows)]
mod winhttp;

pub struct Resolver {
    cfg: Config,
    cache: Mutex<HashMap<String, CacheEnt>>,
    blacklist: Mutex<HashMap<String, Instant>>,
}

struct CacheEnt {
    hops: Vec<Hop>,
    until: Instant,
}

impl Resolver {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            cache: Mutex::new(HashMap::new()),
            blacklist: Mutex::new(HashMap::new()),
        }
    }

    pub fn invalidate(&self) {
        self.cache.lock().unwrap().clear();
    }

    pub fn mark_bad(&self, hop: &Hop) {
        if let Hop::Http { host, port } = hop {
            let until = Instant::now() + Duration::from_secs(self.cfg.blacklist_timeout * 60);
            self.blacklist
                .lock()
                .unwrap()
                .insert(format!("{host}:{port}"), until);
        }
    }

    pub fn hops_for(&self, url: &str, host: &str) -> Result<Vec<Hop>> {
        if noproxy::matches(host, &self.cfg.noproxy) {
            return Ok(vec![Hop::Direct]);
        }
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(ent) = cache.get(host)
                && ent.until > Instant::now()
            {
                return Ok(self.filter_blacklist(&ent.hops));
            }
            cache.retain(|_, e| e.until > Instant::now());
        }

        let hops = match self.cfg.mode {
            Mode::Proxy => {
                let (h, p) = self.cfg.upstream_addr()?;
                vec![Hop::Http { host: h, port: p }]
            }
            Mode::Pac | Mode::System => self.lookup_system_or_pac(url)?,
        };

        self.cache.lock().unwrap().insert(
            host.to_string(),
            CacheEnt {
                hops: hops.clone(),
                until: Instant::now() + Duration::from_secs(60),
            },
        );
        Ok(self.filter_blacklist(&hops))
    }

    fn filter_blacklist(&self, hops: &[Hop]) -> Vec<Hop> {
        let now = Instant::now();
        let bl = self.blacklist.lock().unwrap();
        let filtered: Vec<Hop> = hops
            .iter()
            .filter(|hop| match hop {
                Hop::Direct => true,
                Hop::Http { host, port } => bl
                    .get(&format!("{host}:{port}"))
                    .is_none_or(|until| *until <= now),
            })
            .cloned()
            .collect();
        if filtered.is_empty() {
            hops.to_vec()
        } else {
            filtered
        }
    }

    fn lookup_system_or_pac(&self, url: &str) -> Result<Vec<Hop>> {
        #[cfg(windows)]
        {
            let pac = match self.cfg.mode {
                Mode::Pac => self.cfg.pac.clone(),
                Mode::System => None,
                Mode::Proxy => None,
            };
            winhttp::resolve(url, pac.as_deref(), self.cfg.mode)
        }
        #[cfg(not(windows))]
        {
            let _ = url;
            Err(Error::Unsupported(
                "mode=system and mode=pac require Windows WinHTTP",
            ))
        }
    }
}

pub fn url_for_destination(host: &str, port: u16, connect: bool) -> String {
    if connect || port == 443 {
        format!("https://{host}/")
    } else if port == 80 {
        format!("http://{host}/")
    } else {
        format!("http://{host}:{port}/")
    }
}

/// Used by doctor when we only have a static hop list string.
pub fn hops_from_raw(raw: &str) -> Result<Vec<Hop>> {
    hop::parse_pac_result(raw).or_else(|_| hop::parse_ie_proxy_list(raw))
}
