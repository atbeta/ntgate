#![cfg(windows)]

use std::ptr;

use windows_sys::Win32::Foundation::{FALSE, GetLastError, GlobalFree, TRUE};
use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A,
    WINHTTP_AUTOPROXY_AUTO_DETECT, WINHTTP_AUTOPROXY_CONFIG_URL, WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO, WinHttpCloseHandle,
    WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpOpen,
};

use crate::config::Mode;
use crate::error::{Error, Result};
use crate::hop::{self, Hop};

const ERROR_WINHTTP_AUTODETECTION_FAILED: u32 = 12180;

pub fn resolve(url: &str, pac: Option<&str>, mode: Mode) -> Result<Vec<Hop>> {
    match mode {
        Mode::Pac => {
            let pac = pac.ok_or_else(|| Error::Config("pac URL is empty".into()))?;
            proxy_for_url(url, Some(pac), false)
        }
        Mode::System => resolve_system(url),
        Mode::Proxy => Err(Error::msg("internal: system resolver called in proxy mode")),
    }
}

fn resolve_system(url: &str) -> Result<Vec<Hop>> {
    let ie = ie_config();
    if let Some(ref ie) = ie {
        if let Some(pac) = ie.auto_config_url.as_deref().filter(|s| !s.is_empty()) {
            match proxy_for_url(url, Some(pac), ie.auto_detect) {
                Ok(hops) => return Ok(hops),
                Err(e) => tracing::debug!("WinHttpGetProxyForUrl via IE PAC failed: {e}"),
            }
        } else if ie.auto_detect {
            match proxy_for_url(url, None, true) {
                Ok(hops) => return Ok(hops),
                Err(e) => tracing::debug!("WPAD failed: {e}"),
            }
        }
        if let Some(list) = ie.proxy.as_deref().filter(|s| !s.is_empty()) {
            return hop::parse_ie_proxy_list(list);
        }
    }
    proxy_for_url(url, None, true)
}

struct IeConfig {
    auto_detect: bool,
    auto_config_url: Option<String>,
    proxy: Option<String>,
}

fn ie_config() -> Option<IeConfig> {
    unsafe {
        let mut cfg: WINHTTP_CURRENT_USER_IE_PROXY_CONFIG = std::mem::zeroed();
        if WinHttpGetIEProxyConfigForCurrentUser(&mut cfg) == FALSE {
            return None;
        }
        let auto_config_url = pwstr_to_string(cfg.lpszAutoConfigUrl);
        let proxy = pwstr_to_string(cfg.lpszProxy);
        if !cfg.lpszAutoConfigUrl.is_null() {
            GlobalFree(cfg.lpszAutoConfigUrl as _);
        }
        if !cfg.lpszProxy.is_null() {
            GlobalFree(cfg.lpszProxy as _);
        }
        if !cfg.lpszProxyBypass.is_null() {
            GlobalFree(cfg.lpszProxyBypass as _);
        }
        Some(IeConfig {
            auto_detect: cfg.fAutoDetect == TRUE,
            auto_config_url,
            proxy,
        })
    }
}

fn proxy_for_url(url: &str, pac: Option<&str>, auto_detect: bool) -> Result<Vec<Hop>> {
    let agent = wide("cntlm-next/0.1");
    let session = unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            ptr::null(),
            ptr::null(),
            0, // synchronous
        )
    };
    if session.is_null() {
        return Err(Error::msg(format!("WinHttpOpen failed: {}", unsafe {
            GetLastError()
        })));
    }
    struct Session(*mut core::ffi::c_void);
    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                WinHttpCloseHandle(self.0);
            }
        }
    }
    let _session = Session(session);

    let pac_wide = pac.map(wide);
    let mut flags = 0u32;
    if pac_wide.is_some() {
        flags |= WINHTTP_AUTOPROXY_CONFIG_URL;
    }
    if auto_detect || pac_wide.is_none() {
        flags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
    }

    let mut opts = WINHTTP_AUTOPROXY_OPTIONS {
        dwFlags: flags,
        dwAutoDetectFlags: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
        lpszAutoConfigUrl: pac_wide.as_ref().map(|v| v.as_ptr()).unwrap_or(ptr::null()),
        lpvReserved: ptr::null_mut(),
        dwReserved: 0,
        fAutoLogonIfChallenged: TRUE,
    };

    let url_w = wide(url);
    let mut info: WINHTTP_PROXY_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe { WinHttpGetProxyForUrl(session, url_w.as_ptr(), &mut opts, &mut info) };
    if ok == FALSE {
        let err = unsafe { GetLastError() };
        if err == ERROR_WINHTTP_AUTODETECTION_FAILED && pac_wide.is_some() {
            opts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
            opts.dwAutoDetectFlags = 0;
            let ok =
                unsafe { WinHttpGetProxyForUrl(session, url_w.as_ptr(), &mut opts, &mut info) };
            if ok == FALSE {
                return Err(Error::msg(format!(
                    "WinHttpGetProxyForUrl failed: {}",
                    unsafe { GetLastError() }
                )));
            }
        } else {
            return Err(Error::msg(format!("WinHttpGetProxyForUrl failed: {err}")));
        }
    }

    let list = unsafe { pwstr_to_string(info.lpszProxy) };
    unsafe {
        if !info.lpszProxy.is_null() {
            GlobalFree(info.lpszProxy as _);
        }
        if !info.lpszProxyBypass.is_null() {
            GlobalFree(info.lpszProxyBypass as _);
        }
    }
    match list {
        Some(s) => hop::parse_ie_proxy_list(&s),
        None => Ok(vec![Hop::Direct]),
    }
}

unsafe fn pwstr_to_string(ptr: windows_sys::core::PWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
        if s.is_empty() { None } else { Some(s) }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
