#![cfg(windows)]

use std::ptr;

use base64::Engine;
use windows_sys::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle,
    ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_CONNECTION, ISC_REQ_REPLAY_DETECT,
    InitializeSecurityContextW, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND,
    SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
};
use windows_sys::Win32::Security::Credentials::SecHandle;

use super::handshake::AuthSession;
use crate::error::{Error, Result};

const SEC_E_OK: i32 = 0;
const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312;
const SEC_I_COMPLETE_NEEDED: i32 = 0x0009_0313;
const SEC_I_COMPLETE_AND_CONTINUE: i32 = 0x0009_0314;

pub struct SspiSession {
    cred: SecHandle,
    ctx: SecHandle,
    have_ctx: bool,
    complete: bool,
    target: Vec<u16>,
}

impl SspiSession {
    pub fn new(proxy_host: &str, scheme: &str) -> Result<Self> {
        let package = match scheme.to_ascii_lowercase().as_str() {
            "ntlm" => wide("NTLM"),
            _ => wide("Negotiate"),
        };
        let target = wide(&format!("HTTP/{proxy_host}"));
        let mut cred = empty_handle();
        let mut expiry: i64 = 0;
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                package.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                ptr::null(),
                ptr::null(),
                None,
                ptr::null(),
                &mut cred,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(Error::Auth(format!(
                "AcquireCredentialsHandleW failed: 0x{status:08X} (not logged into a domain session?)"
            )));
        }
        Ok(Self {
            cred,
            ctx: empty_handle(),
            have_ctx: false,
            complete: false,
            target,
        })
    }
}

impl AuthSession for SspiSession {
    fn step(&mut self, challenge_b64: Option<&str>) -> Result<String> {
        let challenge = match challenge_b64 {
            Some(t) if !t.is_empty() => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(t.trim())
                    .map_err(|e| Error::Auth(format!("invalid Negotiate token: {e}")))?,
            ),
            _ => None,
        };

        let mut in_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 0,
            pBuffers: ptr::null_mut(),
        };
        if let Some(ref data) = challenge {
            in_buf.cbBuffer = data.len() as u32;
            in_buf.pvBuffer = data.as_ptr() as *mut _;
            in_desc.cBuffers = 1;
            in_desc.pBuffers = &mut in_buf;
        }

        let mut out_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };

        let flags = ISC_REQ_ALLOCATE_MEMORY
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_CONNECTION
            | ISC_REQ_REPLAY_DETECT;
        let mut attrs: u32 = 0;
        let mut expiry: i64 = 0;

        let ph_ctx = if self.have_ctx {
            &self.ctx as *const SecHandle
        } else {
            ptr::null()
        };

        let status = unsafe {
            InitializeSecurityContextW(
                &self.cred,
                ph_ctx,
                self.target.as_ptr(),
                flags,
                0,
                SECURITY_NATIVE_DREP,
                if challenge.is_some() {
                    &in_desc
                } else {
                    ptr::null()
                },
                0,
                &mut self.ctx,
                &mut out_desc,
                &mut attrs,
                &mut expiry,
            )
        };

        self.have_ctx = true;
        match status {
            SEC_E_OK | SEC_I_COMPLETE_NEEDED => self.complete = true,
            SEC_I_CONTINUE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => self.complete = false,
            other => {
                return Err(Error::Auth(format!(
                    "InitializeSecurityContextW failed: 0x{other:08X}"
                )));
            }
        }

        if out_buf.pvBuffer.is_null() || out_buf.cbBuffer == 0 {
            if self.complete {
                return Ok(String::new());
            }
            return Err(Error::Auth("SSPI produced an empty token".into()));
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize)
        };
        let token = base64::engine::general_purpose::STANDARD.encode(bytes);
        unsafe {
            FreeContextBuffer(out_buf.pvBuffer);
        }
        Ok(token)
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

impl Drop for SspiSession {
    fn drop(&mut self) {
        unsafe {
            if self.have_ctx {
                DeleteSecurityContext(&self.ctx);
            }
            FreeCredentialsHandle(&self.cred);
        }
    }
}

fn empty_handle() -> SecHandle {
    SecHandle {
        dwLower: 0,
        dwUpper: 0,
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
