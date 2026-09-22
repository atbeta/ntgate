//! Local HTTP proxy facade for corporate NTLM/Negotiate proxies.
//!
//! Behavior follows Winfoom (current-user SSO, PAC/system/static upstream,
//! CONNECT + HTTP forwarding). Delivery is a single Windows binary with a
//! config file and optional logon-time service.

pub mod auth;
pub mod config;
mod dial;
pub mod doctor;
pub mod error;
pub mod hop;
pub mod http1;
pub mod io;
pub mod noproxy;
pub mod resolve;
pub mod server;
pub mod service;

pub use config::{Config, Mode};
pub use error::Error;
