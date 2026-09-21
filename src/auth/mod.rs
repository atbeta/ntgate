mod handshake;

#[cfg(windows)]
mod sspi;

pub use handshake::authenticate_and_send;
