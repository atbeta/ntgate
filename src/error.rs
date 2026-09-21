use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),

    #[error("config: {0}")]
    Config(String),

    #[error("unsupported on this OS: {0}")]
    Unsupported(&'static str),

    #[error("http: {0}")]
    Http(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("upstream {host}:{port}: {message}")]
    Upstream {
        host: String,
        port: u16,
        message: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn msg(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
