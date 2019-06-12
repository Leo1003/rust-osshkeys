use failure::{Error as FailureError, Fail};
use std::fmt::{Display, Formatter, Result as FmtResult};

pub type OsshResult<T> = Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: Option<FailureError>,
}

impl Error {
    pub(crate) fn from_kind(kind: ErrorKind) -> Self {
        Error {
            kind: kind,
            inner: None,
        }
    }

    pub(crate) fn with_failure<F: Fail>(kind: ErrorKind, failure: F) -> Self {
        Error {
            kind: kind,
            inner: Some(failure.into()),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.kind)?;
        if let Some(cause) = &self.inner {
            write!(f, ": {}", cause)?;
        }
        Ok(())
    }
}

impl Fail for Error {
    fn name(&self) -> Option<&str> {
        if self.kind == ErrorKind::Custom {
            None
        } else {
            Some(self.kind.name())
        }
    }

    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.as_ref().map(|f| f.as_fail())
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::from_kind(kind)
    }
}
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::with_failure(ErrorKind::IOError, err)
    }
}
impl From<std::fmt::Error> for Error {
    fn from(err: std::fmt::Error) -> Self {
        Self::with_failure(ErrorKind::FmtError, err)
    }
}
impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::with_failure(ErrorKind::OpenSslError, err)
    }
}
impl From<ed25519_dalek::SignatureError> for Error {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::with_failure(ErrorKind::Ed25519Error, err)
    }
}
impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Self::with_failure(ErrorKind::Base64Error, err)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ErrorKind {
    OpenSslError,
    Ed25519Error,
    IOError,
    FmtError,
    Base64Error,
    InvalidPublicKey,
    InvalidKeyPair,
    InvalidFormat,
    InvalidKeySize,
    UnsupportedCurve,
    Custom,
}

impl ErrorKind {
    pub fn name(&self) -> &'static str {
        use ErrorKind::*;

        match self {
            OpenSslError => "OpenSSL Error",
            Ed25519Error => "Ed25519 Error",
            IOError => "I/O Error",
            FmtError => "Formatter Error",
            Base64Error => "Base64 Error",
            InvalidPublicKey => "Invalid Public Key",
            InvalidKeyPair => "Invalid Key Pair",
            InvalidFormat => "Invalid Format",
            InvalidKeySize => "Invalid Key Size",
            UnsupportedCurve => "Unsupported Elliptic Curve",
            Custom => "Custom Error",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.name())
    }
}
