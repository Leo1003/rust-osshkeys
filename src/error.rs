use failure::{Backtrace, Error as FailureError, Fail};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// The [Result](https://doc.rust-lang.org/std/result/enum.Result.html) alias of this crate
pub type OsshResult<T> = Result<T, Error>;

/// The error type of this crate
pub struct Error {
    kind: ErrorKind,
    inner: Option<FailureError>,
    bt: Backtrace,
}

impl Error {
    pub(crate) fn from_kind(kind: ErrorKind) -> Self {
        Error {
            kind,
            inner: None,
            bt: Backtrace::new(),
        }
    }

    pub(crate) fn with_failure<F: Fail>(kind: ErrorKind, failure: F) -> Self {
        Error {
            kind,
            inner: Some(failure.into()),
            bt: Backtrace::new(),
        }
    }

    /// Get the kind of the error
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        writeln!(f, "OsshError {{")?;
        write!(f, "Kind: {:?} => \"{}\"", self.kind, self.kind)?;
        if let Some(cause) = &self.inner {
            write!(f, "\nCaused: {:?}", cause)?;
        }
        write!(f, "\nBackTrace: \n{:?}", self.bt)?;
        write!(f, "\n}}")
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.kind)?;
        if let Some(cause) = &self.inner {
            write!(f, "; Caused by: {}", cause)?;
        }
        Ok(())
    }
}

impl Fail for Error {
    fn name(&self) -> Option<&str> {
        Some("Osshkeys Error")
    }

    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.as_ref().map(|f| f.as_fail())
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        Some(&self.bt)
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

#[cfg(feature = "rustcrypto-cipher")]
impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(err: block_modes::InvalidKeyIvLength) -> Self {
        Self::with_failure(ErrorKind::InvalidKeyIvLength, err)
    }
}
#[cfg(feature = "rustcrypto-cipher")]
impl From<stream_cipher::InvalidKeyNonceLength> for Error {
    fn from(err: stream_cipher::InvalidKeyNonceLength) -> Self {
        Self::with_failure(ErrorKind::InvalidKeyIvLength, err)
    }
}
#[cfg(feature = "rustcrypto-cipher")]
impl From<block_modes::BlockModeError> for Error {
    fn from(err: block_modes::BlockModeError) -> Self {
        Self::with_failure(ErrorKind::IncorrectPass, err)
    }
}

impl From<nom_pem::PemParsingError> for Error {
    fn from(_err: nom_pem::PemParsingError) -> Self {
        // nom_pem::PemParsingError doesn't implement std::error::Error
        Self::from_kind(ErrorKind::InvalidPemFormat)
    }
}
impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Self {
        Self::with_failure(ErrorKind::InvalidLength, err)
    }
}

/// Indicate the reason of the error
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ErrorKind {
    /// The error is caused by OpenSSL, to get the underlying error, use [failure::Fail::cause()](https://docs.rs/failure/^0.1.5/failure/trait.Fail.html#method.cause)
    OpenSslError,
    /// The error is caused by ed25519-dalek, to get the underlying error, use [failure::Fail::cause()](https://docs.rs/failure/^0.1.5/failure/trait.Fail.html#method.cause)
    Ed25519Error,
    /// The error is caused by I/O error or reader error
    IOError,
    /// Can't format some data
    FmtError,
    /// The base64 string is invalid
    Base64Error,
    /// The argument passed into the function is invalid
    InvalidArgument,
    /// The key file has some invalid data in it
    InvalidKeyFormat,
    /// Currently not used...
    InvalidFormat,
    /// Some parts of the key are invalid
    InvalidKey,
    /// The key size is invalid
    InvalidKeySize,
    /// The slice length is invalid
    InvalidLength,
    /// The elliptic curve is not supported
    UnsupportCurve,
    /// The encrypt cipher is not supported
    UnsupportCipher,
    /// The passphrase is incorrect, can't decrypt the key
    IncorrectPass,
    /// The key type is not the desired one
    TypeNotMatch,
    /// The key type is not supported
    UnsupportType,
    /// The key file's PEM part is invalid
    InvalidPemFormat,
    /// The key or IV length can't meet the cipher's requirement
    InvalidKeyIvLength,
    /// Something shouldn't happen but it DID happen...
    Unknown,
}

impl ErrorKind {
    /// Get the description of the kind
    pub fn description(self) -> &'static str {
        use ErrorKind::*;

        match self {
            OpenSslError => "OpenSSL Error",
            Ed25519Error => "Ed25519 Error",
            IOError => "I/O Error",
            FmtError => "Formatter Error",
            Base64Error => "Base64 Error",
            InvalidArgument => "Invalid Argument",
            InvalidKeyFormat => "Invalid Key Format",
            InvalidFormat => "Invalid Format",
            InvalidKey => "Invalid Key",
            InvalidKeySize => "Invalid Key Size",
            InvalidLength => "Invalid Length",
            UnsupportCurve => "Unsupported Elliptic Curve",
            UnsupportCipher => "Unsupported Cipher",
            IncorrectPass => "Incorrect Passphrase",
            TypeNotMatch => "Key Type Not Match",
            UnsupportType => "Unsupported Key Type",
            InvalidPemFormat => "Invalid PEM Format",
            InvalidKeyIvLength => "Invalid Key/IV Length",
            Unknown => "Unknown Error",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.description())
    }
}
