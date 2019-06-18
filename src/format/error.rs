use failure::{Error as FailureError, Fail};
use std::fmt::{Display, Formatter, Result as FmtResult};

pub type KeyFormatResult<T> = Result<T, KeyFormatError>;

//TODO: Make Error kind more preciously
#[derive(Debug)]
pub enum KeyFormatError {
    InvalidKey,
    InvalidSize,
    PassIncorrect,
    TypeNotMatch,
    UnsupportType,
    UnsupportCurve,
    UnknownError,
    OpensslError(openssl::error::ErrorStack),
    Ed25519Error(ed25519_dalek::SignatureError),
    Base64Error(base64::DecodeError),
    IOError(std::io::Error),
    FormatError(std::fmt::Error),
}

impl Display for KeyFormatError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl Fail for KeyFormatError {
    fn name(&self) -> Option<&str> {
        use KeyFormatError::*;
        let err_name = match self {
            InvalidKey => "Invalid Key",
            InvalidSize => "Invalid Key Size",
            PassIncorrect => "Passphrase Incorrect",
            TypeNotMatch => "Key Type Not Match",
            UnsupportType => "Unsupported Key Type",
            UnsupportCurve => "Unsupported Eclipse Curve",
            UnknownError => "Unknown Error",
            OpensslError(_) => "OpenSSL Error",
            Ed25519Error(_) => "Ed25519 Error",
            Base64Error(_) => "Base64 Error",
            IOError(_) => "I/O Error",
            FormatError(_) => "Formatter Error",
        };
        Some(err_name)
    }
    fn cause(&self) -> Option<&Fail> {
        use KeyFormatError::*;
        match self {
            OpensslError(e) => Some(e),
            Ed25519Error(e) => Some(e),
            Base64Error(e) => Some(e),
            IOError(e) => Some(e),
            FormatError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KeyFormatError {
    fn from(err: std::io::Error) -> Self {
        KeyFormatError::IOError(err)
    }
}
impl From<std::fmt::Error> for KeyFormatError {
    fn from(err: std::fmt::Error) -> Self {
        KeyFormatError::FormatError(err)
    }
}
impl From<openssl::error::ErrorStack> for KeyFormatError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        KeyFormatError::OpensslError(err)
    }
}
impl From<ed25519_dalek::SignatureError> for KeyFormatError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        KeyFormatError::Ed25519Error(err)
    }
}
impl From<base64::DecodeError> for KeyFormatError {
    fn from(err: base64::DecodeError) -> Self {
        KeyFormatError::Base64Error(err)
    }
}
