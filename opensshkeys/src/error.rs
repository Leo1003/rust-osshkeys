use std::error;
use std::fmt;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: Option<String>,
    source: Option<Box<dyn error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error {
            kind: kind,
            message: None,
            source: None
        }
    }
    pub fn new_msg(kind: ErrorKind, msg: &'static str) -> Self {
        Error {
            kind: kind,
            message: Some(String::from(msg)),
            source: None
        }
    }
    pub fn from<E>(kind: ErrorKind, error: E) -> Self
    where E: Into<Box<error::Error + Send + Sync>> {
        let error = error.into();
        Error {
            kind: kind,
            message: None,
            source: Some(error)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(src) = &self.source {
            if let Some(msg) = &self.message {
                write!(f, "{}: {}; From: {}", self.kind, msg, src)
            } else {
                write!(f, "{}; From: {}", self.kind, src)
            }
        } else {
            if let Some(msg) = &self.message {
                write!(f, "{}: {}", self.kind, msg)
            } else {
                write!(f, "{}", self.kind)
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.source {
            Some(s) => Some(s.as_ref()),
            None => None
        }
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ErrorKind {
    OpenSslError,
    InvalidFormat,
    InvalidKeySize,
}

impl ErrorKind {
    fn description(&self) -> &'static str {
        match self {
            ErrorKind::OpenSslError => "OpenSsl Error",
            ErrorKind::InvalidFormat => "Invalid Format",
            ErrorKind::InvalidKeySize => "Invalid Key Size",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}
