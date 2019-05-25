custom_error! {pub Error
    OpenSslError{ source: openssl::error::ErrorStack } = "OpenSSL Error",
    Ed25519Error{ err: ed25519_dalek::SignatureError } = "Ed25519 Error",
    IOError{ source: std::io::Error } = "I/O Error",
    InvalidFormat = "Invalid Format",
    InvalidKeySize = "Invalid Key Size",
    UnsupportedCurve = "Unsupported Elliptic Curve",
}

// ed25519_dalek::SignatureError didn't implement the std::error::Error trait
impl From<ed25519_dalek::SignatureError> for Error {
    fn from(err: ed25519_dalek::SignatureError) -> Error {
        Error::Ed25519Error { err: err }
    }
}
