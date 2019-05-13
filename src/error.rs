custom_error!{pub Error
    OpenSslError{ source: openssl::error::ErrorStack } = "OpenSSL Error",
    IOError{ source: std::io::Error } = "I/O Error",
    InvalidFormat = "Invalid Format",
    InvalidKeySize = "Invalid Key Size",
}
