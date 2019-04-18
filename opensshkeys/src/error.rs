custom_error!{pub Error
    OpenSslError{ source: openssl::error::ErrorStack } = "OpenSSL Error",
    InvalidFormat = "Invalid Format",
    InvalidKeySize = "Invalid Key Size",
}
