#[macro_use]
extern crate custom_error;
extern crate rand;
extern crate ed25519_dalek;

pub mod error;
pub mod keys;
pub mod sshbuf;
use openssl::hash::MessageDigest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintHash {
    MD5,
    SHA256,
    SHA512,
}

impl FingerprintHash {
    fn get_digest(&self) -> MessageDigest {
        match self {
            FingerprintHash::MD5 => MessageDigest::md5(),
            FingerprintHash::SHA256 => MessageDigest::sha256(),
            FingerprintHash::SHA512 => MessageDigest::sha512(),
        }
    }
}
