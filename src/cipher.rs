use aes::{Aes128, Aes192, Aes256};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use des::TdesEde3;
use digest::{Digest, DynDigest};
use std::str::FromStr;

use crate::error::{Error as OsshError, ErrorKind, OsshResult};

/// Provide an unified interface to encrypt/decrypt data
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Cipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    TDesCbc,
    Null,
}

impl Cipher {
    pub fn encrypt(self, src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        use Cipher::*;
        match self {
            Aes128Cbc => aes128cbc_encrypt(src, key, iv),
            Aes192Cbc => aes192cbc_encrypt(src, key, iv),
            Aes256Cbc => aes256cbc_encrypt(src, key, iv),
            TDesCbc => tdescbc_encrypt(src, key, iv),
            Null => Ok(src.to_vec()),
        }
    }

    pub fn decrypt(self, src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        use Cipher::*;
        match self {
            Aes128Cbc => aes128cbc_decrypt(src, key, iv),
            Aes192Cbc => aes192cbc_decrypt(src, key, iv),
            Aes256Cbc => aes256cbc_decrypt(src, key, iv),
            TDesCbc => tdescbc_decrypt(src, key, iv),
            Null => Ok(src.to_vec()),
        }
    }

    pub fn keylen(self) -> usize {
        use Cipher::*;
        match self {
            Aes128Cbc => 16,
            Aes192Cbc => 24,
            Aes256Cbc => 32,
            TDesCbc => 24,
            Null => 0,
        }
    }
}

impl FromStr for Cipher {
    type Err = OsshError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Cipher::*;
        match s {
            "3des-cbc" => Ok(TDesCbc),
            "aes128-cbc" => Ok(Aes128Cbc),
            "aes192-cbc" => Ok(Aes192Cbc),
            "aes256-cbc" | "rijndael-cbc@lysator.liu.se" => Ok(Aes256Cbc),
            "aes128-ctr" => Err(ErrorKind::UnsupportCipher.into()),
            "aes192-ctr" => Err(ErrorKind::UnsupportCipher.into()),
            "aes256-ctr" => Err(ErrorKind::UnsupportCipher.into()),
            "none" => Ok(Null),
            _ => Err(ErrorKind::UnsupportCipher.into()),
        }
    }
}

fn aes128cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<Aes128, Pkcs7>::new_var(key, iv)?.encrypt_vec(src))
}
fn aes128cbc_decrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<Aes128, Pkcs7>::new_var(key, iv)?.decrypt_vec(src)?)
}

fn aes192cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<Aes192, Pkcs7>::new_var(key, iv)?.encrypt_vec(src))
}
fn aes192cbc_decrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<Aes192, Pkcs7>::new_var(key, iv)?.decrypt_vec(src)?)
}

fn aes256cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<Aes256, Pkcs7>::new_var(key, iv)?.encrypt_vec(src))
}
fn aes256cbc_decrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<Aes256, Pkcs7>::new_var(key, iv)?.decrypt_vec(src)?)
}

fn tdescbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<TdesEde3, Pkcs7>::new_var(key, iv)?.encrypt_vec(src))
}
fn tdescbc_decrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
    Ok(Cbc::<TdesEde3, Pkcs7>::new_var(key, iv)?.decrypt_vec(src)?)
}
