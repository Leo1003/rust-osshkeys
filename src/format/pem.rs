// Temporary disable unused codes warnings in this file
#![allow(dead_code)]

use super::ossh_privkey::decode_ossh_priv;
use crate::error::*;
use crate::keys::*;
use aes::{Aes128, Aes192, Aes256};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use des::{Des, TdesEde3};
use digest::{Digest, DynDigest};
use nom_pem::{Block as PemBlock, HeaderEntry, ProcTypeType, RFC1423Algorithm};
use openssl::pkey::PKey;
use std::convert::TryInto;
use zeroize::Zeroize;

const MAX_KEY_LEN: usize = 64;

const AES128_KEY_LEN: usize = 16;
const AES192_KEY_LEN: usize = 24;
const AES256_KEY_LEN: usize = 32;
const DES_KEY_LEN: usize = 8;
const DES_EDE3_KEY_LEN: usize = 24;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes192Cbc = Cbc<Aes192, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type DesCbc = Cbc<Des, Pkcs7>;
type DesEde3Cbc = Cbc<TdesEde3, Pkcs7>;

//TODO: Not to depend on openssl to parse pem file in the future
pub fn parse_pem_privkey(pem: &[u8], passphrase: Option<&[u8]>) -> OsshResult<KeyPair> {
    let pkey = if let Some(passphrase) = passphrase {
        PKey::private_key_from_pem_passphrase(pem, passphrase)
            .map_err(|_| ErrorKind::IncorrectPass)?
    } else {
        PKey::private_key_from_pem(pem)?
    };

    Ok(KeyPair::from_ossl_pkey(&pkey)?)
}

//TODO: Not to depend on openssl to parse pem file in the future
pub fn stringify_pem_privkey(keypair: &KeyPair, passphrase: Option<&[u8]>) -> OsshResult<String> {
    let pem = if let Some(passphrase) = passphrase {
        let cipher = openssl::symm::Cipher::aes_128_cbc();
        match &keypair.key {
            KeyPairType::RSA(key) => key
                .ossl_rsa()
                .private_key_to_pem_passphrase(cipher, passphrase)?,
            KeyPairType::DSA(key) => key
                .ossl_dsa()
                .private_key_to_pem_passphrase(cipher, passphrase)?,
            KeyPairType::ECDSA(key) => key
                .ossl_ec()
                .private_key_to_pem_passphrase(cipher, passphrase)?,
            _ => return Err(ErrorKind::UnsupportType.into()),
        }
    } else {
        match &keypair.key {
            KeyPairType::RSA(key) => key.ossl_rsa().private_key_to_pem()?,
            KeyPairType::DSA(key) => key.ossl_dsa().private_key_to_pem()?,
            KeyPairType::ECDSA(key) => key.ossl_ec().private_key_to_pem()?,
            _ => return Err(ErrorKind::UnsupportType.into()),
        }
    };

    Ok(String::from_utf8(pem).map_err(|e| Error::with_failure(ErrorKind::InvalidPemFormat, e))?)
}

pub fn parse_keystr(pem: &[u8], passphrase: Option<&[u8]>) -> OsshResult<KeyPair> {
    let pemdata = nom_pem::decode_block(pem)?;

    match pemdata.block_type {
        "OPENSSH PRIVATE KEY" => {
            // Openssh format
            decode_ossh_priv(&pemdata.data, passphrase)
        }
        "PRIVATE KEY" => {
            // PKCS#8 format
            parse_pem_privkey(pem, passphrase)
            //unimplemented!()
        }
        "ENCRYPTED PRIVATE KEY" => {
            // PKCS#8 format
            parse_pem_privkey(pem, passphrase)
            //unimplemented!()
        }
        "DSA PRIVATE KEY" => {
            // Openssl DSA Key
            parse_pem_privkey(pem, passphrase)
            //unimplemented!()
        }
        "RSA PRIVATE KEY" => {
            // Openssl RSA Key
            parse_pem_privkey(pem, passphrase)
            //unimplemented!()
        }
        "EC PRIVATE KEY" => {
            // Openssl EC Key
            parse_pem_privkey(pem, passphrase)
            //unimplemented!()
        }
        _ => Err(ErrorKind::UnsupportType.into()),
    }
}

fn pem_decrypt(pemblock: &nom_pem::Block, passphrase: Option<&[u8]>) -> OsshResult<Vec<u8>> {
    let mut encrypted = false;
    for entry in &pemblock.headers {
        if let HeaderEntry::ProcType(ver, proctype) = entry {
            if *proctype == ProcTypeType::ENCRYPTED && *ver == 4 {
                encrypted = true;
            } else {
                return Err(ErrorKind::UnsupportType.into());
            }
        }
    }
    if encrypted {
        let mut decrypted = None;
        for entry in &pemblock.headers {
            if let HeaderEntry::DEKInfo(algo, iv) = entry {
                if let Some(pass) = passphrase {
                    decrypted = Some(
                        match algo {
                            RFC1423Algorithm::DES_CBC => {
                                let key = openssl_kdf(
                                    pass,
                                    iv.as_slice().try_into()?,
                                    &mut md5::Md5::default(),
                                    DES_KEY_LEN,
                                    1,
                                )?;
                                DesCbc::new_var(&key, &iv)?.decrypt_vec(&pemblock.data)
                            }
                            RFC1423Algorithm::DES_EDE3_CBC => {
                                let key = openssl_kdf(
                                    pass,
                                    iv.as_slice().try_into()?,
                                    &mut md5::Md5::default(),
                                    DES_EDE3_KEY_LEN,
                                    1,
                                )?;
                                DesEde3Cbc::new_var(&key, &iv)?.decrypt_vec(&pemblock.data)
                            }
                            RFC1423Algorithm::AES_128_CBC => {
                                let key = openssl_kdf(
                                    pass,
                                    iv.as_slice().try_into()?,
                                    &mut md5::Md5::default(),
                                    AES128_KEY_LEN,
                                    1,
                                )?;
                                Aes128Cbc::new_var(&key, &iv)?.decrypt_vec(&pemblock.data)
                            }
                            RFC1423Algorithm::AES_192_CBC => {
                                let key = openssl_kdf(
                                    pass,
                                    iv.as_slice().try_into()?,
                                    &mut md5::Md5::default(),
                                    AES192_KEY_LEN,
                                    1,
                                )?;
                                Aes192Cbc::new_var(&key, &iv)?.decrypt_vec(&pemblock.data)
                            }
                            RFC1423Algorithm::AES_256_CBC => {
                                let key = openssl_kdf(
                                    pass,
                                    iv.as_slice().try_into()?,
                                    &mut md5::Md5::default(),
                                    AES256_KEY_LEN,
                                    1,
                                )?;
                                Aes256Cbc::new_var(&key, &iv)?.decrypt_vec(&pemblock.data)
                            }
                        }
                        .map_err(|_| ErrorKind::IncorrectPass)?,
                    );
                } else {
                    return Err(ErrorKind::IncorrectPass.into());
                }
                break;
            }
        }
        if let Some(data) = decrypted {
            Ok(data)
        } else {
            Err(ErrorKind::InvalidPemFormat.into())
        }
    } else {
        Ok(pemblock.data.clone())
    }
}

fn openssl_kdf(
    data: &[u8],
    salt: &[u8; 8],
    digest: &mut dyn DynDigest,
    keylen: usize,
    iter: usize,
) -> OsshResult<Vec<u8>> {
    if keylen > MAX_KEY_LEN {
        return Err(ErrorKind::InvalidKeySize.into());
    }

    let mut key: Vec<u8> = Vec::with_capacity(keylen);
    let mut dig: Box<[u8]> = Box::default();

    let mut first = true;
    digest.reset();
    while key.len() < keylen {
        if !first {
            digest.input(&dig);
        }
        digest.input(data);
        digest.input(salt);
        dig = digest.result_reset();

        for _ in 1..iter {
            digest.input(&dig);
            dig = digest.result_reset();
        }

        for byte in dig.as_ref() {
            if key.len() < keylen {
                key.push(*byte);
            }
        }

        first = false;
    }

    dig.zeroize();
    Ok(key)
}
