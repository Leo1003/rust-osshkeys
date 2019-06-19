use super::error::{KeyFormatError, KeyFormatResult};
use crate::error::Error;
use crate::keys::*;
use openssl::pkey::PKey;

//TODO: Not to use openssl to parse pem file in the future
pub fn parse_pem_privkey(pem: &[u8], passphrase: Option<&[u8]>) -> KeyFormatResult<KeyPair> {
    let pkey = if let Some(passphrase) = passphrase {
        PKey::private_key_from_pem_passphrase(pem, passphrase)
            .map_err(|_| KeyFormatError::PassIncorrect)?
    } else {
        PKey::private_key_from_pem(pem)?
    };

    Ok(KeyPair::from_ossl_pkey(&pkey)?)
}

//TODO: Not to use openssl to parse pem file in the future
pub fn stringify_pem_privkey(
    keypair: &KeyPair,
    passphrase: Option<&[u8]>,
) -> KeyFormatResult<String> {
    let pem = if let Some(passphrase) = passphrase {
        let cipher = openssl::symm::Cipher::aes_128_cbc();
        match &keypair.key {
            KeyPairType::RSA(key) => key
                .ossl_rsa()
                .private_key_to_pem_passphrase(cipher, passphrase)?,
            KeyPairType::DSA(key) => unimplemented!(), //FIXME: openssl crate not implement it!!! //key.ossl_dsa().private_key_to_pem_passphrase(cipher, passphrase)?,
            KeyPairType::ECDSA(key) => key
                .ossl_ec()
                .private_key_to_pem_passphrase(cipher, passphrase)?,
            _ => return Err(KeyFormatError::UnsupportType),
        }
    } else {
        match &keypair.key {
            KeyPairType::RSA(key) => key.ossl_rsa().private_key_to_pem()?,
            KeyPairType::DSA(key) => unimplemented!(), //FIXME: openssl crate not implement it!!! //key.ossl_dsa().private_key_to_pem()?,
            KeyPairType::ECDSA(key) => key.ossl_ec().private_key_to_pem()?,
            _ => return Err(KeyFormatError::UnsupportType),
        }
    };

    Ok(String::from_utf8(pem).map_err(|_| KeyFormatError::UnknownError)?)
}
