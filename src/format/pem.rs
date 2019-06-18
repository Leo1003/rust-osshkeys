use crate::error::Error;
use crate::keys::*;
use super::error::{KeyFormatError, KeyFormatResult};
use openssl::pkey::PKey;

//TODO: Not to use openssl to parse pem file in the future
pub fn parse_pem_privkey(pem: &[u8], passphrase: Option<&[u8]>) -> KeyFormatResult<KeyPair> {
    let pkey = if let Some(passphrase) = passphrase {
        PKey::private_key_from_pem_passphrase(pem, passphrase).map_err(|_| KeyFormatError::PassIncorrect)?
    } else {
        PKey::private_key_from_pem(pem)?
    };

    Ok(KeyPair::from_ossl_pkey(&pkey)?)
}

//TODO: Not to use openssl to parse pem file in the future
pub fn stringify_pem_privkey(keypair: &KeyPair, passphrase: Option<&[u8]>) -> KeyFormatResult<String> {
    let data = keypair.pem_stringify(passphrase)?;

    Ok(String::from_utf8(data).map_err(|_| KeyFormatError::UnknownError)?)
}
