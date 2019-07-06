use crate::error::Error;
use crate::keys::rsa::{RsaKeyPair, RsaSignature};
use openssl::rsa::Rsa;

pub fn decode_pkcs1(keyder: &[u8], signhash: RsaSignature) -> Result<RsaKeyPair, Error> {
    RsaKeyPair::from_ossl_rsa(Rsa::private_key_from_der(keyder)?, signhash)
}

pub fn encode_pkcs1(rsa: RsaKeyPair) -> Result<Vec<u8>, Error> {
    Ok(rsa.ossl_rsa().private_key_to_der()?)
}
