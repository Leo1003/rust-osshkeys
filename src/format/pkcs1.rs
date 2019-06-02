use openssl::rsa::Rsa;
use crate::keys::rsa::{RsaKeyPair, RsaSignature};
use crate::error::Error;

pub fn decode_pkcs1(keyder: &[u8], signhash: RsaSignature) -> Result<RsaKeyPair, Error> {
    Ok(RsaKeyPair::from_ossl_rsa(Rsa::private_key_from_der(keyder)?, signhash))
}

pub fn encode_pkcs1(rsa: RsaKeyPair) -> Result<Vec<u8>, Error> {
    Ok(rsa.ossl_rsa().private_key_to_der()?)
}
