use crate::error::Error;
use crate::keys::{PrivateKey, PublicKey};
use crate::FingerprintHash;
use openssl::bn::BigNum;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;

const RSA_MIN_SIZE: usize = 1024;

pub struct RsaPublicKey {
    rsa: Rsa<Public>,
    pub comment: String,
}

impl RsaPublicKey {
    pub fn new(n: BigNum, e: BigNum) -> Result<RsaPublicKey, Error> {
        let rsa = Rsa::from_public_components(n, e)?;
        Ok(RsaPublicKey {
            rsa: rsa,
            comment: String::new(),
        })
    }
}

impl PublicKey for RsaPublicKey {
    fn size(&self) -> usize {
        self.rsa.size() as usize
    }

    fn keytype(&self) -> &'static str {
        "ssh-rsa"
    }

    fn blob(&self) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }

    fn verify(&self, data: &[u8]) -> Result<bool, Error> {
        if self.size() < RSA_MIN_SIZE {
            return Err(Error::InvalidKeySize);
        }
        unimplemented!();
    }

    fn comment(&self) -> &String {
        &self.comment
    }

    fn comment_mut(&mut self) -> &mut String {
        &mut self.comment
    }

    fn set_comment(&mut self, comment: &str) -> () {
        self.comment = String::from(comment);
    }
}

pub struct RsaPrivateKey {
    rsa: Rsa<Private>,
    comment: String,
}
