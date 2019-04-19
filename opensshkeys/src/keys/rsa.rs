use crate::error::Error;
use crate::keys::{PrivateKey, PublicKey};
use openssl::bn::{BigNum, BigNumRef};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

const RSA_MIN_SIZE: usize = 1024;
const RSA_NAME: &'static str = "ssh-rsa";

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
        RSA_NAME
    }

    fn blob(&self) -> Result<Vec<u8>, Error> {
        rsa_blob(self.rsa.e(), self.rsa.n())
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

impl PublicKey for RsaPrivateKey {
    fn size(&self) -> usize {
        self.rsa.size() as usize
    }

    fn keytype(&self) -> &'static str {
        RSA_NAME
    }

    fn blob(&self) -> Result<Vec<u8>, Error> {
        rsa_blob(self.rsa.e(), self.rsa.n())
    }

    fn verify(&self, data: &[u8]) -> Result<bool, Error> {
        self.as_public_key()?.verify(data)
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

impl PrivateKey for RsaPrivateKey {
    type Public = RsaPublicKey;

    fn as_public_key(&self) -> Result<RsaPublicKey, Error> {
        let n = self.rsa.n().to_owned()?;
        let e = self.rsa.e().to_owned()?;
        Ok(RsaPublicKey::new(n, e)?)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }
}

fn rsa_blob(e: &BigNumRef, n: &BigNumRef) -> Result<Vec<u8>, Error> {
    unimplemented!();
}
