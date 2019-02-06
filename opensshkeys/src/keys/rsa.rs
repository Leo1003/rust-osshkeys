use crate::error::{Error, ErrorKind};
use crate::FingerprintHash;
use crate::keys::{PublicKey, PrivateKey};
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Public, Private};
use openssl::sign::Verifier;

const RSA_MIN_SIZE: usize = 1024;

pub struct RsaPublicKey {
    rsa: Rsa<Public>,
    pub comment: String,
}

impl RsaPublicKey {
    pub fn new(n: BigNum, e: BigNum) -> Result<RsaPublicKey, Error> {
        match Rsa::from_public_components(n, e) {
            Result::Ok(rsa) => Result::Ok(RsaPublicKey {
                rsa: rsa,
                comment: String::new()
            }),
            Result::Err(e) => Result::Err(Error::from(ErrorKind::OpenSslError, e))
        }
    }
}

impl PublicKey for RsaPublicKey {
    fn size(&self) -> usize {
        self.rsa.size() as usize
    }
    fn fingerprint(&self, hash: FingerprintHash) -> Vec<u8> {
        //TODO: Unimplemented
        unimplemented!();
        vec![]
    }
    fn keytype(&self) -> &'static str {
        "ssh-rsa"
    }
    fn verify(&self, data: &[u8]) -> Result<bool, Error> {
        if self.size() < RSA_MIN_SIZE {
            return Result::Err(Error::new_msg(ErrorKind::InvalidKeySize, "Rsa key size too short"));
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