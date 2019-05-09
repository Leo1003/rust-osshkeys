use super::{Key, PubKey, PrivKey};
use crate::error::Error;
use crate::sshbuf::{SshReadExt, SshWriteExt};
use openssl::bn::{BigNum, BigNumRef};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use std::fmt;

const RSA_MIN_SIZE: usize = 1024;
const RSA_NAME: &'static str = "ssh-rsa";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignature {
    SHA1,
    SHA2_256,
    SHA2_512,
}

impl RsaSignature {
    fn get_digest(&self) -> MessageDigest {
        use RsaSignature::*;
        match self {
            SHA1 => MessageDigest::md5(),
            SHA2_256 => MessageDigest::sha256(),
            SHA2_512 => MessageDigest::sha512(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    rsa: Rsa<Public>,
    signhash: RsaSignature,
}

impl RsaPublicKey {
    pub fn new(n: BigNum, e: BigNum, sig_hash: RsaSignature) -> Result<RsaPublicKey, Error> {
        let rsa = Rsa::from_public_components(n, e)?;
        Ok(RsaPublicKey {
            rsa: rsa,
            signhash: sig_hash,
        })
    }

    pub fn sign_type(&self) -> RsaSignature {
        self.signhash
    }

    pub fn set_sign_type(&mut self, sig: RsaSignature) {
        self.signhash = sig;
    }
}

impl Key for RsaPublicKey {
    fn size(&self) -> usize {
        self.rsa.size() as usize
    }

    fn keytype(&self) -> &'static str {
        RSA_NAME
    }
}

impl PubKey for RsaPublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        rsa_blob(self.rsa.e(), self.rsa.n())
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        if self.size() < RSA_MIN_SIZE {
            return Err(Error::InvalidKeySize);
        }
        let pkey = PKey::from_rsa(self.rsa.clone())?;
        let mut veri = Verifier::new(self.signhash.get_digest(), &pkey)?;
        veri.update(data)?;
        Ok(veri.verify(sig)?)
    }
}

impl PartialEq for RsaPublicKey {
    fn eq(&self, other: &RsaPublicKey) -> bool {
        self.rsa.e() == other.rsa.e() && self.rsa.n() == other.rsa.n()
    }
}

pub struct RsaKeyPair {
    rsa: Rsa<Private>,
    signhash: RsaSignature,
}

impl RsaKeyPair {
    pub fn sign_type(&self) -> RsaSignature {
        self.signhash
    }

    pub fn set_sign_type(&mut self, sig: RsaSignature) {
        self.signhash = sig;
    }

    pub fn clone_public_key(&self) -> Result<RsaPublicKey, Error> {
        let n = self.rsa.n().to_owned()?;
        let e = self.rsa.e().to_owned()?;
        Ok(RsaPublicKey::new(n, e, self.signhash)?)
    }
}

impl Key for RsaKeyPair {
    fn size(&self) -> usize {
        self.rsa.size() as usize
    }

    fn keytype(&self) -> &'static str {
        RSA_NAME
    }
}

impl PubKey for RsaKeyPair {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        rsa_blob(self.rsa.e(), self.rsa.n())
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.clone_public_key()?.verify(data, sig)
    }
}

impl PrivKey for RsaKeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if self.size() < RSA_MIN_SIZE {
            return Err(Error::InvalidKeySize);
        }
        let pkey = PKey::from_rsa(self.rsa.clone())?;
        let mut sign = Signer::new(self.signhash.get_digest(), &pkey)?;
        sign.update(data)?;
        Ok(sign.sign_to_vec()?)
    }
}

fn rsa_blob(e: &BigNumRef, n: &BigNumRef) -> Result<Vec<u8>, Error> {
    use std::io::Cursor;

    let mut buf = Cursor::new(Vec::new());

    buf.write_utf8(RSA_NAME)?;
    buf.write_mpint(e)?;
    buf.write_mpint(n)?;

    Ok(buf.into_inner())
}
