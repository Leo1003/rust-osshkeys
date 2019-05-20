use super::{Key, PrivKey, PubKey};
use crate::error::Error;
use crate::sshbuf::{SshReadExt, SshWriteExt};
use openssl::bn::{BigNum, BigNumRef};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use std::fmt;
use std::io::Cursor;

const DSA_NAME: &'static str = "ssh-dss";

#[derive(Debug, Clone)]
pub struct DsaPublicKey {
    dsa: Dsa<Public>,
}

impl DsaPublicKey {
    pub fn new(p: BigNum, q: BigNum, g: BigNum, pub_key: BigNum) -> Result<Self, Error> {
        let dsa = Dsa::from_public_components(p, q, g, pub_key)?;
        Ok(Self { dsa: dsa })
    }
}

impl Key for DsaPublicKey {
    fn size(&self) -> usize {
        self.dsa.size() as usize
    }

    fn keytype(&self) -> &'static str {
        DSA_NAME
    }
}

impl PubKey for DsaPublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        dsa_blob(self.dsa.p(), self.dsa.q(), self.dsa.g(), self.dsa.pub_key())
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let pkey = PKey::from_dsa(self.dsa.clone())?;
        let mut veri = Verifier::new(MessageDigest::sha1(), &pkey)?;
        veri.update(data)?;
        Ok(veri.verify(sig)?)
    }
}

impl PartialEq for DsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        (self.dsa.p() == other.dsa.p())
            && (self.dsa.q() == other.dsa.q())
            && (self.dsa.g() == other.dsa.g())
            && (self.dsa.pub_key() == other.dsa.pub_key())
    }
}

impl fmt::Display for DsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let body = base64::encode_config(&self.blob().unwrap(), base64::STANDARD);
        write!(f, "{} {}", DSA_NAME, &body)
    }
}

pub struct DsaKeyPair {
    dsa: Dsa<Private>,
}

impl DsaKeyPair {
    pub fn clone_public_key(&self) -> Result<DsaPublicKey, Error> {
        let p = self.dsa.p().to_owned()?;
        let q = self.dsa.q().to_owned()?;
        let g = self.dsa.g().to_owned()?;
        let pub_key = self.dsa.pub_key().to_owned()?;
        Ok(DsaPublicKey::new(p, q, g, pub_key)?)
    }
}

impl Key for DsaKeyPair {
    fn size(&self) -> usize {
        self.dsa.size() as usize
    }

    fn keytype(&self) -> &'static str {
        DSA_NAME
    }
}

impl PubKey for DsaKeyPair {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        dsa_blob(self.dsa.p(), self.dsa.q(), self.dsa.g(), self.dsa.pub_key())
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.clone_public_key()?.verify(data, sig)
    }
}

impl PrivKey for DsaKeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = PKey::from_dsa(self.dsa.clone())?;
        let mut sign = Signer::new(MessageDigest::sha1(), &pkey)?;
        sign.update(data)?;
        Ok(sign.sign_to_vec()?)
    }
}

fn dsa_blob(p: &BigNumRef, q: &BigNumRef, g: &BigNumRef, y: &BigNumRef) -> Result<Vec<u8>, Error> {
    let mut buf = Cursor::new(Vec::new());

    buf.write_utf8(DSA_NAME)?;
    buf.write_mpint(p)?;
    buf.write_mpint(q)?;
    buf.write_mpint(g)?;
    buf.write_mpint(y)?;

    Ok(buf.into_inner())
}
