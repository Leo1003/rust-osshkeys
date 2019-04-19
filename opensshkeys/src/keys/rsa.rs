use crate::FingerprintHash;
use crate::error::Error;
use crate::keys::{PrivateKey, PublicKey};
use crate::sshbuf::SshWriter;
use openssl::bn::{BigNum, BigNumRef};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

const RSA_MIN_SIZE: usize = 1024;
const RSA_NAME: &'static str = "ssh-rsa";

pub struct RsaPublicKey {
    rsa: Rsa<Public>,
    signhash: FingerprintHash,
    pub comment: String,
}

impl RsaPublicKey {
    pub fn new(n: BigNum, e: BigNum, sig_hash: FingerprintHash) -> Result<RsaPublicKey, Error> {
        let rsa = Rsa::from_public_components(n, e)?;
        Ok(RsaPublicKey {
            rsa: rsa,
            signhash: sig_hash,
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

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        if self.size() < RSA_MIN_SIZE {
            return Err(Error::InvalidKeySize);
        }
        let pkey = PKey::from_rsa(self.rsa.clone())?;
        let mut veri = Verifier::new(self.signhash.get_digest(), &pkey)?;
        veri.update(data)?;
        Ok(veri.verify(sig)?)
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
    signhash: FingerprintHash,
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

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.as_public_key()?.verify(data, sig)
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
        Ok(RsaPublicKey::new(n, e, self.signhash)?)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = PKey::from_rsa(self.rsa.clone())?;
        let mut sign = Signer::new(self.signhash.get_digest(), &pkey)?;
        sign.update(data)?;
        Ok(sign.sign_to_vec()?)
    }
}

fn rsa_blob(e: &BigNumRef, n: &BigNumRef) -> Result<Vec<u8>, Error> {
    use std::io::Cursor;

    let buf = Cursor::new(Vec::new());
    let mut writer = SshWriter::new(buf);

    writer.write_utf8(RSA_NAME)?;
    writer.write_mpint(e)?;
    writer.write_mpint(n)?;

    Ok(writer.into_inner().into_inner())
}
