use super::{Key, PrivKey, PubKey};
use crate::error::Error;
use crate::sshbuf::{SshReadExt, SshWriteExt};
use openssl::bn::{BigNum, BigNumRef};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use std::fmt;
use std::io::Cursor;

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
    pub fn new(n: BigNum, e: BigNum) -> Result<RsaPublicKey, Error> {
        let rsa = Rsa::from_public_components(n, e)?;
        Ok(RsaPublicKey {
            rsa: rsa,
            signhash: RsaSignature::SHA1,
        })
    }

    pub fn new_with_signhash(
        n: BigNum,
        e: BigNum,
        sig_hash: RsaSignature,
    ) -> Result<RsaPublicKey, Error> {
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

impl fmt::Display for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let body = base64::encode_config(&self.blob().unwrap(), base64::STANDARD);
        write!(f, "{} {}", RSA_NAME, &body)
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
        Ok(RsaPublicKey::new_with_signhash(n, e, self.signhash)?)
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
    let mut buf = Cursor::new(Vec::new());

    buf.write_utf8(RSA_NAME)?;
    buf.write_mpint(e)?;
    buf.write_mpint(n)?;

    Ok(buf.into_inner())
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod test {
    use super::*;
    use openssl::bn::BigNum;

    const pub_str: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9NCtKoC/4Gk+zS8XGtA5aGC9BeFfcOCg/9C14ph4oHVXzWlR5t3HdHJK6EJGLlC6fj5vI+6cviX7NUbXJXQ/hJe4m4c5AGzubX/jfzNTjBa+hB+5CEqSztA20aHgEWzBwoakhkOd0knT6IvHV/vqTzHVbtfWIiof2SenyHv7yD9RbS9SCmkjISi4wQWzJ1Yu0O1CbH/U1c18WnP46/HBiaJcmV9hk/L3vjSoI7kpjXfSq4d3KLnwsUdrFdhh3eN7K4/ZdnrZC8n1liDXyMAWiaAL8cu8K5wmBmnHTcqIwxYu7g+k46OzcaZxVy0i9hFBM2bzvGvsCJOF3Hh6zF15p";
    const e: [u8; 3] = [0x01, 0x00, 0x01];
    const n: [u8; 0x101] = [
        0x00, 0xbd, 0x34, 0x2b, 0x4a, 0xa0, 0x2f, 0xf8, 0x1a, 0x4f, 0xb3, 0x4b, 0xc5, 0xc6, 0xb4,
        0x0e, 0x5a, 0x18, 0x2f, 0x41, 0x78, 0x57, 0xdc, 0x38, 0x28, 0x3f, 0xf4, 0x2d, 0x78, 0xa6,
        0x1e, 0x28, 0x1d, 0x55, 0xf3, 0x5a, 0x54, 0x79, 0xb7, 0x71, 0xdd, 0x1c, 0x92, 0xba, 0x10,
        0x91, 0x8b, 0x94, 0x2e, 0x9f, 0x8f, 0x9b, 0xc8, 0xfb, 0xa7, 0x2f, 0x89, 0x7e, 0xcd, 0x51,
        0xb5, 0xc9, 0x5d, 0x0f, 0xe1, 0x25, 0xee, 0x26, 0xe1, 0xce, 0x40, 0x1b, 0x3b, 0x9b, 0x5f,
        0xf8, 0xdf, 0xcc, 0xd4, 0xe3, 0x05, 0xaf, 0xa1, 0x07, 0xee, 0x42, 0x12, 0xa4, 0xb3, 0xb4,
        0x0d, 0xb4, 0x68, 0x78, 0x04, 0x5b, 0x30, 0x70, 0xa1, 0xa9, 0x21, 0x90, 0xe7, 0x74, 0x92,
        0x74, 0xfa, 0x22, 0xf1, 0xd5, 0xfe, 0xfa, 0x93, 0xcc, 0x75, 0x5b, 0xb5, 0xf5, 0x88, 0x8a,
        0x87, 0xf6, 0x49, 0xe9, 0xf2, 0x1e, 0xfe, 0xf2, 0x0f, 0xd4, 0x5b, 0x4b, 0xd4, 0x82, 0x9a,
        0x48, 0xc8, 0x4a, 0x2e, 0x30, 0x41, 0x6c, 0xc9, 0xd5, 0x8b, 0xb4, 0x3b, 0x50, 0x9b, 0x1f,
        0xf5, 0x35, 0x73, 0x5f, 0x16, 0x9c, 0xfe, 0x3a, 0xfc, 0x70, 0x62, 0x68, 0x97, 0x26, 0x57,
        0xd8, 0x64, 0xfc, 0xbd, 0xef, 0x8d, 0x2a, 0x08, 0xee, 0x4a, 0x63, 0x5d, 0xf4, 0xaa, 0xe1,
        0xdd, 0xca, 0x2e, 0x7c, 0x2c, 0x51, 0xda, 0xc5, 0x76, 0x18, 0x77, 0x78, 0xde, 0xca, 0xe3,
        0xf6, 0x5d, 0x9e, 0xb6, 0x42, 0xf2, 0x7d, 0x65, 0x88, 0x35, 0xf2, 0x30, 0x05, 0xa2, 0x68,
        0x02, 0xfc, 0x72, 0xef, 0x0a, 0xe7, 0x09, 0x81, 0x9a, 0x71, 0xd3, 0x72, 0xa2, 0x30, 0xc5,
        0x8b, 0xbb, 0x83, 0xe9, 0x38, 0xe8, 0xec, 0xdc, 0x69, 0x9c, 0x55, 0xcb, 0x48, 0xbd, 0x84,
        0x50, 0x4c, 0xd9, 0xbc, 0xef, 0x1a, 0xfb, 0x02, 0x24, 0xe1, 0x77, 0x1e, 0x1e, 0xb3, 0x17,
        0x5e, 0x69,
    ];

    #[test]
    fn rsa_publickey_serialize() {
        let rsa_e = BigNum::from_slice(&e).unwrap();
        let rsa_n = BigNum::from_slice(&n).unwrap();
        let key = RsaPublicKey::new(rsa_n, rsa_e).unwrap();
        assert_eq!(key.to_string(), String::from(pub_str));
    }
}
