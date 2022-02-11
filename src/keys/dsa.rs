use super::{Key, PrivateParts, PublicParts};
use crate::error::{Error, ErrorKind, OsshResult};
use crate::format::ossh_pubkey::*;
use openssl::bn::BigNum;
use openssl::dsa::{Dsa, DsaRef};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use std::fmt;

/// The key name returned by [`Key::keyname()`](../trait.Key.html#method.keyname)
pub const DSA_NAME: &str = "ssh-dss";
/// The key name returned by [`Key::short_keyname()`](../trait.Key.html#method.short_keyname)
pub const DSA_SHORT_NAME: &str = "DSA";

/// Represent the DSA public key
#[derive(Debug, Clone)]
pub struct DsaPublicKey {
    dsa: Dsa<Public>,
}

impl DsaPublicKey {
    /// Create the DSA public key from public components
    pub fn new(
        p: BigNum,
        q: BigNum,
        g: BigNum,
        pub_key: BigNum,
    ) -> Result<Self, openssl::error::ErrorStack> {
        let dsa = Dsa::from_public_components(p, q, g, pub_key)?;
        Ok(Self { dsa })
    }

    pub(crate) fn from_ossl_dsa(key: Dsa<Public>) -> Self {
        Self { dsa: key }
    }

    #[allow(unused)]
    pub(crate) fn ossl_dsa(&self) -> &DsaRef<Public> {
        &self.dsa
    }

    pub(crate) fn ossl_pkey(&self) -> Result<PKey<Public>, openssl::error::ErrorStack> {
        PKey::from_dsa(self.dsa.clone())
    }
}

impl Key for DsaPublicKey {
    fn size(&self) -> usize {
        self.dsa.p().num_bits() as usize
    }

    fn keyname(&self) -> &'static str {
        DSA_NAME
    }

    fn short_keyname(&self) -> &'static str {
        DSA_SHORT_NAME
    }
}

impl PublicParts for DsaPublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        encode_dsa_pubkey(&self.dsa)
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
        f.write_str(&serialize_ossh_pubkey(self, "").unwrap())
    }
}

/// Represent the DSA key pair
pub struct DsaKeyPair {
    dsa: Dsa<Private>,
}

impl DsaKeyPair {
    pub(crate) fn from_ossl_dsa(key: Dsa<Private>) -> Self {
        Self { dsa: key }
    }

    pub(crate) fn ossl_dsa(&self) -> &DsaRef<Private> {
        &self.dsa
    }

    /// Generate DSA key pair
    ///
    /// The bits parameter should be 1024 bits or `0` to use default length (1024 bits).
    pub fn generate(mut bits: usize) -> OsshResult<Self> {
        if bits == 0 {
            bits = 1024;
        }
        if bits != 1024 {
            return Err(Error::from_kind(ErrorKind::InvalidKeySize));
        }
        Ok(DsaKeyPair {
            dsa: Dsa::generate(bits as u32)?,
        })
    }

    /// Clone the public parts to generate public key
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
        self.dsa.p().num_bits() as usize
    }

    fn keyname(&self) -> &'static str {
        DSA_NAME
    }

    fn short_keyname(&self) -> &'static str {
        DSA_SHORT_NAME
    }
}

impl PublicParts for DsaKeyPair {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        encode_dsa_pubkey(&self.dsa)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.clone_public_key()?.verify(data, sig)
    }
}

impl PrivateParts for DsaKeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = PKey::from_dsa(self.dsa.clone())?;
        let mut sign = Signer::new(MessageDigest::sha1(), &pkey)?;
        sign.update(data)?;
        Ok(sign.sign_to_vec()?)
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod test {
    use super::*;
    use openssl::bn::BigNum;

    const pub_str: &str = "ssh-dss AAAAB3NzaC1kc3MAAACBAORLYnYacOdGmSJ99aZ+j2UqtQldYNHvAVVAI42wt/T/GTkg8cXdwwQ8HSJyD6T1e9ebnCXZd/YItX8DCPIP5GLUHVZy5zzKSzwga7zEjKP2j3JZGLAzFIUpStwQ8gur3zmh5DYi7JOdc/kWNpjT86n4fnrP+s8ZxuVDO5bbSasHAAAAFQD62yfFzJxz313aoIVgoMFoz8cF/wAAAIEAj7rvQz2hmuRyFUZIGWpwVHoR3y3SoQjEryX4ZtzwL04ROIXHSKJeOY9cdu2l5fMVYiMBtfWTQTlltFl1H//0hG/g5KBLhhwQ3Y7ul4Q8wsCWZJZeP3jtcO7+p3BLyMa6vvv5ptnMH+jRMgX5wwdszqogk4jCT+7fM2p6brMGccoAAACAD9qfPNxRo+npg+troNZ/FoYJezECqxg0jUyHWClACt7gS0W+r3dJIn9te6Xi7UFGPrLWJtlC++8i27m2FTS0sQUljM2NmRaf6jrCAhwPaJ0ievPJm5kBQmprTqBbdzCNRpI1+hceAnoHbajRwLueFwpoVOy2QjTkvBzd84Oobtw=";
    const p: [u8; 0x81] = [
        0x00, 0xe4, 0x4b, 0x62, 0x76, 0x1a, 0x70, 0xe7, 0x46, 0x99, 0x22, 0x7d, 0xf5, 0xa6, 0x7e,
        0x8f, 0x65, 0x2a, 0xb5, 0x09, 0x5d, 0x60, 0xd1, 0xef, 0x01, 0x55, 0x40, 0x23, 0x8d, 0xb0,
        0xb7, 0xf4, 0xff, 0x19, 0x39, 0x20, 0xf1, 0xc5, 0xdd, 0xc3, 0x04, 0x3c, 0x1d, 0x22, 0x72,
        0x0f, 0xa4, 0xf5, 0x7b, 0xd7, 0x9b, 0x9c, 0x25, 0xd9, 0x77, 0xf6, 0x08, 0xb5, 0x7f, 0x03,
        0x08, 0xf2, 0x0f, 0xe4, 0x62, 0xd4, 0x1d, 0x56, 0x72, 0xe7, 0x3c, 0xca, 0x4b, 0x3c, 0x20,
        0x6b, 0xbc, 0xc4, 0x8c, 0xa3, 0xf6, 0x8f, 0x72, 0x59, 0x18, 0xb0, 0x33, 0x14, 0x85, 0x29,
        0x4a, 0xdc, 0x10, 0xf2, 0x0b, 0xab, 0xdf, 0x39, 0xa1, 0xe4, 0x36, 0x22, 0xec, 0x93, 0x9d,
        0x73, 0xf9, 0x16, 0x36, 0x98, 0xd3, 0xf3, 0xa9, 0xf8, 0x7e, 0x7a, 0xcf, 0xfa, 0xcf, 0x19,
        0xc6, 0xe5, 0x43, 0x3b, 0x96, 0xdb, 0x49, 0xab, 0x07,
    ];
    const q: [u8; 0x15] = [
        0x00, 0xfa, 0xdb, 0x27, 0xc5, 0xcc, 0x9c, 0x73, 0xdf, 0x5d, 0xda, 0xa0, 0x85, 0x60, 0xa0,
        0xc1, 0x68, 0xcf, 0xc7, 0x05, 0xff,
    ];
    const g: [u8; 0x81] = [
        0x00, 0x8f, 0xba, 0xef, 0x43, 0x3d, 0xa1, 0x9a, 0xe4, 0x72, 0x15, 0x46, 0x48, 0x19, 0x6a,
        0x70, 0x54, 0x7a, 0x11, 0xdf, 0x2d, 0xd2, 0xa1, 0x08, 0xc4, 0xaf, 0x25, 0xf8, 0x66, 0xdc,
        0xf0, 0x2f, 0x4e, 0x11, 0x38, 0x85, 0xc7, 0x48, 0xa2, 0x5e, 0x39, 0x8f, 0x5c, 0x76, 0xed,
        0xa5, 0xe5, 0xf3, 0x15, 0x62, 0x23, 0x01, 0xb5, 0xf5, 0x93, 0x41, 0x39, 0x65, 0xb4, 0x59,
        0x75, 0x1f, 0xff, 0xf4, 0x84, 0x6f, 0xe0, 0xe4, 0xa0, 0x4b, 0x86, 0x1c, 0x10, 0xdd, 0x8e,
        0xee, 0x97, 0x84, 0x3c, 0xc2, 0xc0, 0x96, 0x64, 0x96, 0x5e, 0x3f, 0x78, 0xed, 0x70, 0xee,
        0xfe, 0xa7, 0x70, 0x4b, 0xc8, 0xc6, 0xba, 0xbe, 0xfb, 0xf9, 0xa6, 0xd9, 0xcc, 0x1f, 0xe8,
        0xd1, 0x32, 0x05, 0xf9, 0xc3, 0x07, 0x6c, 0xce, 0xaa, 0x20, 0x93, 0x88, 0xc2, 0x4f, 0xee,
        0xdf, 0x33, 0x6a, 0x7a, 0x6e, 0xb3, 0x06, 0x71, 0xca,
    ];
    const pub_key: [u8; 0x80] = [
        0x0f, 0xda, 0x9f, 0x3c, 0xdc, 0x51, 0xa3, 0xe9, 0xe9, 0x83, 0xeb, 0x6b, 0xa0, 0xd6, 0x7f,
        0x16, 0x86, 0x09, 0x7b, 0x31, 0x02, 0xab, 0x18, 0x34, 0x8d, 0x4c, 0x87, 0x58, 0x29, 0x40,
        0x0a, 0xde, 0xe0, 0x4b, 0x45, 0xbe, 0xaf, 0x77, 0x49, 0x22, 0x7f, 0x6d, 0x7b, 0xa5, 0xe2,
        0xed, 0x41, 0x46, 0x3e, 0xb2, 0xd6, 0x26, 0xd9, 0x42, 0xfb, 0xef, 0x22, 0xdb, 0xb9, 0xb6,
        0x15, 0x34, 0xb4, 0xb1, 0x05, 0x25, 0x8c, 0xcd, 0x8d, 0x99, 0x16, 0x9f, 0xea, 0x3a, 0xc2,
        0x02, 0x1c, 0x0f, 0x68, 0x9d, 0x22, 0x7a, 0xf3, 0xc9, 0x9b, 0x99, 0x01, 0x42, 0x6a, 0x6b,
        0x4e, 0xa0, 0x5b, 0x77, 0x30, 0x8d, 0x46, 0x92, 0x35, 0xfa, 0x17, 0x1e, 0x02, 0x7a, 0x07,
        0x6d, 0xa8, 0xd1, 0xc0, 0xbb, 0x9e, 0x17, 0x0a, 0x68, 0x54, 0xec, 0xb6, 0x42, 0x34, 0xe4,
        0xbc, 0x1c, 0xdd, 0xf3, 0x83, 0xa8, 0x6e, 0xdc,
    ];

    fn get_test_pubkey() -> Result<DsaPublicKey, Error> {
        let dsa_p = BigNum::from_slice(&p)?;
        let dsa_q = BigNum::from_slice(&q)?;
        let dsa_g = BigNum::from_slice(&g)?;
        let dsa_pub = BigNum::from_slice(&pub_key)?;
        Ok(DsaPublicKey::new(dsa_p, dsa_q, dsa_g, dsa_pub)?)
    }

    #[test]
    fn dsa_publickey_serialize() {
        let key = get_test_pubkey().unwrap();
        assert_eq!(key.to_string(), String::from(pub_str));
    }

    #[test]
    fn dsa_publickey_size() {
        let key = get_test_pubkey().unwrap();
        assert_eq!(key.size(), 1024);
    }
}
