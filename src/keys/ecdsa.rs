use super::{Key, PrivateParts, PublicParts};
use crate::error::{Error, ErrorKind, OsshResult};
use crate::format::ossh_pubkey::*;
use openssl::bn::{BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey, EcKeyRef, EcPoint, EcPointRef};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use std::fmt;
use std::str::FromStr;

const ECDSA_DEF_SIZE: usize = 256;
/// The name of 256 bits curve key returned by [`Key::keyname()`](../trait.Key.html#method.keyname)
pub const NIST_P256_NAME: &str = "ecdsa-sha2-nistp256";
/// The name of 384 bits curve key returned by [`Key::keyname()`](../trait.Key.html#method.keyname)
pub const NIST_P384_NAME: &str = "ecdsa-sha2-nistp384";
/// The name of 521 bits curve key returned by [`Key::keyname()`](../trait.Key.html#method.keyname)
pub const NIST_P521_NAME: &str = "ecdsa-sha2-nistp521";
/// The short name of ECDSA returned by [`Key::short_keyname()`](../trait.Key.html#method.short_keyname)
pub const ECDSA_SHORT_NAME: &str = "ECDSA";

/// An enum of the supported elliptic curves
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    Nistp256,
    Nistp384,
    Nistp521,
}

impl EcCurve {
    /// Parse from the ecdsa key name
    pub fn from_name(s: &str) -> OsshResult<Self> {
        match s {
            NIST_P256_NAME => Ok(EcCurve::Nistp256),
            NIST_P384_NAME => Ok(EcCurve::Nistp384),
            NIST_P521_NAME => Ok(EcCurve::Nistp521),
            _ => Err(ErrorKind::UnsupportCurve.into()),
        }
    }

    /// The key size of this curve
    pub fn size(self) -> usize {
        match self {
            EcCurve::Nistp256 => 256,
            EcCurve::Nistp384 => 384,
            EcCurve::Nistp521 => 521,
        }
    }

    /// The key name of this curve
    pub fn name(self) -> &'static str {
        match self {
            EcCurve::Nistp256 => NIST_P256_NAME,
            EcCurve::Nistp384 => NIST_P384_NAME,
            EcCurve::Nistp521 => NIST_P521_NAME,
        }
    }

    /// The identifier part in the key name
    pub fn ident(self) -> &'static str {
        match self {
            EcCurve::Nistp256 => "nistp256",
            EcCurve::Nistp384 => "nistp384",
            EcCurve::Nistp521 => "nistp521",
        }
    }

    fn nid(self) -> Nid {
        match self {
            EcCurve::Nistp256 => Nid::X9_62_PRIME256V1,
            EcCurve::Nistp384 => Nid::SECP384R1,
            EcCurve::Nistp521 => Nid::SECP521R1,
        }
    }
}

impl FromStr for EcCurve {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "nistp256" => Ok(EcCurve::Nistp256),
            "nistp384" => Ok(EcCurve::Nistp384),
            "nistp521" => Ok(EcCurve::Nistp521),
            _ => Err(ErrorKind::UnsupportCurve.into()),
        }
    }
}

impl TryInto<EcGroup> for EcCurve {
    type Error = openssl::error::ErrorStack;
    fn try_into(self) -> Result<EcGroup, Self::Error> {
        EcGroup::from_curve_name(self.nid())
    }
}

/// Represent the EcDSA public key
#[derive(Clone, Debug)]
pub struct EcDsaPublicKey {
    key: EcKey<Public>,
    curve: EcCurve,
}

impl EcDsaPublicKey {
    /// Create the EcDSA public key from the elliptic curve and the public point
    pub(crate) fn new(
        curve: EcCurve,
        public_key: &EcPointRef,
    ) -> Result<Self, openssl::error::ErrorStack> {
        let group: EcGroup = curve.try_into()?;

        Ok(Self {
            key: EcKey::from_public_key(&group, public_key)?,
            curve,
        })
    }

    pub(crate) fn from_ossl_ec(key: EcKey<Public>) -> OsshResult<Self> {
        let curve = match key.group().curve_name().unwrap_or(Nid::UNDEF) {
            Nid::X9_62_PRIME256V1 => EcCurve::Nistp256,
            Nid::SECP384R1 => EcCurve::Nistp384,
            Nid::SECP521R1 => EcCurve::Nistp521,
            _ => return Err(ErrorKind::UnsupportCurve.into()),
        };

        Ok(Self { key, curve })
    }

    pub(crate) fn from_bytes(curve: EcCurve, public_key: &[u8]) -> OsshResult<Self> {
        Ok(Self::new(
            curve,
            into_ec_point(curve, public_key)?.as_ref(),
        )?)
    }

    /// Get the key's elliptic curve type
    pub fn curve(&self) -> EcCurve {
        self.curve
    }

    #[allow(unused)]
    pub(crate) fn ossl_ec(&self) -> &EcKeyRef<Public> {
        &self.key
    }

    pub(crate) fn ossl_pkey(&self) -> Result<PKey<Public>, openssl::error::ErrorStack> {
        PKey::from_ec_key(self.key.clone())
    }
}

impl Key for EcDsaPublicKey {
    fn size(&self) -> usize {
        self.curve.size()
    }

    fn keyname(&self) -> &'static str {
        self.curve.name()
    }

    fn short_keyname(&self) -> &'static str {
        ECDSA_SHORT_NAME
    }
}

impl PublicParts for EcDsaPublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        encode_ecdsa_pubkey(self.curve, &self.key)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let pkey = PKey::from_ec_key(self.key.clone())?;
        let mut veri = Verifier::new(MessageDigest::sha1(), &pkey)?;
        veri.update(data)?;
        Ok(veri.verify(sig)?)
    }
}

impl PartialEq for EcDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        let mut bn_ctx = BigNumContext::new().unwrap();
        //FIXME: rust-openssl doesn't provide a EC_GROUP_cmp() wrapper, so we temporarily use curve type instead.
        (self.curve == other.curve)
            && self
                .key
                .public_key()
                .eq(self.key.group(), other.key.public_key(), &mut bn_ctx)
                .unwrap()
    }
}

impl fmt::Display for EcDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&serialize_ossh_pubkey(self, "").unwrap())
    }
}

/// Represent the EcDSA key pair
pub struct EcDsaKeyPair {
    key: EcKey<Private>,
    curve: EcCurve,
}

impl EcDsaKeyPair {
    pub(crate) fn from_ossl_ec(key: EcKey<Private>) -> OsshResult<Self> {
        let curve = match key.group().curve_name().unwrap_or(Nid::UNDEF) {
            Nid::X9_62_PRIME256V1 => EcCurve::Nistp256,
            Nid::SECP384R1 => EcCurve::Nistp384,
            Nid::SECP521R1 => EcCurve::Nistp521,
            _ => return Err(ErrorKind::UnsupportCurve.into()),
        };

        Ok(Self { key, curve })
    }

    pub(crate) fn ossl_ec(&self) -> &EcKeyRef<Private> {
        &self.key
    }

    pub(crate) fn new(
        curve: EcCurve,
        public_key: &EcPointRef,
        private_number: &BigNumRef,
    ) -> OsshResult<Self> {
        let group: EcGroup = curve.try_into()?;

        Ok(Self {
            key: EcKey::from_private_components(&group, private_number, public_key)?,
            curve,
        })
    }

    pub(crate) fn from_bytes(
        curve: EcCurve,
        public_key: &[u8],
        private_number: &BigNumRef,
    ) -> OsshResult<Self> {
        Self::new(
            curve,
            into_ec_point(curve, public_key)?.as_ref(),
            private_number,
        )
    }

    /// Generate EcDSA key pair
    ///
    /// The bits parameter should be 256, 284, 521 bits or `0` to use default length (256 bits).
    /// Different key length is corresponding to different curve.
    pub fn generate(mut bits: usize) -> OsshResult<Self> {
        if bits == 0 {
            bits = ECDSA_DEF_SIZE;
        }
        let curve = match bits {
            256 => EcCurve::Nistp256,
            384 => EcCurve::Nistp384,
            521 => EcCurve::Nistp521,
            _ => return Err(Error::from_kind(ErrorKind::InvalidKeySize)),
        };
        let group: EcGroup = curve.try_into()?;

        Ok(EcDsaKeyPair {
            key: EcKey::generate(&group)?,
            curve,
        })
    }

    /// Get the key's elliptic curve type
    pub fn curve(&self) -> EcCurve {
        self.curve
    }

    /// Clone the public parts to generate public key
    pub fn clone_public_key(&self) -> Result<EcDsaPublicKey, Error> {
        Ok(EcDsaPublicKey::new(self.curve, self.key.public_key())?)
    }
}

impl Key for EcDsaKeyPair {
    fn size(&self) -> usize {
        self.curve.size()
    }

    fn keyname(&self) -> &'static str {
        self.curve.name()
    }

    fn short_keyname(&self) -> &'static str {
        ECDSA_SHORT_NAME
    }
}

impl PublicParts for EcDsaKeyPair {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        encode_ecdsa_pubkey(self.curve, &self.key)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.clone_public_key()?.verify(data, sig)
    }
}

impl PrivateParts for EcDsaKeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = PKey::from_ec_key(self.key.clone())?;
        let mut sign = Signer::new(MessageDigest::sha1(), &pkey)?;
        sign.update(data)?;
        Ok(sign.sign_to_vec()?)
    }
}

fn into_ec_point(curve: EcCurve, public_key: &[u8]) -> Result<EcPoint, openssl::error::ErrorStack> {
    let mut bn_ctx = BigNumContext::new()?;
    let group: EcGroup = curve.try_into()?;
    EcPoint::from_bytes(&group, public_key, &mut bn_ctx)
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod test {
    use super::*;
    use openssl::bn::BigNumContext;
    use openssl::ec::EcPoint;

    const pub_str: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKtcK82cEoqjiXyqPpyQAlkOQYs8LL5dDahPah5dqoaJfVHcKS5CJYBX0Ow+Dlj9xKtSQRCyJXOCEtJx+k4LUV0=";
    const ident: [u8; 0x08] = [0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36];
    const pub_key: [u8; 0x41] = [
        0x04, 0xab, 0x5c, 0x2b, 0xcd, 0x9c, 0x12, 0x8a, 0xa3, 0x89, 0x7c, 0xaa, 0x3e, 0x9c, 0x90,
        0x02, 0x59, 0x0e, 0x41, 0x8b, 0x3c, 0x2c, 0xbe, 0x5d, 0x0d, 0xa8, 0x4f, 0x6a, 0x1e, 0x5d,
        0xaa, 0x86, 0x89, 0x7d, 0x51, 0xdc, 0x29, 0x2e, 0x42, 0x25, 0x80, 0x57, 0xd0, 0xec, 0x3e,
        0x0e, 0x58, 0xfd, 0xc4, 0xab, 0x52, 0x41, 0x10, 0xb2, 0x25, 0x73, 0x82, 0x12, 0xd2, 0x71,
        0xfa, 0x4e, 0x0b, 0x51, 0x5d,
    ];

    fn get_test_pubkey() -> Result<EcDsaPublicKey, Error> {
        let ident_str = std::str::from_utf8(&ident).unwrap();
        let mut bn_ctx = BigNumContext::new()?;
        let curve: EcCurve = EcCurve::from_str(ident_str)?;
        let group: EcGroup = curve.try_into()?;
        let point = EcPoint::from_bytes(&group, &pub_key, &mut bn_ctx)?;
        Ok(EcDsaPublicKey::new(curve, &point)?)
    }

    #[test]
    fn ecdsa_publickey_serialize() {
        let key = get_test_pubkey().unwrap();
        assert_eq!(key.to_string(), String::from(pub_str));
    }

    #[test]
    fn ecdsa_publickey_size() {
        let key = get_test_pubkey().unwrap();
        assert_eq!(key.size(), 256);
    }
}
