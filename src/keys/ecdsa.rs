use super::{Key, PrivKey, PubKey};
use crate::error::Error;
use crate::sshbuf::{SshReadExt, SshWriteExt};
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroupRef, EcKey, EcKeyRef, EcPointRef, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasParams, HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use std::fmt;
use std::io::Cursor;

const NIST_P256_NAME: &'static str = "ecdsa-sha2-nistp256";
const NIST_P384_NAME: &'static str = "ecdsa-sha2-nistp384";
const NIST_P521_NAME: &'static str = "ecdsa-sha2-nistp521";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    Nistp256,
    Nistp384,
    Nistp521,
}

impl EcCurve {
    pub fn size(&self) -> usize {
        match self {
            EcCurve::Nistp256 => 256,
            EcCurve::Nistp384 => 384,
            EcCurve::Nistp521 => 521,
        }
    }

    pub fn nid(&self) -> Nid {
        match self {
            EcCurve::Nistp256 => Nid::X9_62_PRIME256V1,
            EcCurve::Nistp384 => Nid::SECP384R1,
            EcCurve::Nistp521 => Nid::SECP521R1,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EcCurve::Nistp256 => NIST_P256_NAME,
            EcCurve::Nistp384 => NIST_P384_NAME,
            EcCurve::Nistp521 => NIST_P521_NAME,
        }
    }

    pub fn ident(&self) -> &'static str {
        match self {
            EcCurve::Nistp256 => "nistp256",
            EcCurve::Nistp384 => "nistp384",
            EcCurve::Nistp521 => "nistp521",
        }
    }
}

#[derive(Clone)]
pub struct EcDsaPublicKey {
    key: EcKey<Public>,
    curve: EcCurve,
}

//TODO: No Debug Implement for EcKey<Public>
impl fmt::Debug for EcDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dbg = f.debug_struct("EcDsaPublicKey");
        dbg.field("key", &"ECKEY".to_string());
        dbg.field("curve", &self.curve);
        dbg.finish()
    }
}

impl EcDsaPublicKey {
    pub fn new(group: &EcGroupRef, public_key: &EcPointRef) -> Result<Self, Error> {
        let curve = if let Some(nid) = group.curve_name() {
            match nid {
                Nid::X9_62_PRIME256V1 => EcCurve::Nistp256,
                Nid::SECP384R1 => EcCurve::Nistp384,
                Nid::SECP521R1 => EcCurve::Nistp521,
                _ => return Err(Error::InvalidFormat),
            }
        } else {
            return Err(Error::InvalidFormat);
        };

        Ok(Self {
            key: EcKey::from_public_key(group, public_key)?,
            curve: curve,
        })
    }
}

impl Key for EcDsaPublicKey {
    fn size(&self) -> usize {
        self.curve.size()
    }

    fn keytype(&self) -> &'static str {
        self.curve.name()
    }
}

impl PubKey for EcDsaPublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        eckey_blob(self.curve, &self.key)
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
        let body = base64::encode_config(&self.blob().unwrap(), base64::STANDARD);
        write!(f, "{} {}", self.curve.name(), &body)
    }
}

pub struct EcDsaKeyPair {
    key: EcKey<Private>,
    curve: EcCurve,
}

impl EcDsaKeyPair {
    pub fn clone_public_key(&self) -> Result<EcDsaPublicKey, Error> {
        Ok(EcDsaPublicKey::new(
            self.key.group(),
            self.key.public_key(),
        )?)
    }
}

impl Key for EcDsaKeyPair {
    fn size(&self) -> usize {
        self.curve.size()
    }

    fn keytype(&self) -> &'static str {
        self.curve.name()
    }
}

impl PubKey for EcDsaKeyPair {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        eckey_blob(self.curve, &self.key)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.clone_public_key()?.verify(data, sig)
    }
}

impl PrivKey for EcDsaKeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = PKey::from_ec_key(self.key.clone())?;
        let mut sign = Signer::new(MessageDigest::sha1(), &pkey)?;
        sign.update(data)?;
        Ok(sign.sign_to_vec()?)
    }
}

fn eckey_blob<T: HasPublic + HasParams>(
    curve: EcCurve,
    key: &EcKeyRef<T>,
) -> Result<Vec<u8>, Error> {
    let mut buf = Cursor::new(Vec::new());
    let mut bn_ctx = BigNumContext::new()?;

    buf.write_utf8(curve.name())?;
    buf.write_utf8(curve.ident())?;
    buf.write_string(&key.public_key().to_bytes(
        key.group(),
        PointConversionForm::UNCOMPRESSED,
        &mut bn_ctx,
    )?)?;

    Ok(buf.into_inner())
}
