use crate::error::Error;
use crate::keys::dsa::{DsaPublicKey, DSA_NAME};
use crate::keys::ecdsa::{EcCurve, EcDsaPublicKey, NIST_P256_NAME, NIST_P384_NAME, NIST_P521_NAME};
use crate::keys::ed25519::{Ed25519PublicKey, ED25519_NAME};
use crate::keys::rsa::{RsaPublicKey, RSA_NAME};
use crate::keys::{KeyType, PublicKey};
use crate::sshbuf::{SshReadExt, SshWriteExt};
use ed25519_dalek::PublicKey as Ed25519PubKey;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use openssl::bn::BigNumContext;
use openssl::dsa::DsaRef;
use openssl::ec::{EcGroup, EcKeyRef, EcPoint, PointConversionForm};
use openssl::pkey::{HasParams, HasPublic};
use openssl::rsa::RsaRef;
use std::convert::TryInto;
use std::io;
use std::str::FromStr;

pub fn parse_ossh_pubkey(keystr: &str) -> Result<PublicKey, Error> {
    let key_split: Vec<&str> = keystr.split_ascii_whitespace().collect();
    if key_split.len() < 2 || key_split.len() > 3 {
        return Err(Error::InvalidFormat);
    }
    let blob = base64::decode(key_split[1])?;
    let mut pubkey: PublicKey = match key_split[0] {
        RSA_NAME => decode_rsa_pubkey(&blob)?.into(),
        DSA_NAME => decode_dsa_pubkey(&blob)?.into(),
        NIST_P256_NAME => decode_ecdsa_pubkey(&blob, Some(EcCurve::Nistp256))?.into(),
        NIST_P384_NAME => decode_ecdsa_pubkey(&blob, Some(EcCurve::Nistp384))?.into(),
        NIST_P521_NAME => decode_ecdsa_pubkey(&blob, Some(EcCurve::Nistp521))?.into(),
        ED25519_NAME => decode_ed25519_pubkey(&blob)?.into(),
        _ => return Err(Error::InvalidFormat),
    };
    if key_split.len() == 3 {
        pubkey.comment_mut().clone_from(&key_split[2].into());
        //Unstable: key_split[2].clone_into(pubkey.comment_mut());
    }
    Ok(pubkey)
}

pub(crate) fn decode_rsa_pubkey(keyblob: &[u8]) -> Result<RsaPublicKey, Error> {
    let mut reader = io::Cursor::new(keyblob);
    if reader.read_utf8()? != RSA_NAME {
        return Err(Error::InvalidFormat);
    }
    let e = reader.read_mpint()?;
    let n = reader.read_mpint()?;

    RsaPublicKey::new(n, e)
}

pub(crate) fn decode_dsa_pubkey(keyblob: &[u8]) -> Result<DsaPublicKey, Error> {
    let mut reader = io::Cursor::new(keyblob);
    if reader.read_utf8()? != DSA_NAME {
        return Err(Error::InvalidFormat);
    }

    let p = reader.read_mpint()?;
    let q = reader.read_mpint()?;
    let g = reader.read_mpint()?;
    let y = reader.read_mpint()?;

    DsaPublicKey::new(p, q, g, y)
}

pub(crate) fn decode_ecdsa_pubkey(
    keyblob: &[u8],
    curve_hint: Option<EcCurve>,
) -> Result<EcDsaPublicKey, Error> {
    let mut reader = io::Cursor::new(keyblob);
    let curve = match reader.read_utf8()?.as_str() {
        NIST_P256_NAME | NIST_P384_NAME | NIST_P521_NAME => {
            let ident_str = reader.read_utf8()?;
            EcCurve::from_str(&ident_str)?
        }
        _ => return Err(Error::InvalidFormat),
    };
    if let Some(curve_hint) = curve_hint {
        if curve != curve_hint {
            return Err(Error::InvalidFormat);
        }
    }
    let pub_key = reader.read_string()?;

    let mut bn_ctx = BigNumContext::new()?;
    let group: EcGroup = curve.try_into()?;
    let point = EcPoint::from_bytes(&group, &pub_key, &mut bn_ctx)?;
    EcDsaPublicKey::new(&group, &point)
}

pub(crate) fn decode_ed25519_pubkey(keyblob: &[u8]) -> Result<Ed25519PublicKey, Error> {
    let mut reader = io::Cursor::new(keyblob);
    if reader.read_utf8()? != ED25519_NAME {
        return Err(Error::InvalidFormat);
    }

    let pub_key = reader.read_string()?;
    if pub_key.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidFormat);
    }

    Ed25519PublicKey::new(pub_key.as_slice().try_into().unwrap())
}

pub(crate) fn encode_rsa_pubkey<T: HasPublic + HasParams>(
    key: &RsaRef<T>,
) -> Result<Vec<u8>, Error> {
    let mut buf = io::Cursor::new(Vec::new());

    buf.write_utf8(RSA_NAME)?;
    buf.write_mpint(key.e())?;
    buf.write_mpint(key.n())?;

    Ok(buf.into_inner())
}

pub(crate) fn encode_dsa_pubkey<T: HasPublic + HasParams>(
    key: &DsaRef<T>,
) -> Result<Vec<u8>, Error> {
    let mut buf = io::Cursor::new(Vec::new());

    buf.write_utf8(DSA_NAME)?;
    buf.write_mpint(key.p())?;
    buf.write_mpint(key.q())?;
    buf.write_mpint(key.g())?;
    buf.write_mpint(key.pub_key())?;

    Ok(buf.into_inner())
}

pub(crate) fn encode_ecdsa_pubkey<T: HasPublic + HasParams>(
    curve: EcCurve,
    key: &EcKeyRef<T>,
) -> Result<Vec<u8>, Error> {
    let mut buf = io::Cursor::new(Vec::new());
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

pub(crate) fn encode_ed25519_pubkey(pub_key: &Ed25519PubKey) -> Result<Vec<u8>, Error> {
    let mut buf = io::Cursor::new(Vec::new());

    buf.write_utf8(ED25519_NAME)?;
    buf.write_string(pub_key.as_bytes())?;

    Ok(buf.into_inner())
}
