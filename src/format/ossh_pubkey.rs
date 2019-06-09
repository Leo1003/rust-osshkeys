use crate::error::Error;
use crate::keys::dsa::{DsaPublicKey, DSA_NAME};
use crate::keys::ecdsa::{EcCurve, EcDsaPublicKey, NIST_P256_NAME, NIST_P384_NAME, NIST_P521_NAME};
use crate::keys::ed25519::{Ed25519PublicKey, ED25519_NAME};
use crate::keys::rsa::{RsaPublicKey, RSA_NAME};
use crate::keys::{KeyType, PublicKey};
use crate::sshbuf::{SshReadExt, SshWriteExt};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint};
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

fn decode_rsa_pubkey(keyblob: &[u8]) -> Result<RsaPublicKey, Error> {
    let mut reader = io::Cursor::new(keyblob);
    if reader.read_utf8()? != RSA_NAME {
        return Err(Error::InvalidFormat);
    }
    let e = reader.read_mpint()?;
    let n = reader.read_mpint()?;

    RsaPublicKey::new(n, e)
}

fn decode_dsa_pubkey(keyblob: &[u8]) -> Result<DsaPublicKey, Error> {
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

fn decode_ecdsa_pubkey(keyblob: &[u8], curve_hint: Option<EcCurve>) -> Result<EcDsaPublicKey, Error> {
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

fn decode_ed25519_pubkey(keyblob: &[u8]) -> Result<Ed25519PublicKey, Error> {
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