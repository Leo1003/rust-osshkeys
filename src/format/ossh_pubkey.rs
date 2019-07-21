use crate::error::*;
use crate::keys::{dsa::*, ecdsa::*, ed25519::*, rsa::*, PublicPart, PublicKey};
use crate::sshbuf::{SshReadExt, SshWriteExt};
use ed25519_dalek::PublicKey as Ed25519PubKey;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use openssl::bn::BigNumContext;
use openssl::dsa::DsaRef;
use openssl::ec::{EcKeyRef, PointConversionForm};
use openssl::pkey::{HasParams, HasPublic};
use openssl::rsa::RsaRef;
use std::convert::TryInto;
use std::fmt::Write as _;
use std::io;
use std::str::FromStr;

pub fn parse_ossh_pubkey(keystr: &str) -> OsshResult<PublicKey> {
    let key_split: Vec<&str> = keystr.split_ascii_whitespace().collect();
    if key_split.len() < 2 || key_split.len() > 3 {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let blob = base64::decode(key_split[1])?;
    let mut pubkey: PublicKey = match key_split[0] {
        RSA_NAME | RSA_SHA256_NAME | RSA_SHA512_NAME => {
            let mut rsa = decode_rsa_pubkey(&blob)?;
            rsa.set_sign_type(RsaSignature::from_name(key_split[0]).unwrap());
            rsa.into()
        }
        DSA_NAME => decode_dsa_pubkey(&blob)?.into(),
        NIST_P256_NAME => decode_ecdsa_pubkey(&blob, Some(EcCurve::Nistp256))?.into(),
        NIST_P384_NAME => decode_ecdsa_pubkey(&blob, Some(EcCurve::Nistp384))?.into(),
        NIST_P521_NAME => decode_ecdsa_pubkey(&blob, Some(EcCurve::Nistp521))?.into(),
        ED25519_NAME => decode_ed25519_pubkey(&blob)?.into(),
        _ => return Err(ErrorKind::UnsupportType.into()),
    };
    if key_split.len() == 3 {
        *pubkey.comment_mut() = key_split[2].to_owned();
    }
    Ok(pubkey)
}

pub(crate) fn decode_rsa_pubkey(keyblob: &[u8]) -> OsshResult<RsaPublicKey> {
    let mut reader = io::Cursor::new(keyblob);
    let keyname = reader.read_utf8()?;
    if keyname != RSA_NAME && keyname != RSA_SHA256_NAME && keyname != RSA_SHA512_NAME {
        return Err(ErrorKind::TypeNotMatch.into());
    }
    let e = reader.read_mpint()?;
    let n = reader.read_mpint()?;

    Ok(RsaPublicKey::new(n, e)?)
}

pub(crate) fn decode_dsa_pubkey(keyblob: &[u8]) -> OsshResult<DsaPublicKey> {
    let mut reader = io::Cursor::new(keyblob);
    if reader.read_utf8()? != DSA_NAME {
        return Err(ErrorKind::TypeNotMatch.into());
    }

    let p = reader.read_mpint()?;
    let q = reader.read_mpint()?;
    let g = reader.read_mpint()?;
    let y = reader.read_mpint()?;

    Ok(DsaPublicKey::new(p, q, g, y)?)
}

pub(crate) fn decode_ecdsa_pubkey(
    keyblob: &[u8],
    curve_hint: Option<EcCurve>,
) -> OsshResult<EcDsaPublicKey> {
    let mut reader = io::Cursor::new(keyblob);
    let curve = if reader.read_utf8()?.starts_with("ecdsa-sha2-") {
        let ident_str = reader.read_utf8()?;
        EcCurve::from_str(&ident_str).map_err(|_| ErrorKind::UnsupportCurve)?
    } else {
        return Err(ErrorKind::TypeNotMatch.into());
    };
    if let Some(curve_hint) = curve_hint {
        if curve != curve_hint {
            return Err(ErrorKind::TypeNotMatch.into());
        }
    }
    let pub_key = reader.read_string()?;
    Ok(EcDsaPublicKey::from_bytes(curve, &pub_key)?)
}

pub(crate) fn decode_ed25519_pubkey(keyblob: &[u8]) -> OsshResult<Ed25519PublicKey> {
    let mut reader = io::Cursor::new(keyblob);
    if reader.read_utf8()? != ED25519_NAME {
        return Err(ErrorKind::TypeNotMatch.into());
    }

    let pub_key = reader.read_string()?;
    if pub_key.len() != PUBLIC_KEY_LENGTH {
        return Err(ErrorKind::InvalidKeySize.into());
    }

    Ok(Ed25519PublicKey::new(
        pub_key.as_slice().try_into().unwrap(),
    )?)
}

pub(crate) fn stringify_ossh_pubkey(key: &PublicPart, comment: Option<&str>) -> OsshResult<String> {
    let mut keystr = String::new();
    write!(
        &mut keystr,
        "{} {}",
        key.keyname(),
        base64::encode(&key.blob()?)
    )?;
    if let Some(comment) = comment {
        write!(&mut keystr, " {}", comment)?;
    }
    Ok(keystr)
}

pub(crate) fn encode_rsa_pubkey<T: HasPublic + HasParams>(key: &RsaRef<T>) -> OsshResult<Vec<u8>> {
    let mut buf = io::Cursor::new(Vec::new());

    buf.write_utf8(RSA_NAME)?;
    buf.write_mpint(key.e())?;
    buf.write_mpint(key.n())?;

    Ok(buf.into_inner())
}

pub(crate) fn encode_dsa_pubkey<T: HasPublic + HasParams>(key: &DsaRef<T>) -> OsshResult<Vec<u8>> {
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
) -> OsshResult<Vec<u8>> {
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

pub(crate) fn encode_ed25519_pubkey(pub_key: &Ed25519PubKey) -> OsshResult<Vec<u8>> {
    let mut buf = io::Cursor::new(Vec::new());

    buf.write_utf8(ED25519_NAME)?;
    buf.write_string(pub_key.as_bytes())?;

    Ok(buf.into_inner())
}

#[cfg(test)]
mod test {
    use super::*;

    const DSA_PUBKEY: &'static str = "ssh-dss AAAAB3NzaC1kc3MAAACBAORLYnYacOdGmSJ99aZ+j2UqtQldYNHvAVVAI42wt/T/GTkg8cXdwwQ8HSJyD6T1e9ebnCXZd/YItX8DCPIP5GLUHVZy5zzKSzwga7zEjKP2j3JZGLAzFIUpStwQ8gur3zmh5DYi7JOdc/kWNpjT86n4fnrP+s8ZxuVDO5bbSasHAAAAFQD62yfFzJxz313aoIVgoMFoz8cF/wAAAIEAj7rvQz2hmuRyFUZIGWpwVHoR3y3SoQjEryX4ZtzwL04ROIXHSKJeOY9cdu2l5fMVYiMBtfWTQTlltFl1H//0hG/g5KBLhhwQ3Y7ul4Q8wsCWZJZeP3jtcO7+p3BLyMa6vvv5ptnMH+jRMgX5wwdszqogk4jCT+7fM2p6brMGccoAAACAD9qfPNxRo+npg+troNZ/FoYJezECqxg0jUyHWClACt7gS0W+r3dJIn9te6Xi7UFGPrLWJtlC++8i27m2FTS0sQUljM2NmRaf6jrCAhwPaJ0ievPJm5kBQmprTqBbdzCNRpI1+hceAnoHbajRwLueFwpoVOy2QjTkvBzd84Oobtw= osshkeys_dsa-test";
    const RSA_PUBKEY: &'static str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9NCtKoC/4Gk+zS8XGtA5aGC9BeFfcOCg/9C14ph4oHVXzWlR5t3HdHJK6EJGLlC6fj5vI+6cviX7NUbXJXQ/hJe4m4c5AGzubX/jfzNTjBa+hB+5CEqSztA20aHgEWzBwoakhkOd0knT6IvHV/vqTzHVbtfWIiof2SenyHv7yD9RbS9SCmkjISi4wQWzJ1Yu0O1CbH/U1c18WnP46/HBiaJcmV9hk/L3vjSoI7kpjXfSq4d3KLnwsUdrFdhh3eN7K4/ZdnrZC8n1liDXyMAWiaAL8cu8K5wmBmnHTcqIwxYu7g+k46OzcaZxVy0i9hFBM2bzvGvsCJOF3Hh6zF15p osshkeys_rsa-test";
    const RSA256_PUBKEY: &'static str = "rsa-sha2-256 AAAAB3NzaC1yc2EAAAADAQABAAABAQC9NCtKoC/4Gk+zS8XGtA5aGC9BeFfcOCg/9C14ph4oHVXzWlR5t3HdHJK6EJGLlC6fj5vI+6cviX7NUbXJXQ/hJe4m4c5AGzubX/jfzNTjBa+hB+5CEqSztA20aHgEWzBwoakhkOd0knT6IvHV/vqTzHVbtfWIiof2SenyHv7yD9RbS9SCmkjISi4wQWzJ1Yu0O1CbH/U1c18WnP46/HBiaJcmV9hk/L3vjSoI7kpjXfSq4d3KLnwsUdrFdhh3eN7K4/ZdnrZC8n1liDXyMAWiaAL8cu8K5wmBmnHTcqIwxYu7g+k46OzcaZxVy0i9hFBM2bzvGvsCJOF3Hh6zF15p osshkeys_rsa-test";
    const ECDSA_PUBKEY: &'static str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKtcK82cEoqjiXyqPpyQAlkOQYs8LL5dDahPah5dqoaJfVHcKS5CJYBX0Ow+Dlj9xKtSQRCyJXOCEtJx+k4LUV0= osshkeys_ecdsa-test";
    const ED25519_PUBKEY: &'static str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMoWBluPErgKhNja3lHEf7ie6AVzR24mPRd742xEYodC osshkeys_ed25519-test";

    #[test]
    fn dsa_publickey_parse_serialize() {
        let dsa = parse_ossh_pubkey(DSA_PUBKEY).unwrap();
        assert_eq!(dsa.comment(), "osshkeys_dsa-test");
        let dsa_string = stringify_ossh_pubkey(&dsa, Some(dsa.comment())).unwrap();
        assert_eq!(&dsa_string, DSA_PUBKEY);
    }

    #[test]
    fn rsa_publickey_parse_serialize() {
        let rsa = parse_ossh_pubkey(RSA_PUBKEY).unwrap();
        assert_eq!(rsa.comment(), "osshkeys_rsa-test");
        let rsa_string = stringify_ossh_pubkey(&rsa, Some(rsa.comment())).unwrap();
        assert_eq!(&rsa_string, RSA_PUBKEY);
    }

    #[test]
    fn rsa256_publickey_parse_serialize() {
        let rsa = parse_ossh_pubkey(RSA256_PUBKEY).unwrap();
        assert_eq!(rsa.comment(), "osshkeys_rsa-test");
        let rsa_string = stringify_ossh_pubkey(&rsa, Some(rsa.comment())).unwrap();
        assert_eq!(&rsa_string, RSA256_PUBKEY);
    }

    #[test]
    fn ecdsa_publickey_parse_serialize() {
        let ecdsa = parse_ossh_pubkey(ECDSA_PUBKEY).unwrap();
        assert_eq!(ecdsa.comment(), "osshkeys_ecdsa-test");
        let ecdsa_string = stringify_ossh_pubkey(&ecdsa, Some(ecdsa.comment())).unwrap();
        assert_eq!(&ecdsa_string, ECDSA_PUBKEY);
    }

    #[test]
    fn ed25519_publickey_parse_serialize() {
        let ed25519 = parse_ossh_pubkey(ED25519_PUBKEY).unwrap();
        assert_eq!(ed25519.comment(), "osshkeys_ed25519-test");
        let ed25519_string = stringify_ossh_pubkey(&ed25519, Some(ed25519.comment())).unwrap();
        assert_eq!(&ed25519_string, ED25519_PUBKEY);
    }
}
