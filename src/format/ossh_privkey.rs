use crate::bcrypt_pbkdf::bcrypt_pbkdf;
use crate::cipher::Cipher;
use crate::error::*;
use crate::keys::{dsa::*, ecdsa::*, ed25519::*, rsa::*, KeyPair, PublicParts};
use crate::sshbuf::{SshBuf, SshReadExt, SshWriteExt};
use byteorder::WriteBytesExt;
use cryptovec::CryptoVec;
use openssl::dsa::Dsa;
use openssl::rsa::RsaPrivateKeyBuilder;
use rand::prelude::*;
use rand::rngs::StdRng;
use std::io::{Cursor, Read, Write};
use std::str::FromStr;
use zeroize::Zeroizing;

const KEY_MAGIC: &[u8] = b"openssh-key-v1\0";
const KDF_BCRYPT: &str = "bcrypt";
const KDF_NONE: &str = "none";
const DEFAULT_ROUNDS: u32 = 16;
const SALT_LEN: usize = 16;

pub fn decode_ossh_priv(keydata: &[u8], passphrase: Option<&[u8]>) -> OsshResult<KeyPair> {
    if keydata.len() >= 16 && &keydata[0..15] == KEY_MAGIC {
        let mut reader = Cursor::new(keydata);
        reader.set_position(15);

        let ciphername = reader.read_utf8()?;
        let kdfname = reader.read_utf8()?;
        let kdf = reader.read_string()?;
        let nkeys = reader.read_uint32()?;
        if nkeys != 1 {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }
        reader.read_string()?; // Skip public keys
        let encrypted = reader.read_string()?;

        let mut secret_reader =
            decrypt_ossh_priv(&encrypted, passphrase, &ciphername, &kdfname, &kdf)?;
        let checksum0 = Zeroizing::new(secret_reader.read_uint32()?);
        let checksum1 = Zeroizing::new(secret_reader.read_uint32()?);
        if *checksum0 != *checksum1 {
            return Err(ErrorKind::IncorrectPass.into());
        }
        let mut keypair: KeyPair = decode_key(&mut secret_reader)?;

        *keypair.comment_mut() = secret_reader.read_utf8()?;

        // Check padding
        for (i, pad) in secret_reader.bytes().enumerate() {
            if ((i + 1) & 0xff) as u8 != pad? {
                return Err(ErrorKind::InvalidKeyFormat.into());
            }
        }

        Ok(keypair)
    } else {
        Err(ErrorKind::InvalidKeyFormat.into())
    }
}

pub fn decrypt_ossh_priv(
    privkey_data: &[u8],
    passphrase: Option<&[u8]>,
    ciphername: &str,
    kdfname: &str,
    kdf: &[u8],
) -> OsshResult<SshBuf> {
    let cipher = Cipher::from_str(ciphername)?;

    // Check if empty passphrase but encrypted
    if (!passphrase.map_or(false, |pass| !pass.is_empty())) && !cipher.is_null() {
        return Err(ErrorKind::IncorrectPass.into());
    }
    // Check kdf type
    if kdfname != "none" && kdfname != "bcrypt" {
        return Err(ErrorKind::UnsupportCipher.into());
    }
    // Check if no kdf providing but encrypted
    if kdfname == "none" && !cipher.is_null() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    let blocksize = cipher.block_size();
    if privkey_data.len() < blocksize || privkey_data.len() % blocksize != 0 {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    if !cipher.is_null() {
        let keyder = match kdfname {
            "bcrypt" => {
                if let Some(pass) = passphrase {
                    let mut kdfreader = Cursor::new(kdf);
                    let salt = kdfreader.read_string()?;
                    let round = kdfreader.read_uint32()?;
                    let mut output = Zeroizing::new(vec![0u8; cipher.key_len() + cipher.iv_len()]);
                    bcrypt_pbkdf(pass, &salt, round, &mut output)?;
                    output
                } else {
                    // Should have already checked passphrase
                    return Err(ErrorKind::Unknown.into());
                }
            }
            _ => {
                return Err(ErrorKind::UnsupportCipher.into());
            }
        };

        // Splitting key & iv
        let key = &keyder[..cipher.key_len()];
        let iv = &keyder[cipher.key_len()..];

        // Decrypt
        let mut cvec = CryptoVec::new();
        cvec.resize(cipher.cal_len(privkey_data.len()));
        let n = cipher.decrypt_to(&mut cvec, privkey_data, key, iv)?;
        cvec.resize(n);

        Ok(SshBuf::with_vec(cvec))
    } else {
        let cvec = CryptoVec::from_slice(privkey_data);
        Ok(SshBuf::with_vec(cvec))
    }
}

#[allow(clippy::many_single_char_names)]
fn decode_key(reader: &mut SshBuf) -> OsshResult<KeyPair> {
    let keystring = Zeroizing::new(reader.read_utf8()?);
    let keyname: &str = keystring.as_str();
    let key = match keyname {
        RSA_NAME | RSA_SHA256_NAME | RSA_SHA512_NAME => {
            let n = reader.read_mpint()?;
            let e = reader.read_mpint()?;
            let d = reader.read_mpint()?;
            let mut _iqmp = reader.read_mpint()?;
            let p = reader.read_mpint()?;
            let q = reader.read_mpint()?;
            let rsa = RsaPrivateKeyBuilder::new(n, e, d)?
                .set_factors(p, q)?
                .build();
            _iqmp.clear(); // Explicity clear the sensitive data
            match keyname {
                RSA_NAME => RsaKeyPair::from_ossl_rsa(rsa, RsaSignature::SHA1),
                RSA_SHA256_NAME => RsaKeyPair::from_ossl_rsa(rsa, RsaSignature::SHA2_256),
                RSA_SHA512_NAME => RsaKeyPair::from_ossl_rsa(rsa, RsaSignature::SHA2_512),
                _ => unreachable!(),
            }?
            .into()
        }
        DSA_NAME => {
            let p = reader.read_mpint()?;
            let q = reader.read_mpint()?;
            let g = reader.read_mpint()?;
            let pubkey = reader.read_mpint()?;
            let privkey = reader.read_mpint()?;
            let dsa = Dsa::from_private_components(p, q, g, privkey, pubkey)?;
            DsaKeyPair::from_ossl_dsa(dsa).into()
        }
        NIST_P256_NAME | NIST_P384_NAME | NIST_P521_NAME => {
            let curvename = Zeroizing::new(reader.read_utf8()?);
            let curvehint = EcCurve::from_name(keyname)?;
            let curve = EcCurve::from_str(&curvename)?;
            if curve != curvehint {
                return Err(ErrorKind::TypeNotMatch.into());
            }
            let pubkey = Zeroizing::new(reader.read_string()?);
            let mut privkey = reader.read_mpint()?;

            let keypair = EcDsaKeyPair::from_bytes(curve, &pubkey, &privkey)?.into();
            privkey.clear(); // Explicity clear the sensitive data
            keypair
        }
        ED25519_NAME => {
            let pk = Zeroizing::new(reader.read_string()?);
            let sk = Zeroizing::new(reader.read_string()?); // Actually is an ed25519 keypair
            Ed25519KeyPair::from_bytes(&pk, &sk)?.into()
        }
        _ => return Err(ErrorKind::UnsupportType.into()),
    };
    Ok(key)
}

// --------------------------------

pub fn serialize_ossh_privkey(
    key: &KeyPair,
    passphrase: &[u8],
    cipher: Cipher,
    kdf_rounds: u32,
) -> OsshResult<String> {
    let buf = encode_ossh_priv(key, passphrase, cipher, kdf_rounds)?;
    let mut keystr = String::new();
    keystr.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    let b64str = base64::encode(&buf);

    // Wrap the base64 data
    keystr.extend(b64str.chars().enumerate().flat_map(|(i, c)| {
        if i > 0 && i % 70 == 0 {
            Some('\n')
        } else {
            None
        }
        .into_iter()
        .chain(std::iter::once(c))
    }));

    keystr.push_str("\n-----END OPENSSH PRIVATE KEY-----\n");
    Ok(keystr)
}

pub fn encode_ossh_priv(
    key: &KeyPair,
    passphrase: &[u8],
    cipher: Cipher,
    kdf_rounds: u32,
) -> OsshResult<Vec<u8>> {
    if cipher.is_some() && passphrase.is_empty() {
        return Err(ErrorKind::IncorrectPass.into());
    }
    let rounds = if kdf_rounds > 0 {
        kdf_rounds
    } else {
        DEFAULT_ROUNDS
    };
    let mut salt = Zeroizing::from([0u8; SALT_LEN]);

    let ciphername = cipher.name();

    let mut buf = Vec::new();
    buf.write_all(KEY_MAGIC)?;
    buf.write_utf8(ciphername)?;
    if cipher.is_some() {
        buf.write_utf8(KDF_BCRYPT)?;

        // Generate salt
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut *salt);

        // Write KDF informations
        let mut kdfbuf = Vec::with_capacity(salt.len() + 8);
        kdfbuf.write_string(&*salt)?;
        kdfbuf.write_uint32(rounds)?;

        buf.write_string(&kdfbuf)?;
    } else {
        buf.write_utf8(KDF_NONE)?;
        buf.write_string(&[0; 0])?;
    }
    buf.write_uint32(1)?; // Number of keys (Currently always be 1)
    buf.write_string(&key.blob()?)?;

    let mut privbuf = SshBuf::new();

    // Generate checksum
    let mut rng = StdRng::from_entropy();
    let checksum: u32 = rng.gen();
    privbuf.write_uint32(checksum)?;
    privbuf.write_uint32(checksum)?;

    encode_key(key, &mut privbuf)?;

    privbuf.write_utf8(key.comment())?;

    // Writing padding
    let mut i = 0;
    while privbuf.len() % cipher.block_size() != 0 {
        i += 1;
        privbuf.write_u8((i & 0xff) as u8)?;
    }

    // Encrypt
    if cipher.is_some() {
        let encrypted = encrypt_ossh_priv(privbuf.as_slice(), passphrase, cipher, rounds, &*salt)?;
        buf.write_string(&encrypted)?;
    } else {
        buf.write_string(&privbuf.as_slice())?;
    };

    Ok(buf)
}

pub fn encrypt_ossh_priv(
    privkey: &[u8],
    passphrase: &[u8],
    cipher: Cipher,
    kdf_rounds: u32,
    salt: &[u8],
) -> OsshResult<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(ErrorKind::IncorrectPass.into());
    }

    // Derive key
    let mut keyder = Zeroizing::new(vec![0u8; cipher.key_len() + cipher.iv_len()]);
    bcrypt_pbkdf(passphrase, salt, kdf_rounds, &mut keyder)?;

    // Splitting key & iv
    let key = &keyder[..cipher.key_len()];
    let iv = &keyder[cipher.key_len()..];

    // Encrypt
    let encrypted = cipher.encrypt(privkey, key, iv)?;

    Ok(encrypted)
}

#[allow(clippy::many_single_char_names)]
fn encode_key<W: Write + ?Sized>(key: &KeyPair, buf: &mut W) -> OsshResult<()> {
    use crate::keys::Key;
    use crate::keys::KeyPairType;
    use openssl::bn::BigNumContext;
    use openssl::ec::PointConversionForm;

    buf.write_utf8(key.keyname())?;
    match &key.key {
        KeyPairType::RSA(rsa) => {
            let inner = rsa.ossl_rsa();

            buf.write_mpint(inner.n())?;
            buf.write_mpint(inner.e())?;
            buf.write_mpint(inner.d())?;
            buf.write_mpint(inner.iqmp().unwrap())?;
            buf.write_mpint(inner.p().unwrap())?;
            buf.write_mpint(inner.q().unwrap())?;
        }
        KeyPairType::DSA(dsa) => {
            let inner = dsa.ossl_dsa();

            buf.write_mpint(inner.p())?;
            buf.write_mpint(inner.q())?;
            buf.write_mpint(inner.g())?;
            buf.write_mpint(inner.pub_key())?;
            buf.write_mpint(inner.priv_key())?;
        }
        KeyPairType::ECDSA(ecdsa) => {
            buf.write_utf8(ecdsa.curve().ident())?;

            let inner = ecdsa.ossl_ec();
            let mut bn_ctx = BigNumContext::new()?;
            buf.write_string(&inner.public_key().to_bytes(
                inner.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )?)?;
            buf.write_mpint(inner.private_key())?;
        }
        KeyPairType::ED25519(ed25519) => {
            buf.write_string(&ed25519.key.public.to_bytes())?;
            buf.write_string(&ed25519.key.to_bytes())?; // Actually is an ed25519 keypair
        }
    }
    Ok(())
}
/*
fn cal_keysize(key: &KeyPair) -> usize {
    use crate::keys::Key;
    use crate::keys::KeyPairType;
    match key.key {
        KeyPairType::RSA(rsa) => {
            let mut s: usize = 0;
            let inner = rsa.ossl_rsa();
            s += inner.n().num_bytes() as usize;
            s += inner.e().num_bytes() as usize;
            s += inner.d().num_bytes() as usize;
            s += inner.iqmp().unwrap().num_bytes() as usize;
            s += inner.p().unwrap().num_bytes() as usize;
            s += inner.q().unwrap().num_bytes() as usize;
            // sshbuf string length size
            s += 4 * 6;
            s
        },
        KeyPairType::DSA(dsa) => {
            let mut s: usize = 0;
            let inner = dsa.ossl_dsa();
            s += inner.p().num_bytes() as usize;
            s += inner.q().num_bytes() as usize;
            s += inner.g().num_bytes() as usize;
            s += inner.pub_key().num_bytes() as usize;
            s += inner.priv_key().num_bytes() as usize;
            // sshbuf string length size
            s += 4 * 5;
            s
        },
        KeyPairType::ECDSA(ecdsa) => {
            let mut s: usize = 0;
            let inner = ecdsa.ossl_ec();
            s += ecdsa.keyname().len();
            s += inner.public_key().num_bytes() as usize;
            s += inner.private_key().num_bytes() as usize;
            // sshbuf string length size
            s += 4 * 3;
            s
        },
    }
}
*/
