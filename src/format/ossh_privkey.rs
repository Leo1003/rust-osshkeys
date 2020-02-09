use crate::bcrypt_pbkdf::bcrypt_pbkdf;
use crate::cipher::Cipher;
use crate::error::*;
use crate::keys::{dsa::*, ecdsa::*, ed25519::*, rsa::*, KeyPair, PublicKey, PublicParts};
use crate::sshbuf::{SshReadExt, SshWriteExt, ZeroizeReadExt};
use byteorder::WriteBytesExt;
use openssl::dsa::Dsa;
use openssl::rsa::RsaPrivateKeyBuilder;
use std::io::Read;
use std::io::Write;

use rand::prelude::*;
use rand::rngs::StdRng;
use std::io::{Cursor, Read as _, Write as _};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

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

        let decrypted = Zeroizing::new(decrypt_ossh_priv(
            &encrypted,
            passphrase,
            &ciphername,
            &kdfname,
            &kdf,
        )?);
        let mut secret_reader = Cursor::new(decrypted.as_slice());
        let checksum0 = secret_reader.read_uint32_zeroize()?;
        let checksum1 = secret_reader.read_uint32_zeroize()?;
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
) -> OsshResult<Vec<u8>> {
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
                    let salt = kdfreader.read_string_zeroize()?;
                    let round = kdfreader.read_uint32_zeroize()?;
                    let mut output = Zeroizing::new(vec![0u8; cipher.key_len() + cipher.iv_len()]);
                    bcrypt_pbkdf(pass, &salt, *round, &mut output)?;
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
        let decrypted = cipher.decrypt(privkey_data, key, iv)?;

        Ok(decrypted)
    } else {
        Ok(privkey_data.to_vec())
    }
}

#[allow(clippy::many_single_char_names)]
fn decode_key<R: Read + ?Sized>(reader: &mut R) -> OsshResult<KeyPair> {
    let keystring = reader.read_utf8_zeroize()?;
    let keyname: &str = keystring.as_str();
    let key = match keyname {
        RSA_NAME | RSA_SHA256_NAME | RSA_SHA512_NAME => {
            let n = reader.read_mpint_zeroize()?;
            let e = reader.read_mpint_zeroize()?;
            let d = reader.read_mpint_zeroize()?;
            let mut _iqmp = reader.read_mpint_zeroize()?;
            let p = reader.read_mpint_zeroize()?;
            let q = reader.read_mpint_zeroize()?;
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
            let p = reader.read_mpint_zeroize()?;
            let q = reader.read_mpint_zeroize()?;
            let g = reader.read_mpint_zeroize()?;
            let pubkey = reader.read_mpint_zeroize()?;
            let privkey = reader.read_mpint_zeroize()?;
            let dsa = Dsa::from_private_components(p, q, g, privkey, pubkey)?;
            DsaKeyPair::from_ossl_dsa(dsa).into()
        }
        NIST_P256_NAME | NIST_P384_NAME | NIST_P521_NAME => {
            let curvename = reader.read_utf8_zeroize()?;
            let curvehint = EcCurve::from_name(keyname)?;
            let curve = EcCurve::from_str(&curvename)?;
            if curve != curvehint {
                return Err(ErrorKind::TypeNotMatch.into());
            }
            let pubkey = reader.read_string_zeroize()?;
            let mut privkey = reader.read_mpint_zeroize()?;

            let keypair = EcDsaKeyPair::from_bytes(curve, &pubkey, &privkey)?.into();
            privkey.clear(); // Explicity clear the sensitive data
            keypair
        }
        ED25519_NAME => {
            let pk = Zeroizing::new(reader.read_string_zeroize()?);
            let sk = Zeroizing::new(reader.read_string_zeroize()?); // Actually is an ed25519 keypair
            Ed25519KeyPair::from_bytes(&pk, &sk)?.into()
        }
        _ => return Err(ErrorKind::UnsupportType.into()),
    };
    Ok(key)
}

// --------------------------------

pub fn serialize_ossh_priv(
    key: &KeyPair,
    passphrase: &[u8],
    cipher: Cipher,
    kdf_rounds: u32,
) -> OsshResult<String> {
    let buf = encode_ossh_priv(key, passphrase, cipher, kdf_rounds)?;
    let mut keystr = String::new();
    keystr.push_str("-----BEGIN OPENSSH PRIVATE KEY-----");
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

    keystr.push_str("-----END OPENSSH PRIVATE KEY-----");
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
        buf.write_string(&*salt)?;
        buf.write_uint32(rounds)?;
    } else {
        buf.write_utf8(KDF_NONE)?;
        buf.write_string(&[0; 0])?;
    }
    buf.write_string(&key.blob()?)?;

    // FIXME: alloc a large size memory to prevent resizing
    //let reserve_len = todo!();
    let mut privbuf = Zeroizing::new(Vec::with_capacity(16384));

    // Generate checksum
    let mut rng = StdRng::from_entropy();
    let checksum: u32 = rng.gen();
    privbuf.write_uint32(checksum)?;
    privbuf.write_uint32(checksum)?;

    encode_key(key, &mut *privbuf)?;

    privbuf.write_utf8(key.comment())?;

    // Writing padding
    let mut i = 0;
    while privbuf.len() % cipher.block_size() != 0 {
        i += 1;
        privbuf.write_u8((i & 0xff) as u8)?;
    }

    // Encrypt
    if cipher.is_some() {
        let encrypted = encrypt_ossh_priv(&privbuf, passphrase, cipher, rounds, &*salt)?;
        buf.write_string(&encrypted)?;
    } else {
        buf.write_string(&privbuf)?;
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
            let n = Zeroizing::new(inner.n().to_vec());
            let e = Zeroizing::new(inner.e().to_vec());
            let d = Zeroizing::new(inner.d().to_vec());
            let iqmp = Zeroizing::new(inner.iqmp().unwrap().to_vec());
            let p = Zeroizing::new(inner.p().unwrap().to_vec());
            let q = Zeroizing::new(inner.q().unwrap().to_vec());

            buf.write_string(&n)?;
            buf.write_string(&e)?;
            buf.write_string(&d)?;
            buf.write_string(&iqmp)?;
            buf.write_string(&p)?;
            buf.write_string(&q)?;
        }
        KeyPairType::DSA(dsa) => {
            let inner = dsa.ossl_dsa();
            let p = Zeroizing::new(inner.p().to_vec());
            let q = Zeroizing::new(inner.q().to_vec());
            let g = Zeroizing::new(inner.g().to_vec());
            let pubkey = Zeroizing::new(inner.pub_key().to_vec());
            let privkey = Zeroizing::new(inner.priv_key().to_vec());

            buf.write_string(&p)?;
            buf.write_string(&q)?;
            buf.write_string(&g)?;
            buf.write_string(&pubkey)?;
            buf.write_string(&privkey)?;
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
            let privkey = Zeroizing::new(inner.private_key().to_vec());
            buf.write_string(&privkey)?;
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
