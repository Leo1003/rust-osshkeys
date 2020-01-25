use crate::bcrypt_pbkdf::bcrypt_pbkdf;
use crate::cipher::Cipher;
use crate::error::*;
use crate::keys::{dsa::*, ecdsa::*, ed25519::*, rsa::*, KeyPair, PublicKey, PublicParts};
use crate::sshbuf::{SshReadExt, SshWriteExt, ZeroizeReadExt};
use openssl::dsa::Dsa;
use openssl::rsa::RsaPrivateKeyBuilder;

use std::io::{Cursor, Read as _};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

const KEY_MAGIC: &[u8] = b"openssh-key-v1\0";
#[allow(clippy::many_single_char_names)]
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
        let keyname = secret_reader.read_utf8_zeroize()?;

        // Decode private key
        let mut keypair: KeyPair = match keyname.as_str() {
            RSA_NAME | RSA_SHA256_NAME | RSA_SHA512_NAME => {
                let n = secret_reader.read_mpint_zeroize()?;
                let e = secret_reader.read_mpint_zeroize()?;
                let d = secret_reader.read_mpint_zeroize()?;
                let mut _iqmp = secret_reader.read_mpint_zeroize()?;
                let p = secret_reader.read_mpint_zeroize()?;
                let q = secret_reader.read_mpint_zeroize()?;
                let rsa = RsaPrivateKeyBuilder::new(n, e, d)?
                    .set_factors(p, q)?
                    .build();
                _iqmp.clear(); // Explicity clear the sensitive data
                match keyname.as_str() {
                    RSA_NAME => RsaKeyPair::from_ossl_rsa(rsa, RsaSignature::SHA1),
                    RSA_SHA256_NAME => RsaKeyPair::from_ossl_rsa(rsa, RsaSignature::SHA2_256),
                    RSA_SHA512_NAME => RsaKeyPair::from_ossl_rsa(rsa, RsaSignature::SHA2_512),
                    _ => unreachable!(),
                }?
                .into()
            }
            DSA_NAME => {
                let p = secret_reader.read_mpint_zeroize()?;
                let q = secret_reader.read_mpint_zeroize()?;
                let g = secret_reader.read_mpint_zeroize()?;
                let pubkey = secret_reader.read_mpint_zeroize()?;
                let privkey = secret_reader.read_mpint_zeroize()?;
                let dsa = Dsa::from_private_components(p, q, g, privkey, pubkey)?;
                DsaKeyPair::from_ossl_dsa(dsa).into()
            }
            NIST_P256_NAME | NIST_P384_NAME | NIST_P521_NAME => {
                let curvename = secret_reader.read_utf8_zeroize()?;
                let curvehint = EcCurve::from_name(keyname.as_str())?;
                let curve = EcCurve::from_str(&curvename)?;
                if curve != curvehint {
                    return Err(ErrorKind::TypeNotMatch.into());
                }
                let pubkey = secret_reader.read_string_zeroize()?;
                let mut privkey = secret_reader.read_mpint_zeroize()?;

                let keypair = EcDsaKeyPair::from_bytes(curve, &pubkey, &privkey)?.into();
                privkey.clear(); // Explicity clear the sensitive data
                keypair
            }
            ED25519_NAME => {
                let pk = Zeroizing::new(secret_reader.read_string_zeroize()?);
                let sk = Zeroizing::new(secret_reader.read_string_zeroize()?); // Actually is an ed25519 keypair
                Ed25519KeyPair::from_bytes(&pk, &sk)?.into()
            }
            _ => return Err(ErrorKind::UnsupportType.into()),
        };

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
                    let mut output =
                        Zeroizing::new(vec![0u8; cipher.key_len() + cipher.iv_len()]);
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
