use crate::error::*;
use crate::keys::{dsa::*, ecdsa::*, ed25519::*, rsa::*, KeyPair, PubKey, PublicKey};
use crate::sshbuf::{SshReadExt, SshWriteExt};
use ed25519_dalek::PublicKey as Ed25519PubKey;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use std::io::Cursor;
use zeroize::{Zeroize, Zeroizing};
use openssl::symm::{Cipher, Crypter, Mode};

pub fn decode_ossh_priv(keydata: &[u8], passphrase: Option<&[u8]>) -> OsshResult<KeyPair> {
    if keydata.len() >= 16 && &keydata[0..15] == b"openssh-key-v1\0" {
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
        let checksum0 = Zeroizing::new(secret_reader.read_uint32()?);
        let checksum1 = Zeroizing::new(secret_reader.read_uint32()?);
        if *checksum0 != *checksum1 {
            return Err(ErrorKind::IncorrectPass.into());
        }
        let keyname = secret_reader.read_utf8()?;
        // TODO: Decode private key
        match keyname.as_str() {
            RSA_NAME | RSA_SHA256_NAME | RSA_SHA512_NAME => {
                unimplemented!()
            },
            DSA_NAME => {
                unimplemented!()
            },
            NIST_P256_NAME | NIST_P384_NAME | NIST_P521_NAME => {
                unimplemented!()
            },
            ED25519_NAME => {
                unimplemented!()
            },
            _ => Err(ErrorKind::UnsupportType.into()),
        }
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
    let cipher = match ciphername {
        "3des-cbc" => Some(Cipher::des_ede3_cbc()),
        "aes128-cbc" => Some(Cipher::aes_128_cbc()),
        //"aes192-cbc", // Openssl doesn't implement aes192
        "aes256-cbc" | "rijndael-cbc@lysator.liu.se" => Some(Cipher::aes_256_cbc()),
        "aes128-ctr" => Some(Cipher::aes_128_ctr()),
        //"aes192-ctr", // Openssl doesn't implement aes192
        "aes256-ctr" => Some(Cipher::aes_256_ctr()),
        "none" => None,
        _ => return Err(ErrorKind::UnsupportCipher.into()),
    };
    if (passphrase.map_or(false, |pass| !pass.is_empty())) && cipher.is_some() {
        return Err(ErrorKind::IncorrectPass.into());
    }
    if kdfname != "none" && kdfname != "bcrypt" {
        return Err(ErrorKind::UnsupportCipher.into());
    }
    if kdfname == "none" && cipher.is_some() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    let blocksize = cipher.map_or(8, |c| c.block_size());
    if privkey_data.len() < blocksize || privkey_data.len() % blocksize != 0 {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    if let Some(cipher) = cipher {
        let keyder: &[u8] = match kdfname {
            "bcrypt" => {
                let mut kdfreader = Cursor::new(kdf);
                let salt = Zeroizing::new(kdfreader.read_string()?);
                let round = Zeroizing::new(kdfreader.read_uint32()?);
                // TODO: implement bcrypt_pbkdf
                unimplemented!()
            },
            _ => {
                return Err(ErrorKind::UnsupportCipher.into());
            }
        };
        let key = &keyder[..32];
        let iv = &keyder[32..];
        let crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&iv))?;
        crypter.pad(false);
        let mut decrypted = vec![0; privkey_data.len() + blocksize];
        let mut n = crypter.update(privkey_data, &mut decrypted)?;
        n += crypter.finalize(&mut decrypted[n..])?;
        decrypted.truncate(n);
        Ok(decrypted)
    } else {
        Ok(privkey_data.to_vec())
    }
}



