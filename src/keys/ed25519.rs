use super::{Key, PrivKey, PubKey};
use crate::error::Error;
use crate::format::ossh_pubkey::*;
use ed25519_dalek::{Keypair, PublicKey, Signature, PUBLIC_KEY_LENGTH};
use std::fmt;

pub(crate) const ED25519_NAME: &'static str = "ssh-ed25519";

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    key: PublicKey,
}

impl Ed25519PublicKey {
    pub fn new(key: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ed25519_dalek::SignatureError> {
        Ok(Self {
            key: PublicKey::from_bytes(key)?,
        })
    }
}

impl Key for Ed25519PublicKey {
    fn size(&self) -> usize {
        256
    }

    fn keyname(&self) -> &'static str {
        ED25519_NAME
    }
}

impl PubKey for Ed25519PublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        Ok(encode_ed25519_pubkey(&self.key)?)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let ed25519_sig = Signature::from_bytes(sig)?;
        Ok(self.key.verify(data, &ed25519_sig).is_ok())
    }
}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&stringify_ossh_pubkey(self, None).unwrap())
    }
}

pub struct Ed25519KeyPair {
    key: Keypair,
}

impl Key for Ed25519KeyPair {
    fn size(&self) -> usize {
        256
    }

    fn keyname(&self) -> &'static str {
        ED25519_NAME
    }
}

impl Ed25519KeyPair {
    pub fn clone_public_key(&self) -> Result<Ed25519PublicKey, Error> {
        Ok(Ed25519PublicKey {
            key: self.key.public.clone(),
        })
    }
}

impl PubKey for Ed25519KeyPair {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        Ok(encode_ed25519_pubkey(&self.key.public)?)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let ed25519_sig = Signature::from_bytes(sig)?;
        Ok(self.key.verify(data, &ed25519_sig).is_ok())
    }
}

impl PrivKey for Ed25519KeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod test {
    use super::*;

    const pub_str: &'static str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMoWBluPErgKhNja3lHEf7ie6AVzR24mPRd742xEYodC";
    const pub_key: [u8; 0x20] = [
        0xca, 0x16, 0x06, 0x5b, 0x8f, 0x12, 0xb8, 0x0a, 0x84, 0xd8, 0xda, 0xde, 0x51, 0xc4, 0x7f,
        0xb8, 0x9e, 0xe8, 0x05, 0x73, 0x47, 0x6e, 0x26, 0x3d, 0x17, 0x7b, 0xe3, 0x6c, 0x44, 0x62,
        0x87, 0x42,
    ];

    fn get_test_pubkey() -> Result<Ed25519PublicKey, Error> {
        Ok(Ed25519PublicKey::new(&pub_key)?)
    }

    #[test]
    fn ed25519_publickey_serialize() {
        let key = get_test_pubkey().unwrap();
        assert_eq!(key.to_string(), String::from(pub_str));
    }

    #[test]
    fn ed25519_publickey_size() {
        let key = get_test_pubkey().unwrap();
        assert_eq!(key.size(), 256);
    }
}
