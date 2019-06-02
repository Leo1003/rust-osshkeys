use crate::error::Error;
use crate::FingerprintHash;
use openssl::hash::Hasher;

pub mod rsa;
pub mod dsa;
pub mod ecdsa;
pub mod ed25519;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    RSA,
    DSA,
    ECDSA,
    ED25519,
}

#[derive(Debug, PartialEq)]
enum PublicKeyType {
    RSA(rsa::RsaPublicKey),
    DSA(dsa::DsaPublicKey),
    ECDSA(ecdsa::EcDsaPublicKey),
    ED25519(ed25519::Ed25519PublicKey),
}

enum KeyPairType {
    RSA(rsa::RsaKeyPair),
    DSA(dsa::DsaKeyPair),
    ECDSA(ecdsa::EcDsaKeyPair),
    ED25519(ed25519::Ed25519KeyPair),
}

pub struct PublicKey {
    key: PublicKeyType,
    comment: String,
}

impl PublicKey {
    pub fn keytype(&self) -> KeyType {
        match &self.key {
            PublicKeyType::RSA(_) => KeyType::RSA,
            PublicKeyType::DSA(_) => KeyType::DSA,
            PublicKeyType::ECDSA(_) => KeyType::ECDSA,
            PublicKeyType::ED25519(_) => KeyType::ED25519,
        }
    }

    pub fn comment(&self) -> &String {
        &self.comment
    }

    pub fn comment_mut(&mut self) -> &mut String {
        &mut self.comment
    }

    fn inner_key(&self) -> &PubKey {
        match &self.key {
            PublicKeyType::RSA(key) => key,
            PublicKeyType::DSA(key) => key,
            PublicKeyType::ECDSA(key) => key,
            PublicKeyType::ED25519(key) => key,
        }
    }
}

impl Key for PublicKey {
    fn size(&self) -> usize {
        self.inner_key().size()
    }

    fn keyname(&self) -> &'static str {
        self.inner_key().keyname()
    }
}

impl PubKey for PublicKey {
    fn blob(&self) -> Result<Vec<u8>, Error> {
        self.inner_key().blob()
    }

    fn fingerprint(&self, hash: FingerprintHash) -> Result<Vec<u8>, Error> {
        self.inner_key().fingerprint(hash)
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.inner_key().verify(data, sig)
    }
}

pub struct KeyPair {
    key: KeyPairType,
    comment: String,
}

impl KeyPair {
    pub fn keytype(&self) -> KeyType {
        match &self.key {
            KeyPairType::RSA(_) => KeyType::RSA,
            KeyPairType::DSA(_) => KeyType::DSA,
            KeyPairType::ECDSA(_) => KeyType::ECDSA,
            KeyPairType::ED25519(_) => KeyType::ED25519,
        }
    }

    pub fn comment(&self) -> &String {
        &self.comment
    }

    pub fn comment_mut(&mut self) -> &mut String {
        &mut self.comment
    }

    pub fn clone_public_key(&self) -> Result<PublicKey, Error> {
        let key = match &self.key {
            KeyPairType::RSA(key) => PublicKeyType::RSA(key.clone_public_key()?),
            KeyPairType::DSA(key) => PublicKeyType::DSA(key.clone_public_key()?),
            KeyPairType::ECDSA(key) => PublicKeyType::ECDSA(key.clone_public_key()?),
            KeyPairType::ED25519(key) => PublicKeyType::ED25519(key.clone_public_key()?),
        };
        Ok(PublicKey {
            key: key,
            comment: self.comment().clone()
        })
    }

    fn inner_key(&self) -> &PrivKey {
        match &self.key {
            KeyPairType::RSA(key) => key,
            KeyPairType::DSA(key) => key,
            KeyPairType::ECDSA(key) => key,
            KeyPairType::ED25519(key) => key,
        }
    }

    fn inner_key_pub(&self) -> &PubKey {
        match &self.key {
            KeyPairType::RSA(key) => key,
            KeyPairType::DSA(key) => key,
            KeyPairType::ECDSA(key) => key,
            KeyPairType::ED25519(key) => key,
        }
    }
}

impl Key for KeyPair {
    fn size(&self) -> usize {
        self.inner_key().size()
    }
    fn keyname(&self) -> &'static str {
        self.inner_key().keyname()
    }
}

impl PubKey for KeyPair {
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.inner_key_pub().verify(data, sig)
    }
    fn blob(&self) -> Result<Vec<u8>, Error> {
        self.inner_key_pub().blob()
    }
}

impl PrivKey for KeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner_key().sign(data)
    }
}

pub trait Key {
    fn size(&self) -> usize;
    fn keyname(&self) -> &'static str;
}

pub trait PubKey: Key {
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error>;
    fn blob(&self) -> Result<Vec<u8>, Error>;
    fn fingerprint(&self, hash: FingerprintHash) -> Result<Vec<u8>, Error> {
        let b = self.blob()?;
        let mut hasher = Hasher::new(hash.get_digest())?;
        hasher.update(&b)?;
        let dig = hasher.finish()?;
        Ok(dig.to_vec())
    }
}

pub trait PrivKey: Key {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}
