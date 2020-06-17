use crate::cipher::Cipher;
use crate::error::*;
use crate::format::ossh_privkey::*;
use crate::format::ossh_pubkey::*;
use crate::format::parse_keystr;
use crate::format::pem::*;
use crate::format::pkcs8::*;
use digest::Digest;
use md5::Md5;
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use sha2::{Sha256, Sha512};
use std::fmt;

/// DSA key type
pub mod dsa;
/// EcDSA key type
pub mod ecdsa;
/// Ed25519 key type
pub mod ed25519;
/// RSA key type
pub mod rsa;

/// An enum representing the hash function used to generate fingerprint
///
/// Used with [`PublicPart::fingerprint()`](trait.PublicPart.html#method.fingerprint) to generate different types fingerprint.
///
/// # Hash Algorithm
/// MD5: This is the default fingerprint type in older versions of openssh.
///
/// SHA2-256: Since OpenSSH 6.8, this became the default option of fingerprint.
///
/// SHA2-512: Although not being documented, it can also be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintHash {
    MD5,
    SHA256,
    SHA512,
}

impl FingerprintHash {
    fn hash(self, data: &[u8]) -> Vec<u8> {
        fn digest_hash<D: Digest>(hasher: &mut D, data: &[u8]) -> Vec<u8> {
            hasher.update(data);
            hasher.finalize_reset().to_vec()
        }
        match self {
            FingerprintHash::MD5 => digest_hash(&mut Md5::default(), data),
            FingerprintHash::SHA256 => digest_hash(&mut Sha256::default(), data),
            FingerprintHash::SHA512 => digest_hash(&mut Sha512::default(), data),
        }
    }
}

/// An enum representing the type of key being stored
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    RSA,
    DSA,
    ECDSA,
    ED25519,
}

#[derive(Debug, PartialEq)]
pub(crate) enum PublicKeyType {
    RSA(rsa::RsaPublicKey),
    DSA(dsa::DsaPublicKey),
    ECDSA(ecdsa::EcDsaPublicKey),
    ED25519(ed25519::Ed25519PublicKey),
}

pub(crate) enum KeyPairType {
    RSA(rsa::RsaKeyPair),
    DSA(dsa::DsaKeyPair),
    ECDSA(ecdsa::EcDsaKeyPair),
    ED25519(ed25519::Ed25519KeyPair),
}

/// General public key type
///
/// This is a type to make it easy to store different types of public key in the container.
/// Each can contain one of the types supported in this crate.
///
/// Public key is usually stored in the `.pub` file when generating the key.
pub struct PublicKey {
    pub(crate) key: PublicKeyType,
    comment: String,
}

impl PublicKey {
    /// Parse the openssh public key file
    pub fn from_keystr(keystr: &str) -> OsshResult<Self> {
        Ok(parse_ossh_pubkey(keystr)?)
    }

    /// Indicate the key type being stored
    pub fn keytype(&self) -> KeyType {
        match &self.key {
            PublicKeyType::RSA(_) => KeyType::RSA,
            PublicKeyType::DSA(_) => KeyType::DSA,
            PublicKeyType::ECDSA(_) => KeyType::ECDSA,
            PublicKeyType::ED25519(_) => KeyType::ED25519,
        }
    }

    /// Get the comment of the key
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Get the mutable reference of the key comment
    pub fn comment_mut(&mut self) -> &mut String {
        &mut self.comment
    }

    /// Serialize as OpenSSH format of the public key
    pub fn serialize(&self) -> OsshResult<String> {
        serialize_ossh_pubkey(self, &self.comment)
    }

    fn inner_key(&self) -> &dyn PublicParts {
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

impl PublicParts for PublicKey {
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

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.serialize().unwrap())
    }
}

impl From<rsa::RsaPublicKey> for PublicKey {
    fn from(inner: rsa::RsaPublicKey) -> PublicKey {
        PublicKey {
            key: PublicKeyType::RSA(inner),
            comment: String::new(),
        }
    }
}

impl From<dsa::DsaPublicKey> for PublicKey {
    fn from(inner: dsa::DsaPublicKey) -> PublicKey {
        PublicKey {
            key: PublicKeyType::DSA(inner),
            comment: String::new(),
        }
    }
}

impl From<ecdsa::EcDsaPublicKey> for PublicKey {
    fn from(inner: ecdsa::EcDsaPublicKey) -> PublicKey {
        PublicKey {
            key: PublicKeyType::ECDSA(inner),
            comment: String::new(),
        }
    }
}

impl From<ed25519::Ed25519PublicKey> for PublicKey {
    fn from(inner: ed25519::Ed25519PublicKey) -> PublicKey {
        PublicKey {
            key: PublicKeyType::ED25519(inner),
            comment: String::new(),
        }
    }
}

/// General key pair type
///
/// This is a type to make it easy to store different types of key pair in the container.
/// Each can contain one of the types supported in this crate.
///
/// Key pair is the so-called "private key" which contains both public and private parts of an asymmetry key.
pub struct KeyPair {
    pub(crate) key: KeyPairType,
    comment: String,
}

impl KeyPair {
    pub(crate) fn from_ossl_pkey(pkey: &PKeyRef<Private>) -> OsshResult<Self> {
        match pkey.id() {
            Id::RSA => {
                Ok(rsa::RsaKeyPair::from_ossl_rsa(pkey.rsa()?, rsa::RsaSignature::SHA1)?.into())
            }
            Id::DSA => Ok(dsa::DsaKeyPair::from_ossl_dsa(pkey.dsa()?).into()),
            Id::EC => Ok(ecdsa::EcDsaKeyPair::from_ossl_ec(pkey.ec_key()?)?.into()),
            _ => Err(ErrorKind::UnsupportType.into()),
        }
    }

    pub(crate) fn ossl_pkey(&self) -> OsshResult<PKey<Private>> {
        match &self.key {
            KeyPairType::RSA(key) => Ok(PKey::from_rsa(key.ossl_rsa().to_owned())?),
            KeyPairType::DSA(key) => Ok(PKey::from_dsa(key.ossl_dsa().to_owned())?),
            KeyPairType::ECDSA(key) => Ok(PKey::from_ec_key(key.ossl_ec().to_owned())?),
            _ => Err(ErrorKind::UnsupportType.into()),
        }
    }

    /// Parse a keypair from supporting file types
    ///
    /// The passphrase is required if the keypair is encrypted.
    ///
    /// # OpenSSL PEM
    /// - Begin with `-----BEGIN DSA PRIVATE KEY-----` for dsa key.
    /// - Begin with `-----BEGIN RSA PRIVATE KEY-----` for rsa key.
    /// - Begin with `-----BEGIN EC PRIVATE KEY-----` for ecdsa key.
    /// - This file type doesn't support Ed25519
    ///
    /// # PKCS#8 Format
    /// - Begin with `-----BEGIN PRIVATE KEY-----`
    ///
    /// # Openssh
    /// - Begin with `-----BEGIN OPENSSH PRIVATE KEY-----`
    ///
    /// This is the new format which is supported since OpenSSH 6.5, and it became the default format in OpenSSH 7.8.
    /// The Ed25519 key can only be stored in this type.
    pub fn from_keystr(pem: &str, passphrase: Option<&str>) -> OsshResult<Self> {
        Ok(parse_keystr(pem.as_bytes(), passphrase)?)
    }

    /// Generate a key of the specified type and size
    ///
    /// # Key Size
    /// There are some limitations to the key size:
    /// - RSA: the size should `>= 1024` and `<= 16384` bits.
    /// - DSA: the size should be `1024` bits.
    /// - EcDSA: the size should be `256`, `384`, or `521` bits.
    /// - Ed25519: the size should be `256` bits.
    ///
    /// If the key size parameter is zero, then it will use the default size to generate the key
    /// - RSA: `2048` bits
    /// - DSA: `1024` bits
    /// - EcDSA: `256` bits
    /// - Ed25519: `256` bits
    pub fn generate(keytype: KeyType, bits: usize) -> OsshResult<Self> {
        Ok(match keytype {
            KeyType::RSA => rsa::RsaKeyPair::generate(bits)?.into(),
            KeyType::DSA => dsa::DsaKeyPair::generate(bits)?.into(),
            KeyType::ECDSA => ecdsa::EcDsaKeyPair::generate(bits)?.into(),
            KeyType::ED25519 => ed25519::Ed25519KeyPair::generate(bits)?.into(),
        })
    }

    /// Indicate the key type being stored
    pub fn keytype(&self) -> KeyType {
        match &self.key {
            KeyPairType::RSA(_) => KeyType::RSA,
            KeyPairType::DSA(_) => KeyType::DSA,
            KeyPairType::ECDSA(_) => KeyType::ECDSA,
            KeyPairType::ED25519(_) => KeyType::ED25519,
        }
    }

    /// Serialize the keypair to the OpenSSL PEM format
    ///
    /// If the passphrase is given (set to `Some(...)`), then the generated PEM key will be encrypted.
    pub fn serialize_pem(&self, passphrase: Option<&str>) -> OsshResult<String> {
        Ok(stringify_pem_privkey(&self, passphrase)?)
    }

    /// Serialize the keypair to the OpenSSL PKCS#8 PEM format
    ///
    /// If the passphrase is given (set to `Some(...)`), then the generated PKCS#8 key will be encrypted.
    pub fn serialize_pkcs8(&self, passphrase: Option<&str>) -> OsshResult<String> {
        Ok(serialize_pkcs8_privkey(&self, passphrase)?)
    }

    /// Serialize the keypair to the OpenSSH private key format
    ///
    /// If the passphrase is given (set to `Some(...)`) and cipher is not null,
    /// then the generated private key will be encrypted.
    pub fn serialize_openssh(
        &self,
        passphrase: Option<&str>,
        cipher: Cipher,
    ) -> OsshResult<String> {
        if let Some(passphrase) = passphrase {
            Ok(serialize_ossh_privkey(self, passphrase, cipher, 0)?)
        } else {
            Ok(serialize_ossh_privkey(self, "", Cipher::Null, 0)?)
        }
    }

    /// Get the comment of the key
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Get the mutable reference of the key comment
    pub fn comment_mut(&mut self) -> &mut String {
        &mut self.comment
    }

    /// Get the OpenSSH public key of the public parts
    pub fn serialize_publickey(&self) -> OsshResult<String> {
        serialize_ossh_pubkey(self, &self.comment)
    }

    /// Clone the public parts of the key pair
    pub fn clone_public_key(&self) -> Result<PublicKey, Error> {
        let key = match &self.key {
            KeyPairType::RSA(key) => PublicKeyType::RSA(key.clone_public_key()?),
            KeyPairType::DSA(key) => PublicKeyType::DSA(key.clone_public_key()?),
            KeyPairType::ECDSA(key) => PublicKeyType::ECDSA(key.clone_public_key()?),
            KeyPairType::ED25519(key) => PublicKeyType::ED25519(key.clone_public_key()?),
        };
        Ok(PublicKey {
            key,
            comment: self.comment.clone(),
        })
    }

    fn inner_key(&self) -> &dyn PrivateParts {
        match &self.key {
            KeyPairType::RSA(key) => key,
            KeyPairType::DSA(key) => key,
            KeyPairType::ECDSA(key) => key,
            KeyPairType::ED25519(key) => key,
        }
    }

    fn inner_key_pub(&self) -> &dyn PublicParts {
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

impl PublicParts for KeyPair {
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.inner_key_pub().verify(data, sig)
    }
    fn blob(&self) -> Result<Vec<u8>, Error> {
        self.inner_key_pub().blob()
    }
}

impl PrivateParts for KeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner_key().sign(data)
    }
}

impl From<rsa::RsaKeyPair> for KeyPair {
    fn from(inner: rsa::RsaKeyPair) -> KeyPair {
        KeyPair {
            key: KeyPairType::RSA(inner),
            comment: String::new(),
        }
    }
}

impl From<dsa::DsaKeyPair> for KeyPair {
    fn from(inner: dsa::DsaKeyPair) -> KeyPair {
        KeyPair {
            key: KeyPairType::DSA(inner),
            comment: String::new(),
        }
    }
}

impl From<ecdsa::EcDsaKeyPair> for KeyPair {
    fn from(inner: ecdsa::EcDsaKeyPair) -> KeyPair {
        KeyPair {
            key: KeyPairType::ECDSA(inner),
            comment: String::new(),
        }
    }
}

impl From<ed25519::Ed25519KeyPair> for KeyPair {
    fn from(inner: ed25519::Ed25519KeyPair) -> KeyPair {
        KeyPair {
            key: KeyPairType::ED25519(inner),
            comment: String::new(),
        }
    }
}

/// The basic trait of a key
pub trait Key {
    /// The size in bits of the key
    fn size(&self) -> usize;
    /// The key name of the key
    fn keyname(&self) -> &'static str;
}

/// A trait for operations of a public key
pub trait PublicParts: Key {
    /// Verify the data with a detached signature, returning true if the signature is not malformed
    fn verify(&self, data: &[u8], sig: &[u8]) -> OsshResult<bool>;
    /// Return the binary representation of the public key
    fn blob(&self) -> OsshResult<Vec<u8>>;
    /// Hash the blob of the public key to generate the fingerprint
    fn fingerprint(&self, hash: FingerprintHash) -> OsshResult<Vec<u8>> {
        let b = self.blob()?;
        Ok(hash.hash(&b))
    }
}

/// A trait for operations of a private key
pub trait PrivateParts: Key {
    /// Sign the data with the key, returning the "detached" signature
    fn sign(&self, data: &[u8]) -> OsshResult<Vec<u8>>;
}
