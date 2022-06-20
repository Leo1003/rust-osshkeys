use crate::cipher::Cipher;
use crate::error::*;
use crate::format::ossh_privkey::*;
use crate::format::ossh_pubkey::*;
use crate::format::parse_keystr;
use crate::format::pem::*;
use crate::format::pkcs8::*;
use digest::{Digest, FixedOutputReset};
use md5::Md5;
use openssl::pkey::{Id, PKey, PKeyRef, Private, Public};
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

/// The name of the MD5 hashing algorithm returned by [`FingerprintHash::name()`](enum.FingerprintHash.html#method.name)
pub const MD5_NAME: &str = "MD5";
/// The name of the sha2-256 algorithm returned by [`FingerprintHash::name()`](enum.FingerprintHash.html#method.name)
pub const SHA256_NAME: &str = "SHA256";
/// The name of the sha2-512 algorithm returned by [`FingerprintHash::name()`](enum.FingerprintHash.html#method.name)
pub const SHA512_NAME: &str = "SHA512";

/// An enum representing the hash function used to generate fingerprint
///
/// Used with [`PublicPart::fingerprint()`](trait.PublicPart.html#method.fingerprint) and
/// [`PublicPart::fingerprint_randomart()`](trait.PublicPart.html#method.fingerprint) to generate
/// different types fingerprint and randomarts.
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
        fn digest_hash<D>(hasher: &mut D, data: &[u8]) -> Vec<u8>
        where
            D: Digest + FixedOutputReset,
        {
            // Fix error[E0034]: multiple applicable items in scope
            Digest::update(hasher, data);
            hasher.finalize_reset().to_vec()
        }
        match self {
            FingerprintHash::MD5 => digest_hash(&mut Md5::default(), data),
            FingerprintHash::SHA256 => digest_hash(&mut Sha256::default(), data),
            FingerprintHash::SHA512 => digest_hash(&mut Sha512::default(), data),
        }
    }
    fn name(self) -> &'static str {
        match self {
            FingerprintHash::MD5 => MD5_NAME,
            FingerprintHash::SHA256 => SHA256_NAME,
            FingerprintHash::SHA512 => SHA512_NAME,
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

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
pub(crate) enum PublicKeyType {
    RSA(rsa::RsaPublicKey),
    DSA(dsa::DsaPublicKey),
    ECDSA(ecdsa::EcDsaPublicKey),
    ED25519(ed25519::Ed25519PublicKey),
}

#[allow(clippy::upper_case_acronyms)]
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
    pub(crate) fn from_ossl_pkey(pkey: &PKeyRef<Public>) -> OsshResult<Self> {
        match pkey.id() {
            Id::RSA => {
                Ok(rsa::RsaPublicKey::from_ossl_rsa(pkey.rsa()?, rsa::RsaSignature::SHA1)?.into())
            }
            Id::DSA => Ok(dsa::DsaPublicKey::from_ossl_dsa(pkey.dsa()?).into()),
            Id::EC => Ok(ecdsa::EcDsaPublicKey::from_ossl_ec(pkey.ec_key()?)?.into()),
            Id::ED25519 => Ok(ed25519::Ed25519PublicKey::from_ossl_ed25519(&pkey.raw_public_key()?)?.into()),
            _ => Err(ErrorKind::UnsupportType.into()),
        }
    }

    /// Parse the openssh/PEM format public key file
    pub fn from_keystr(keystr: &str) -> OsshResult<Self> {
        if keystr.trim().starts_with("-----BEGIN") {
            // PEM format
            Ok(parse_pem_pubkey(keystr.as_bytes())?)
        } else {
            // openssh format
            Ok(parse_ossh_pubkey(keystr)?)
        }
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

    /// Serialize the public key as OpenSSH format
    pub fn serialize(&self) -> OsshResult<String> {
        serialize_ossh_pubkey(self, &self.comment)
    }

    /// Serialize the public key as PEM format
    ///
    /// # Representation
    /// - Begin with `-----BEGIN PUBLIC KEY-----` for dsa key.
    /// - Begin with `-----BEGIN RSA PUBLIC KEY-----` for rsa key.
    /// - Begin with `-----BEGIN PUBLIC KEY-----` for ecdsa key.
    /// - Begin with `-----BEGIN PUBLIC KEY-----` for ed25519 key.
    ///
    /// # Note
    /// This format cannot store the comment!
    pub fn serialize_pem(&self) -> OsshResult<String> {
        stringify_pem_pubkey(self)
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

    fn short_keyname(&self) -> &'static str {
        self.inner_key().short_keyname()
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
            Id::ED25519 => Ok(ed25519::Ed25519KeyPair::from_ossl_ed25519(&pkey.raw_private_key()?)?.into()),
            _ => Err(ErrorKind::UnsupportType.into()),
        }
    }

    pub(crate) fn ossl_pkey(&self) -> OsshResult<PKey<Private>> {
        match &self.key {
            KeyPairType::RSA(key) => Ok(PKey::from_rsa(key.ossl_rsa().to_owned())?),
            KeyPairType::DSA(key) => Ok(PKey::from_dsa(key.ossl_dsa().to_owned())?),
            KeyPairType::ECDSA(key) => Ok(PKey::from_ec_key(key.ossl_ec().to_owned())?),
            KeyPairType::ED25519(key) => Ok(key.ossl_pkey()?),
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
    /// - Begin with `-----BEGIN PRIVATE KEY-----` for Ed25519 key.
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
        parse_keystr(pem.as_bytes(), passphrase)
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
        stringify_pem_privkey(self, passphrase)
    }

    /// Serialize the keypair to the OpenSSL PKCS#8 PEM format
    ///
    /// If the passphrase is given (set to `Some(...)`), then the generated PKCS#8 key will be encrypted.
    pub fn serialize_pkcs8(&self, passphrase: Option<&str>) -> OsshResult<String> {
        serialize_pkcs8_privkey(self, passphrase)
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
    fn short_keyname(&self) -> &'static str {
        self.inner_key().short_keyname()
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
    /// The short key name of the key
    fn short_keyname(&self) -> &'static str;
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

    // Rewritten from the OpenSSH project. OpenBSD notice is included below.

    /* $OpenBSD: sshkey.c,v 1.120 2022/01/06 22:05:42 djm Exp $ */
    /*
     * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
     * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
     * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
     *
     * Redistribution and use in source and binary forms, with or without
     * modification, are permitted provided that the following conditions
     * are met:
     * 1. Redistributions of source code must retain the above copyright
     *    notice, this list of conditions and the following disclaimer.
     * 2. Redistributions in binary form must reproduce the above copyright
     *    notice, this list of conditions and the following disclaimer in the
     *    documentation and/or other materials provided with the distribution.
     *
     * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
     * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
     * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
     * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
     * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
     * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
     * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
     * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
     * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
     * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
     */

    /// Draw an ASCII-art picture from the fingerprint, also known as "randomart"
    fn fingerprint_randomart(&self, hash: FingerprintHash) -> OsshResult<String> {
        const FLDBASE: usize = 8;
        const FLDSIZE_Y: usize = FLDBASE + 1;
        const FLDSIZE_X: usize = FLDBASE * 2 + 1;

        // Chars to be used after each other every time the worm intersects with itself.  Matter of
        // taste.
        const AUGMENTATION_CHARS: &[u8] = b" .o+=*BOX@%&#/^SE";

        let len = AUGMENTATION_CHARS.len() - 1;

        let mut art = String::with_capacity((FLDSIZE_X + 3) * (FLDSIZE_Y + 2));

        // Initialize field.
        let mut field = [[0; FLDSIZE_X]; FLDSIZE_Y];
        let mut x = FLDSIZE_X / 2;
        let mut y = FLDSIZE_Y / 2;

        // Process raw key.
        let dgst_raw = self.fingerprint(hash)?;
        for mut input in dgst_raw.iter().copied() {
            // Each byte conveys four 2-bit move commands.
            for _ in 0..4 {
                // Evaluate 2 bit, rest is shifted later.
                x = if (input & 0x1) != 0 {
                    x + 1
                } else {
                    x.saturating_sub(1)
                };
                y = if (input & 0x2) != 0 {
                    y + 1
                } else {
                    y.saturating_sub(1)
                };

                // Assure we are still in bounds.
                x = x.min(FLDSIZE_X - 1);
                y = y.min(FLDSIZE_Y - 1);

                // Augment the field.
                if field[y][x] < len as u8 - 2 {
                    field[y][x] += 1;
                }
                input >>= 2;
            }
        }

        // Mark starting point and end point.
        field[FLDSIZE_Y / 2][FLDSIZE_X / 2] = len as u8 - 1;
        field[y][x] = len as u8;

        // Assemble title.
        let title = format!("[{} {}]", self.short_keyname(), self.size());
        // If [type size] won't fit, then try [type]; fits "[ED25519-CERT]".
        let title = if title.chars().count() > FLDSIZE_X {
            format!("[{}]", self.short_keyname())
        } else {
            title
        };

        // Assemble hash ID.
        let hash = format!("[{}]", hash.name());

        // Output upper border.
        art += &format!("+{:-^width$}+\n", title, width = FLDSIZE_X);

        // Output content.
        #[allow(clippy::needless_range_loop)]
        for y in 0..FLDSIZE_Y {
            art.push('|');
            art.extend(
                field[y]
                    .iter()
                    .map(|&c| AUGMENTATION_CHARS[c as usize] as char),
            );
            art += "|\n";
        }

        // Output lower border.
        art += &format!("+{:-^width$}+", hash, width = FLDSIZE_X);

        Ok(art)
    }
}

/// A trait for operations of a private key
pub trait PrivateParts: Key {
    /// Sign the data with the key, returning the "detached" signature
    fn sign(&self, data: &[u8]) -> OsshResult<Vec<u8>>;
}

// This test is used to print the struct size of [`PublicKey`] and [`KeyPair`].
// It is intented to be run manually, and the result is read by the developers.
#[test]
#[ignore]
fn test_size() {
    use std::mem::size_of;

    eprintln!("PublicKey: {} bytes", size_of::<PublicKey>());
    eprintln!("\tRSA: {} bytes", size_of::<rsa::RsaPublicKey>());
    eprintln!("\tDSA: {} bytes", size_of::<dsa::DsaPublicKey>());
    eprintln!("\tECDSA: {} bytes", size_of::<ecdsa::EcDsaPublicKey>());
    eprintln!(
        "\tED25519: {} bytes",
        size_of::<ed25519::Ed25519PublicKey>()
    );
    eprintln!("KeyPair: {} bytes", size_of::<KeyPair>());
    eprintln!("\tRSA: {} bytes", size_of::<rsa::RsaKeyPair>());
    eprintln!("\tDSA: {} bytes", size_of::<dsa::DsaKeyPair>());
    eprintln!("\tECDSA: {} bytes", size_of::<ecdsa::EcDsaKeyPair>());
    eprintln!("\tED25519: {} bytes", size_of::<ed25519::Ed25519KeyPair>());
}
