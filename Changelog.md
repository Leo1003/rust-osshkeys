# Changelog

## Unreleased

---

## 0.4.0 (2020/07/11)
- **Breaking Change!!**
    - Remove `SshReadExt::read_list()`, `SshWriteExt::write_list()`
    - Rename `PublicKey::from_keystring()` to `PublicKey::from_keystr()`
    - Remove the usage of failure crate
    - Change to use the `bcrypt-pbkdf` crate, the passphrase type is `&str` now!
- **Add**
    - `SshBuf` which uses `CryptoVec` to provide memory zeroizing guarantee when resizing
    - `Cipher::decrypt_to()`, `Cipher::calc_buffer_len()`
    - `PublicKey::serialize_pem()` ([#2](https://github.com/Leo1003/rust-osshkeys/issues/2))
- **Improve**
    - Better memory zeroizing of `SshReadExt` and `SshWriteExt` implementations
    - Make RustCrypto crates as optional dependencies
    - Add Github Actions test flow for the RustCrypto cipher backend
    - Add minimum rustc version in test flow and README
    - Add feature to compile with vendored OpenSSL ([#1](https://github.com/Leo1003/rust-osshkeys/issues/1))
    - Upgrade RustCrypto crates: `digest 0.9`, `stream-cipher 0.4`, `block-modes 0.4`, ...
- **Fix**
    - Fix examples compiling problem on Windows

---

## 0.3.1 (2020/03/09)
- **Dependencies**
    - Upgrade base64 to 0.12

---

## 0.3.0 (2020/02/17)
- **Add**
    - An unified Cipher struct for encryption
    - Support for writing OpenSSH private key
    - `keys::PublicKey::serialize()`
    - `keys::KeyPair::serialize_publickey()`
- **API Change**
    - Rename `PublicPart` to `PublicParts`
    - Rename `PrivatePart` to `PrivateParts`

---

## 0.2.2 (2019/12/11)
- **Add**
    - Support for writing PKCS#8 private keys
- **Dependencies**
    - Upgrade rand to 0.7

---

## 0.2.1 (2019/08/03)
- **Fix**
    - Parsing encrypted PKCS#8 private keys
- **Improve**
    - Fingerprint hash method

---

## 0.2.0 (2019/07/27)
- **Add**
    - Keypair generate
    - Support for OpenSSL private keys
    - Support for opensshv2 private keys decode
    - keys::KeyType enum
    - Documents
    - Basic Example
- **Improve**
    - Add unit tests & integrate tests
    - Redesign the error type
    - Enable error backtrace support

---

## 0.1.0 (2019/05/28)
- **Initial release**
    - Construct Rsa, Dsa, EcDsa, Ed25519 key types
    - Construct key-related traits

