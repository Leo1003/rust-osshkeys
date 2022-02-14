# Changelog

## Unreleased
- **Add**
    - `PublicParts::fingerprint_randomart()` to generate ASCII randomart of a key
        - Thanks for hampuslidin implementing this feature in #6
- **Dependencies**
    - Update digest to 0.10.2 with its related crates
    - Update digest to 0.4.0 with its related crates

---

## 0.5.2 (2021/10/27)
- **Bug Fix**
    - Fix invalid private key by from_keystr for OpenSSH format (#4, #5)

---

## 0.5.1 (2021/09/01)
- **Compiler**
    - Minimum rustc version is now 1.51.0
- **Dependencies**
    - Upgrade bcrypt-pbkdf to 0.7.1
    - aes-ctr is deprecated
    - Upgrade block-modes to 0.8.1
    - Upgrade aes to 0.7.4
    - Upgrade des to 0.7.0

---

## 0.5.0 (2021/03/21)
- **Compiler**
    - Minimum rustc version is now 1.47.0
- **Improve**
    - Fix the large struct size issue for `PublicKey` and `KeyPair`
- **Dependencies**
    - Upgrade base64 to 0.13.0
    - Upgrade byteorder to 1.4.3
    - Upgrade bcrypt-pbkdf to 0.5.0
    - stream-cipher is deprecated, changing to use cipher 0.2.5
    - Upgrade block-modes to 0.7.0
    - Upgrade aes to 0.6.0
    - Upgrade des to 0.6.0
- **DevDependencies**
    - Upgrade hex-literal to 0.3.1
    - Upgrade cfg-if to 1.0.0

---

## 0.4.2 (2020/09/21)
- **Dependencies**
    - Upgrade aes-ctr to 0.5.0

---

## 0.4.1 (2020/09/11)
- **Requirement**
    - Minimal Rust version is 1.41.0 now
- **Dependencies**
    - Upgrade ed25519-dalek to 1.0.0
    - Upgrade bcrypt-pbkdf to 0.3.0
    - Upgrade block-modes to 0.6.1
    - Upgrade aes to 0.5.0
    - Upgrade des to 0.5.0

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

