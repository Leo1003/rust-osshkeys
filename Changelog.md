# Changelog
---
## Unreleased
- **Add**
    - Support for writing PKCS#8 private keys
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

