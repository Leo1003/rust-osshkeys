# osshkeys

[![Crates](https://img.shields.io/crates/v/osshkeys.svg)](https://crates.io/crates/osshkeys)
[![Docs](https://docs.rs/osshkeys/badge.svg)](https://docs.rs/osshkeys)

## Description
A Rust library to handle OpenSSH key and other common SSH key

The main function of this library is to read, write different formats of SSH keys.
Also, it provide the ability to generate a key, sign and verify data.

## Current Status
The library is still under development, so there are some functions that haven't implemented.
Some api may also change in the future.

## Planning Features
- Core Features
    - Key Types
        - RSA
        - DSA
        - EcDSA
        - Ed25519
    - [x] Documentation
        - [x] Descriptions
        - [x] Examples
        - [ ] More Examples
    - [x] Key generation
    - [x] Public key formats
        - [x] Openssh
        - [ ] PEM
    - [x] Private keys
        - [x] PEM (Using OpenSSL)
        - [x] PEM (Encrypted) (Using OpenSSL)
        - [x] PKCS#8 (Using OpenSSL)
            - [x] Read
            - [ ] Write
        - [x] PKCS#8 (Encrypted) (Using OpenSSL)
            - [x] Read
            - [ ] Write
        - [x] Openssh v2
            - [x] Read
            - [ ] Write
        - [x] Openssh v2 (Encrypted)
            - [x] Read
            - [ ] Write
- Additional Features
    - [ ] Supporting XMSS keys
    - [ ] Supporting read/write Putty key format(.ppk)
    - [ ] Without using openssl (To become pure Rust library) (if there exists required cryptography crates being mature enough)

