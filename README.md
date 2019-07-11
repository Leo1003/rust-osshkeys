# osshkeys
## Description
A Rust library to read/write OpenSSH public/private keys and sign/verify data

## Current Status
This project is under alpha stage. It may contain many bugs for now.

## Planning Features
- Core Features
    - Key Types
        - RSA
        - DSA
        - EcDSA
        - Ed25519
    - [ ] Documentation
    - [x] Key generation
    - [x] Public key formats
        - [x] Openssh
        - [ ] PEM
    - [x] Private keys
        - [x] PEM (Using OpenSSL)
            - [x] Read
            - [ ] Write (without DSA)
        - [x] PEM (Encrypted) (Using OpenSSL)
            - [x] Read
            - [ ] Write (without DSA)
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

