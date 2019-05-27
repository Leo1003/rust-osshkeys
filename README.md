# osshkeys
## Description
A Rust library to read/write OpenSSH public/private keys and sign/verify data

## Current Status
This project is under initial development. It **SHOULDN'T** be used for now.

## Planning Features
- Core Features
    - Key generation
    - Supporting RSA, DSA, EcDSA, Ed25519 keys
    - Supporting reading/writing public, private, and encrypted private keys
- Additional Features
    - Supporting XMSS keys
    - Supporting read/write Putty key format(.ppk)
    - Without using openssl (if there exists required cryptography crates being mature enough)

