# Rsagent
## Description
A modern SSH Agent written in Rust. Supporting OpenSSH(ssh, ssh-add) and Putty on Windows.

## Current State
This project is under initial development. It **CAN'T** be used for now.

## Features
- Core Features
    - Supporting RSA, DSA, ECDSA, ED25519 keys
    - Using a local database to record user's key
    - Only ask user for password to decrypt a private key when a key is needed or adding a key for the first time
    - Supporting OpenSSH authentication request
    - Supporting interact with ssh-add(1)
    - Supporting Putty authentication request
- Additional Features
    - Generate keys in this application
    - Supporting read/write Putty key format(.ppk)
