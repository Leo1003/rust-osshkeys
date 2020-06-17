extern crate osshkeys;

use osshkeys::cipher::Cipher;
use osshkeys::keys::*;

const TEST_MATRIX: [(KeyType, usize); 5] = [
    (KeyType::RSA, 2048),
    (KeyType::DSA, 1024),
    (KeyType::ECDSA, 256),
    (KeyType::ECDSA, 384),
    (KeyType::ECDSA, 521),
];
const TEST_MATRIX_OSSH: [(KeyType, usize); 6] = [
    (KeyType::RSA, 2048),
    (KeyType::DSA, 1024),
    (KeyType::ECDSA, 256),
    (KeyType::ECDSA, 384),
    (KeyType::ECDSA, 521),
    (KeyType::ED25519, 256),
];

mod utils;

fn pkcs8_serde_test(keypair: &KeyPair, passphrase: Option<&str>) {
    let pkcs8 = keypair.serialize_pkcs8(passphrase).unwrap();
    let keypair2 = KeyPair::from_keystr(&pkcs8, passphrase).unwrap();
    utils::fingerprint_assert(keypair, &keypair2);
}

#[test]
fn serde_pkcs8() {
    for k in &TEST_MATRIX {
        pkcs8_serde_test(&KeyPair::generate(k.0, k.1).unwrap(), None);
    }
}

#[test]
fn serde_pkcs8_encrypt() {
    for k in &TEST_MATRIX {
        let pass = utils::gen_random_pass(8);
        pkcs8_serde_test(&KeyPair::generate(k.0, k.1).unwrap(), Some(&pass));
    }
}

fn pem_serde_test(keypair: &KeyPair, passphrase: Option<&str>) {
    let pem = keypair.serialize_pem(passphrase).unwrap();
    let keypair2 = KeyPair::from_keystr(&pem, passphrase).unwrap();
    utils::fingerprint_assert(keypair, &keypair2);
}

#[test]
fn serde_pem() {
    for k in &TEST_MATRIX {
        pem_serde_test(&KeyPair::generate(k.0, k.1).unwrap(), None);
    }
}

#[test]
fn serde_pem_encrypt() {
    for k in &TEST_MATRIX {
        let pass = utils::gen_random_pass(8);
        pem_serde_test(&KeyPair::generate(k.0, k.1).unwrap(), Some(&pass));
    }
}

fn openssh_serde_test(keypair: &KeyPair, passphrase: Option<&str>, cipher: Cipher) {
    let osshpriv = keypair.serialize_openssh(passphrase, cipher).unwrap();
    let keypair2 = KeyPair::from_keystr(&osshpriv, passphrase).unwrap();
    utils::fingerprint_assert(keypair, &keypair2);
}

#[test]
fn serde_openssh() {
    for k in &TEST_MATRIX_OSSH {
        openssh_serde_test(&KeyPair::generate(k.0, k.1).unwrap(), None, Cipher::Null);
    }
}

#[test]
fn serde_openssh_encrypt() {
    let cipher_matrix = [
        Cipher::Aes128_Cbc,
        Cipher::Aes128_Ctr,
        Cipher::Aes192_Cbc,
        Cipher::Aes192_Cbc,
        Cipher::Aes192_Ctr,
        Cipher::Aes256_Cbc,
        Cipher::Aes256_Ctr,
        Cipher::TDes_Cbc,
    ];
    for k in &TEST_MATRIX_OSSH {
        for ci in &cipher_matrix {
            let pass = utils::gen_random_pass(8);
            openssh_serde_test(&KeyPair::generate(k.0, k.1).unwrap(), Some(&pass), *ci);
        }
    }
}
