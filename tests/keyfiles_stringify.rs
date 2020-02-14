extern crate osshkeys;

use osshkeys::cipher::Cipher;
use osshkeys::keys::*;

const TEST_FILE_PASS: &[u8] = b"12345678";

mod utils;

#[test]
fn stringify_pkcs8() {
    let keypair = KeyPair::generate(KeyType::RSA, 2048).unwrap();
    let pkcs8 = keypair.serialize_pkcs8(None).unwrap();

    let keypair2 = KeyPair::from_keystr(&pkcs8, None).unwrap();
    utils::fingerprint_assert(&keypair, &keypair2);
}

#[test]
fn stringify_pkcs8_encrypt() {
    let keypair = KeyPair::generate(KeyType::RSA, 2048).unwrap();
    let pkcs8 = keypair.serialize_pkcs8(Some(TEST_FILE_PASS)).unwrap();

    let keypair2 = KeyPair::from_keystr(&pkcs8, Some(TEST_FILE_PASS)).unwrap();
    utils::fingerprint_assert(&keypair, &keypair2);
}

#[test]
fn stringify_pem() {
    let keypair = KeyPair::generate(KeyType::RSA, 2048).unwrap();
    let pem = keypair.serialize_pem(None).unwrap();

    let keypair2 = KeyPair::from_keystr(&pem, None).unwrap();
    utils::fingerprint_assert(&keypair, &keypair2);
}

#[test]
fn stringify_pem_encrypt() {
    let keypair = KeyPair::generate(KeyType::RSA, 2048).unwrap();
    let pem = keypair.serialize_pem(Some(TEST_FILE_PASS)).unwrap();

    let keypair2 = KeyPair::from_keystr(&pem, Some(TEST_FILE_PASS)).unwrap();
    utils::fingerprint_assert(&keypair, &keypair2);
}

#[test]
fn stringify_openssh() {
    let keypair = KeyPair::generate(KeyType::RSA, 2048).unwrap();
    let osshpriv = keypair.serialize_openssh(None, Cipher::Null).unwrap();

    let keypair2 = KeyPair::from_keystr(&osshpriv, None).unwrap();
    utils::fingerprint_assert(&keypair, &keypair2);
}

#[test]
fn stringify_openssh_encrypt() {
    let keypair = KeyPair::generate(KeyType::RSA, 2048).unwrap();
    let osshpriv = keypair
        .serialize_openssh(Some(TEST_FILE_PASS), Cipher::Aes256_Ctr)
        .unwrap();

    let keypair2 = KeyPair::from_keystr(&osshpriv, Some(TEST_FILE_PASS)).unwrap();
    utils::fingerprint_assert(&keypair, &keypair2);
}
