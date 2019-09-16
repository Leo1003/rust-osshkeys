extern crate osshkeys;
extern crate rand;

use self::utils::fill_random;
use osshkeys::keys::*;

mod utils;

#[test]
fn rsa_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::RSA, 0).unwrap();
    fill_random(&mut data);

    let sign = key.sign(&data).unwrap();
    assert_eq!(sign.len(), 256);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn rsa_sign_sha256_verify() {
    use osshkeys::keys::rsa::*;

    let mut data: [u8; 64] = [0; 64];
    let mut key = rsa::RsaKeyPair::generate(0).unwrap();
    key.set_sign_type(RsaSignature::SHA2_256);
    fill_random(&mut data);

    let sign = key.sign(&data).unwrap();
    assert_eq!(sign.len(), 256);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn rsa_sign_sha512_verify() {
    use osshkeys::keys::rsa::*;

    let mut data: [u8; 64] = [0; 64];
    let mut key = rsa::RsaKeyPair::generate(4096).unwrap();
    key.set_sign_type(RsaSignature::SHA2_512);
    fill_random(&mut data);

    let sign = key.sign(&data).unwrap();
    assert_eq!(sign.len(), 512);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn dsa_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::DSA, 0).unwrap();
    fill_random(&mut data);

    let sign = key.sign(&data).unwrap();
    assert!(sign.len() >= 40);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn ecdsa_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::ECDSA, 0).unwrap();
    fill_random(&mut data);

    let sign = key.sign(&data).unwrap();
    assert!(sign.len() <= 72);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn ed25519_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::ED25519, 0).unwrap();
    fill_random(&mut data);

    let sign = key.sign(&data).unwrap();
    assert_eq!(sign.len(), 64);
    assert!(key.verify(&data, &sign).unwrap());
}
