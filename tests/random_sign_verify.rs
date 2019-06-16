extern crate osshkeys;
extern crate rand;

use osshkeys::keys::*;
use rand::rngs::ThreadRng;
use rand::RngCore as _;

fn random_data(data: &mut [u8]) {
    let mut rng = ThreadRng::default();
    rng.fill_bytes(data);
}

#[test]
fn rsa_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::RSA, 0).unwrap();
    random_data(&mut data);

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
    random_data(&mut data);

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
    random_data(&mut data);

    let sign = key.sign(&data).unwrap();
    assert_eq!(sign.len(), 512);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn dsa_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::DSA, 0).unwrap();
    random_data(&mut data);

    let sign = key.sign(&data).unwrap();
    assert!(sign.len() >= 40);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn ecdsa_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::ECDSA, 0).unwrap();
    random_data(&mut data);

    let sign = key.sign(&data).unwrap();
    assert!(sign.len() <= 72);
    assert!(key.verify(&data, &sign).unwrap());
}

#[test]
fn ed25519_sign_verify() {
    let mut data: [u8; 64] = [0; 64];
    let key = KeyPair::generate(KeyType::ED25519, 0).unwrap();
    random_data(&mut data);

    let sign = key.sign(&data).unwrap();
    assert_eq!(sign.len(), 64);
    assert!(key.verify(&data, &sign).unwrap());
}
