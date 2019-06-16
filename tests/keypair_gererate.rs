extern crate osshkeys;

use osshkeys::keys::*;

#[test]
fn rsa_generate() {
    let key = KeyPair::generate(KeyType::RSA, 0).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::RSA);
    assert_eq!(key.size(), 2048);
    assert_eq!(key.keyname(), "ssh-rsa");
}

#[test]
#[should_panic]
fn rsa_generate_minsize() {
    KeyPair::generate(KeyType::RSA, 512).unwrap();
}

#[test]
#[should_panic]
fn rsa_generate_maxsize() {
    KeyPair::generate(KeyType::RSA, 32768).unwrap();
}

#[test]
fn rsa_generate_strange() {
    let key = KeyPair::generate(KeyType::RSA, 2500).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::RSA);
    assert_eq!(key.size(), 2500);
    assert_eq!(key.keyname(), "ssh-rsa");
}

#[test]
fn dsa_generate() {
    let key = KeyPair::generate(KeyType::DSA, 0).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::DSA);
    assert_eq!(key.size(), 1024);
    assert_eq!(key.keyname(), "ssh-dss");
}

#[test]
#[should_panic]
fn dsa_generate_invalid_size() {
    KeyPair::generate(KeyType::DSA, 2048).unwrap();
}

#[test]
fn ecdsa_256_generate() {
    let key = KeyPair::generate(KeyType::ECDSA, 256).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::ECDSA);
    assert_eq!(key.size(), 256);
    assert_eq!(key.keyname(), "ecdsa-sha2-nistp256");
}

#[test]
fn ecdsa_384_generate() {
    let key = KeyPair::generate(KeyType::ECDSA, 384).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::ECDSA);
    assert_eq!(key.size(), 384);
    assert_eq!(key.keyname(), "ecdsa-sha2-nistp384");
}

#[test]
fn ecdsa_521_generate() {
    let key = KeyPair::generate(KeyType::ECDSA, 521).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::ECDSA);
    assert_eq!(key.size(), 521);
    assert_eq!(key.keyname(), "ecdsa-sha2-nistp521");
}

#[test]
#[should_panic]
fn ecdsa_generate_invalid() {
    KeyPair::generate(KeyType::ECDSA, 512).unwrap();
}

#[test]
fn ed25519_generate() {
    let key = KeyPair::generate(KeyType::ED25519, 0).unwrap();
    println!("{}", key.clone_public_key().unwrap());
    assert_eq!(key.keytype(), KeyType::ED25519);
    assert_eq!(key.size(), 256);
    assert_eq!(key.keyname(), "ssh-ed25519");
}

#[test]
#[should_panic]
fn ed25519_generate_invalid() {
    KeyPair::generate(KeyType::ED25519, 512).unwrap();
}
