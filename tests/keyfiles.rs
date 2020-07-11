extern crate osshkeys;

use osshkeys::keys::*;
use std::fs;
use std::path::Path;
use std::str::from_utf8;

mod utils;

const TEST_FILE_PASS: &str = "12345678";

fn verify_key<P: AsRef<Path>>(keyfile: P, passphrase: Option<&str>) {
    let keypath = utils::locate_crate_files(keyfile);
    let pubkeypath = keypath.with_extension("pub");

    let privdata = fs::read(keypath).unwrap();
    let privkey =
        KeyPair::from_keystr(from_utf8(privdata.as_slice()).unwrap(), passphrase).unwrap();

    let pubdata = fs::read(pubkeypath).unwrap();
    let pubkey = PublicKey::from_keystr(from_utf8(pubdata.as_slice()).unwrap()).unwrap();

    utils::fingerprint_assert(&privkey, &pubkey);
}

#[test]
fn keyfile_pem_rsa() {
    verify_key("assets/pem_rsa", None);
}

#[test]
fn keyfile_pem_rsa_enc() {
    verify_key("assets/pem_rsa_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_pem_dsa() {
    verify_key("assets/pem_dsa", None);
}

#[test]
fn keyfile_pem_dsa_enc() {
    verify_key("assets/pem_dsa_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_pem_ecdsa() {
    verify_key("assets/pem_ecdsa", None);
}

#[test]
fn keyfile_pem_ecdsa_enc() {
    verify_key("assets/pem_ecdsa_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_openssh_rsa() {
    verify_key("assets/openssh_rsa", None);
}

#[test]
fn keyfile_openssh_rsa_enc() {
    verify_key("assets/openssh_rsa_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_openssh_dsa() {
    verify_key("assets/openssh_dsa", None);
}

#[test]
fn keyfile_openssh_dsa_enc() {
    verify_key("assets/openssh_dsa_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_openssh_ecdsa() {
    verify_key("assets/openssh_ecdsa", None);
}

#[test]
fn keyfile_openssh_ecdsa_enc() {
    verify_key("assets/openssh_ecdsa_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_openssh_ed25519() {
    verify_key("assets/openssh_ed25519", None);
}

#[test]
fn keyfile_openssh_ed25519_enc() {
    verify_key("assets/openssh_ed25519_enc", Some(TEST_FILE_PASS));
}

#[test]
fn keyfile_pkcs8_rsa() {
    verify_key("assets/pkcs8_rsa", None);
}

#[test]
fn keyfile_pkcs8_rsa_enc() {
    verify_key("assets/pkcs8_rsa_enc", Some(TEST_FILE_PASS));
}

#[test]
#[should_panic]
fn keyfile_pem_rsa_wrong() {
    verify_key("assets/pem_rsa_enc", Some("deadbeef"));
}

#[test]
#[should_panic]
fn keyfile_pem_dsa_wrong() {
    verify_key("assets/pem_dsa_enc", Some("hashdjf"));
}

#[test]
#[should_panic]
fn keyfile_pem_ecdsa_wrong() {
    verify_key("assets/pem_ecdsa_enc", Some("1234567"));
}

#[test]
#[should_panic]
fn keyfile_pem_ed25519_wrong() {
    verify_key("assets/pem_ed25519_enc", Some("^&@#Y&G*"));
}
