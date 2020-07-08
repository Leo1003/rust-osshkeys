extern crate osshkeys;

use osshkeys::keys::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::from_utf8;

mod utils;

fn verify_pem_convertion<P: AsRef<Path>>(pubkeyfile: P) {
    let keypath = utils::locate_crate_files(pubkeyfile);
    let mut pemkeyfilename = keypath.file_name().unwrap().to_owned();
    pemkeyfilename.push(".pem");
    let pemkeypath = keypath.with_file_name(pemkeyfilename);

    let ossh_pub = fs::read_to_string(keypath).unwrap();
    let pem_pub = fs::read_to_string(pemkeypath).unwrap();

    // Openssh --> PEM
    let pubkey =
        PublicKey::from_keystr(&ossh_pub).unwrap();

    assert_eq!(&pem_pub.trim_end(), &pubkey.serialize_pem().unwrap().trim_end());

    // PEM --> Openssh

    let pubkey =
        PublicKey::from_keystr(&pem_pub).unwrap();

    assert_eq!(&ossh_pub.trim_end(), &pubkey.serialize().unwrap().trim_end());
}

#[test]
fn pem_serialize_openssh_rsa() {
    verify_pem_convertion("assets/openssh_rsa_enc.pub");
}

#[test]
fn pem_serialize_openssh_dsa() {
    verify_pem_convertion("assets/openssh_dsa_enc.pub");
}

#[test]
fn pem_serialize_openssh_ecdsa() {
    verify_pem_convertion("assets/openssh_ecdsa_enc.pub");
}
