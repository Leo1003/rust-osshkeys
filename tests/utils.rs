#![allow(dead_code)]

extern crate hex;
extern crate osshkeys;

use osshkeys::keys::*;
use rand::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

const PASSPHRASE_CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*+-_=/\\|()[]{}`~,.<>;:'\"";

#[inline]
pub fn fingerprint_assert(key1: &dyn PublicParts, key2: &dyn PublicParts) {
    assert_eq!(
        key1.fingerprint(FingerprintHash::MD5).unwrap(),
        key2.fingerprint(FingerprintHash::MD5).unwrap()
    );
    assert_eq!(
        key1.fingerprint(FingerprintHash::SHA256).unwrap(),
        key2.fingerprint(FingerprintHash::SHA256).unwrap()
    );
}

// This function is for test only,
// not providing any security protection.
pub fn gen_random_pass(len: usize) -> String {
    let charset_len = PASSPHRASE_CHARSET.len();
    let mut rng = ThreadRng::default();
    (0..len)
        .map(|_| -> char {
            let i = rng.gen_range(0, charset_len);
            PASSPHRASE_CHARSET.as_bytes()[i].into()
        })
        .collect()
}

pub fn fill_random(data: &mut [u8]) {
    let mut rng = ThreadRng::default();
    rng.fill_bytes(data);
}

pub fn create_tmp_folder() -> PathBuf {
    let mut rand: [u8; 8] = [0; 8];
    fill_random(&mut rand);
    let mut path = PathBuf::from("/tmp");
    path.push(format!("osshkeys-test-{}", hex::encode(rand)));
    fs::create_dir_all(&path).unwrap();
    path
}

pub fn remove_tmp_folder<P: AsRef<Path>>(path: P) {
    if path.as_ref().canonicalize().unwrap().starts_with("/tmp") {
        fs::remove_dir_all(path).unwrap();
    }
}

pub fn locate_crate_files<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut abspath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    abspath.push(path);
    abspath
}
