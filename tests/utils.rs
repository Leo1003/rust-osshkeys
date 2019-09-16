#![allow(dead_code)]

extern crate hex;
extern crate osshkeys;

use osshkeys::keys::*;
use rand::rngs::ThreadRng;
use rand::RngCore as _;
use std::fs;
use std::path::{Path, PathBuf};

#[inline]
pub fn fingerprint_assert(key1: &dyn PublicPart, key2: &dyn PublicPart) {
    assert_eq!(
        key1.fingerprint(FingerprintHash::MD5).unwrap(),
        key2.fingerprint(FingerprintHash::MD5).unwrap()
    );
    assert_eq!(
        key1.fingerprint(FingerprintHash::SHA256).unwrap(),
        key2.fingerprint(FingerprintHash::SHA256).unwrap()
    );
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
