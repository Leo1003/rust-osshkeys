use crate::FingerprintHash;
use crate::error::Error;

pub mod rsa;

pub trait PublicKey {
    fn size(&self) -> usize;
    fn fingerprint(&self, hash: FingerprintHash) -> Vec<u8>;
    fn keytype(&self) -> &'static str;
    fn verify(&self, data: &[u8]) -> Result<bool, Error>;
    fn comment(&self) -> &String;
    fn comment_mut(&mut self) -> &mut String;
    fn set_comment(&mut self, comment: &str) -> ();
}

pub trait PrivateKey: PublicKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn as_public_key(&self) -> &PublicKey;
}
