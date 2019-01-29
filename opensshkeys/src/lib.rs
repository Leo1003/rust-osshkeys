#[derive(Clone)]
pub struct Error {}

pub trait PublicKey {
    fn size(&self) -> usize;
    fn fingerprint(&self, algo: HashAlgo) -> Vec<u8>;
    fn keytype(&self) -> &'static str;
    fn verify(&self, data: &[u8]) -> Result<bool, Error>;
    fn comment(&self) -> &String;
    fn set_comment(&mut self, comment: &str) -> ();
}

pub trait PrivateKey: PublicKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn as_public_key(&self) -> &PublicKey;
}

pub enum HashAlgo {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}
