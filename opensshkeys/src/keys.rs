use crate::FingerprintHash;
use crate::error::Error;
use openssl::hash::Hasher;

pub mod rsa;

pub trait PublicKey {
    fn size(&self) -> usize;

    fn keytype(&self) -> &'static str;
    fn verify(&self, data: &[u8]) -> Result<bool, Error>;
    fn comment(&self) -> &String;
    fn comment_mut(&mut self) -> &mut String;
    fn set_comment(&mut self, comment: &str) -> ();
    fn blob(&self) -> Result<Vec<u8>, Error>;

    fn fingerprint(&self, hash: FingerprintHash) -> Result<Vec<u8>, Error> {
        let b = self.blob()?;
        let mut hasher = Hasher::new(hash.get_digest())?;
        hasher.update(&b)?;
        let dig = hasher.finish()?;
        Ok(dig.to_vec())
    }
}

pub trait PrivateKey: PublicKey {
    type Public;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn as_public_key(&self) -> Result<Self::Public, Error>;
}
