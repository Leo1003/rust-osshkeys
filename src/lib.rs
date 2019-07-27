extern crate ed25519_dalek;
extern crate failure;
extern crate rand;

/// Processing bcrypt_pbkdf key derive
mod bcrypt_pbkdf;
/// Containing the error type of this crate
pub mod error;
/// Serialize/Deserialize key files
mod format;
/// Representing different types of public/private keys
pub mod keys;
/// Extension to read/write ssh data type representations defined in [RFC 4251](https://tools.ietf.org/html/rfc4251#section-5)
pub mod sshbuf;

pub use keys::Key;
pub use keys::KeyPair;
pub use keys::KeyType;
pub use keys::PrivatePart;
pub use keys::PublicKey;
pub use keys::PublicPart;
