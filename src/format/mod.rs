use crate::error::*;
use crate::keys::*;

pub(crate) mod ossh_privkey;
pub(crate) mod ossh_pubkey;
pub(crate) mod pem;
pub(crate) mod pkcs8;

pub fn parse_keystr(pem: &[u8], passphrase: Option<&[u8]>) -> OsshResult<KeyPair> {
    let pemdata = nom_pem::decode_block(pem)?;

    match pemdata.block_type {
        "OPENSSH PRIVATE KEY" => {
            // Openssh format
            ossh_privkey::decode_ossh_priv(&pemdata.data, passphrase)
        }
        "PRIVATE KEY" => {
            // PKCS#8 format
            pem::parse_pem_privkey(pem, passphrase)
        }
        "ENCRYPTED PRIVATE KEY" => {
            // PKCS#8 format
            pem::parse_pem_privkey(pem, passphrase)
        }
        "DSA PRIVATE KEY" => {
            // Openssl DSA Key
            pem::parse_pem_privkey(pem, passphrase)
        }
        "RSA PRIVATE KEY" => {
            // Openssl RSA Key
            pem::parse_pem_privkey(pem, passphrase)
        }
        "EC PRIVATE KEY" => {
            // Openssl EC Key
            pem::parse_pem_privkey(pem, passphrase)
        }
        _ => Err(ErrorKind::UnsupportType.into()),
    }
}
