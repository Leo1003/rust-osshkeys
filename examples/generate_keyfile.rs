#[macro_use]
extern crate cfg_if;

use osshkeys::error::OsshResult;
use osshkeys::{cipher::Cipher, KeyPair, KeyType};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::*;
use std::path::Path;

fn main() -> OsshResult<()> {
    let filename = "id_ed25519";

    // Generate a keypair
    let keypair = KeyPair::generate(KeyType::ED25519, 256)?;
    // Create the file with permission 0600
    let mut fop = fs::OpenOptions::new();
    fop.write(true).create(true).truncate(true);
    cfg_if! {
        if #[cfg(unix)] {
            fop.mode(0o600);
        }
    }

    let mut f = fop.open(filename)?;
    // Serialize the private key and write it
    f.write(
        keypair
            .serialize_openssh(Some("passw0rd"), Cipher::Aes256_Ctr)?
            .as_bytes(),
    )?;
    f.sync_all()?;

    // Get the serialized public key
    let pubkey = keypair.serialize_publickey()?;

    // Create public key file
    let mut pubf = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(filename).with_extension("pub"))?;
    // Write the public key
    writeln!(pubf, "{}", &pubkey)?;
    pubf.sync_all()?;

    // Print it out
    println!("{}", &pubkey);
    Ok(())
}
