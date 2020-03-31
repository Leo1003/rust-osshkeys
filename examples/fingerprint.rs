use failure::Error;
use osshkeys::keys::FingerprintHash;
use osshkeys::{PublicKey, PublicParts};
use std::env;
use std::fmt::Display;
use std::fs;
use std::path::Path;

fn print_fingerprint<P: Display + AsRef<Path>>(path: P) -> Result<(), Error> {
    print!("{}: ", path);
    match fs::read_to_string(path) {
        Ok(s) => {
            let pubkey = PublicKey::from_keystring(&s)?;
            println!(
                "SHA256:{}",
                hex::encode(pubkey.fingerprint(FingerprintHash::SHA256)?)
            );
        }
        Err(e) => {
            println!("{}", e);
        }
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    let mut argv = env::args();
    argv.next();
    for arg in argv {
        print_fingerprint(&arg)?;
    }
    Ok(())
}
