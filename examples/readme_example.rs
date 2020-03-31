#[macro_use]
extern crate hex_literal;
use osshkeys::keys::FingerprintHash;
use osshkeys::{Key as _, KeyPair, KeyType, PrivateParts as _, PublicParts as _};

fn main() {
    let keyfile = std::fs::read_to_string("assets/openssh_ed25519_enc").unwrap();
    let keypair = KeyPair::from_keystr(&keyfile, Some(b"12345678")).unwrap();

    // Get the public key
    let publickey = keypair.clone_public_key().unwrap();

    // Get the key type
    assert_eq!(keypair.keytype(), KeyType::ED25519);

    // Get the fingerprint
    assert_eq!(
        keypair.fingerprint(FingerprintHash::MD5).unwrap(),
        hex!("d29552b0c87d7ff1acb3c2229e783321")
    );

    // Sign some data
    const SOME_DATA: &[u8] = b"8Kn9PPQV";
    let sign = keypair.sign(SOME_DATA).unwrap();

    assert_eq!(sign.as_slice(), hex!("7206f04ef062ec35f8fb9f9e8a17ec023070ecf5f6e1021ea2af73137b1b832bba08766e5ad95fdca81af37b27898428f9a7dbeb044dd550afeb46efb94fe808").as_ref());
    assert!(publickey.verify(SOME_DATA, &sign).unwrap());
}
