//! Public API coverage for intentionally unbalanced, non-secret RSA fixtures.

use neotales_age::{AgeFile, AgeIdentity, AgeRecipient};
use zeroize::Zeroizing;

const PRIVATE_PKCS1: &str = include_str!("data/rsa-unbalanced-pkcs1.pem");
const PRIVATE_PKCS8: &str = include_str!("data/rsa-unbalanced-pkcs8.pem");
const PRIVATE_OPENSSH: &str = include_str!("data/rsa-unbalanced-openssh.pem");
const PRIVATE_ENCRYPTED: &str = include_str!("data/rsa-unbalanced-encrypted.pem");
const PUBLIC_SSH: &str = include_str!("data/rsa-unbalanced.pub");
const PASSPHRASE: &[u8] = b"unbalanced-test-pass";

#[test]
fn age_imports_unbalanced_rsa_formats_and_decrypts() {
    let recipient = AgeRecipient::from_ssh_public_key(PUBLIC_SSH).expect("RSA recipient");
    let encrypted = AgeFile::encrypt(b"unbalanced fixture payload", &[recipient]).expect("encrypt");

    let identities = [
        AgeIdentity::from_ssh_private_key(PRIVATE_PKCS1).expect("PKCS#1 identity"),
        AgeIdentity::from_ssh_private_key(PRIVATE_PKCS8).expect("PKCS#8 identity"),
        AgeIdentity::from_ssh_private_key(PRIVATE_OPENSSH).expect("OpenSSH identity"),
        AgeIdentity::from_encrypted_ssh_private_key(PUBLIC_SSH, PRIVATE_ENCRYPTED, || {
            Ok(Zeroizing::new(PASSPHRASE.to_vec()))
        })
        .expect("encrypted legacy PEM identity"),
    ];

    for identity in identities {
        assert_eq!(
            AgeFile::decrypt(&encrypted, &[identity]).expect("unbalanced RSA decrypt"),
            b"unbalanced fixture payload"
        );
    }
}
