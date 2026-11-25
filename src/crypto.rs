//! Small cryptographic adapters shared by the age recipient types.

use std::fmt::Write as _;

use {
    chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    },
    hkdf::Hkdf,
    hmac::{Hmac, Mac},
    rsa::{Oaep, PrivateKey, PublicKey as RsaPublicKey, traits::PublicKeyParts as _},
    sha2::{Digest, Sha256},
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::Zeroizing,
};

use crate::error::{AgeError, Result};

pub(crate) const FILE_KEY_LENGTH: usize = 16;
pub(crate) const X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";
pub(crate) const SSH_ED25519_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";
pub(crate) const SSH_RSA_LABEL: &[u8] = b"age-encryption.org/v1/ssh-rsa";
pub(crate) const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";

/// Fills a byte array with operating-system entropy.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0u8; N];
    getrandom::fill(&mut value).map_err(|_| AgeError::Random)?;
    Ok(value)
}

/// Derives 32 bytes with HKDF-SHA-256.
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_| AgeError::Crypto("HKDF output length"))?;
    Ok(*output)
}

/// Computes HMAC-SHA-256.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| AgeError::Crypto("HMAC key length"))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(result.as_slice());
    Ok(output)
}

/// Verifies HMAC-SHA-256 in constant time.
pub(crate) fn verify_hmac_sha256(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 32 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// Encrypts a small value with the age zero nonce and empty AAD.
pub(crate) fn aead_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))?;
    let nonce = Nonce::try_from(&[0u8; 12][..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 encryption"))
}

/// Decrypts a small value with the age zero nonce and empty AAD.
pub(crate) fn aead_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))?;
    let nonce = Nonce::try_from(&[0u8; 12][..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| AgeError::AuthenticationFailed)
}

/// Computes the X25519 public share for a scalar.
pub(crate) fn x25519_base(secret: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret);
    PublicKey::from(&secret).to_bytes()
}

/// Computes an X25519 shared secret and rejects the all-zero result.
pub(crate) fn x25519_shared(secret: &[u8; 32], point: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let secret = StaticSecret::from(*secret);
    let public = PublicKey::from(*point);
    let shared = secret.diffie_hellman(&public).to_bytes();
    if shared.iter().all(|value| *value == 0) {
        return None;
    }
    Some(Zeroizing::new(shared))
}

/// Derives a 32-byte scrypt key with age's label and parameters.
pub(crate) fn derive_scrypt_key(
    password: &[u8],
    salt: &[u8],
    work_factor: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    if !(1..=30).contains(&work_factor) || salt.len() != 16 {
        return Err(AgeError::InvalidWorkFactor);
    }
    let mut labeled_salt = Zeroizing::new(Vec::with_capacity(SCRYPT_LABEL.len() + salt.len()));
    labeled_salt.extend_from_slice(SCRYPT_LABEL);
    labeled_salt.extend_from_slice(salt);
    let log_n = u8::try_from(work_factor).map_err(|_| AgeError::InvalidWorkFactor)?;
    let parameters = scrypt::Params::new(log_n, 8, 1).map_err(|_| AgeError::InvalidWorkFactor)?;
    let mut output = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password, &labeled_salt, &parameters, output.as_mut_slice())
        .map_err(|_| AgeError::Crypto("scrypt derivation"))?;
    Ok(output)
}

/// Computes the four-byte SSH age fingerprint for a wire public key.
pub(crate) fn ssh_fingerprint(wire_key: &[u8]) -> String {
    let digest = Sha256::digest(wire_key);
    let mut short = [0u8; 4];
    if let Some(source) = digest.get(..short.len()) {
        short.copy_from_slice(source);
    }
    crate::codec::encode_raw(&short)
}

/// Computes a short fingerprint of public key material, for diagnostics.
///
/// A `Debug` rendering of a key has to let a caller holding the wrong key tell
/// which one they have, and it has to do that without the private half. This is
/// the first eight bytes of the SHA-256 of the public key, hex-encoded: sixteen
/// characters, no more entropy than a caller can compare by eye, and nothing in
/// it that the public key does not already publish.
pub(crate) fn public_key_fingerprint(public_key: &[u8]) -> String {
    const FINGERPRINT_BYTES: usize = 8;

    let digest = Sha256::digest(public_key);
    let mut output = String::with_capacity(FINGERPRINT_BYTES * 2);
    for byte in digest.iter().take(FINGERPRINT_BYTES) {
        // `write!` into the existing buffer rather than `push_str(&format!)`,
        // which allocates a throwaway `String` per byte.
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

/// Encrypts with RSA-OAEP-SHA-256 and the age SSH RSA label.
pub(crate) fn rsa_oaep_encrypt(key: &RsaPublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let padding = Oaep::<Sha256>::new_with_label(SSH_RSA_LABEL.to_vec());
    let mut rng = getrandom_v04::rand_core::UnwrapErr(getrandom_v04::SysRng);
    key.encrypt(&mut rng, padding, message)
        .map_err(|_| AgeError::Crypto("RSA OAEP encryption"))
}

/// Decrypts with RSA-OAEP-SHA-256 and the age SSH RSA label.
pub(crate) fn rsa_oaep_decrypt(key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() != key.size() {
        return Err(AgeError::AuthenticationFailed);
    }
    let padding = Oaep::<Sha256>::new_with_label(SSH_RSA_LABEL.to_vec());
    let mut rng = getrandom_v04::rand_core::UnwrapErr(getrandom_v04::SysRng);
    key.decrypt_blinded(&mut rng, padding, ciphertext)
        .map_err(|_| AgeError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_oaep_round_trip_rejects_wrong_labels_and_malformed_ciphertexts() {
        let mut rng = getrandom_v04::rand_core::UnwrapErr(getrandom_v04::SysRng);
        let private_key =
            PrivateKey::new(&mut rng, 2048).expect("OS-backed RSA key generation should succeed");
        let public_key = private_key.to_public_key();
        let plaintext = b"age RSA OAEP test";
        let ciphertext =
            rsa_oaep_encrypt(&public_key, plaintext).expect("RSA OAEP encryption should succeed");

        assert_eq!(
            rsa_oaep_decrypt(&private_key, &ciphertext).expect("ciphertext should decrypt"),
            plaintext
        );
        assert!(matches!(
            rsa_oaep_decrypt(&private_key, &ciphertext[..ciphertext.len() - 1]),
            Err(AgeError::AuthenticationFailed)
        ));
        let mut corrupted_ciphertext = ciphertext.clone();
        let byte = corrupted_ciphertext
            .last_mut()
            .expect("RSA ciphertext is nonempty");
        *byte ^= 1;
        assert!(matches!(
            rsa_oaep_decrypt(&private_key, &corrupted_ciphertext),
            Err(AgeError::AuthenticationFailed)
        ));

        let wrong_label_ciphertext = public_key
            .encrypt(
                &mut rng,
                Oaep::<Sha256>::new_with_label(b"wrong age RSA label".to_vec()),
                plaintext,
            )
            .expect("test ciphertext should encrypt");
        assert!(matches!(
            rsa_oaep_decrypt(&private_key, &wrong_label_ciphertext),
            Err(AgeError::AuthenticationFailed)
        ));
    }
}
