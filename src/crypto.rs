//! Cryptographic primitives: key derivation, encryption, and decryption.

use argon2::{Argon2, Params, Version};
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, OsRng}, Nonce};
use std::error::Error;
use aes_gcm::aead::AeadCore;

/// Derives a 32-byte key from the master password and salt using Argon2id.
pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let mut derived_key = [0u8; 32];
    let params = Params::new(65536, 3, 1, None).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(master_password.as_bytes(), salt, &mut derived_key).map_err(|e| e.to_string())?;
    Ok(derived_key)
}

/// Encrypts the given plaintext with the provided key using AES-GCM.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), Box<dyn Error>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| e.to_string())?;
    Ok((ciphertext, *nonce.as_ref()))
}

/// Decrypts the given ciphertext with the provided key and nonce using AES-GCM.
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    Ok(plaintext)
} 