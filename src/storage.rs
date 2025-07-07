//! File storage and serialization logic for the password manager vault.

use crate::models::{Entry, SubEntry, Credential};
use crate::crypto;
use bincode::{config, decode_from_slice, encode_to_vec};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::error::Error;
use aes_gcm::aead::OsRng;

/// Loads credentials from the encrypted vault file.
pub fn load(master_password: &secrecy::Secret<String>) -> Result<HashMap<String, Credential>, Box<dyn Error>> {
    let mut file = File::open("vault.dat")?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let (entry, _): (Entry, _) = decode_from_slice(&contents, config::standard())?;
    let salt_string = argon2::password_hash::SaltString::from_b64(&entry.salt).map_err(|e| e.to_string())?;
    let salt_ref = salt_string.as_salt();
    let salt_bytes = salt_ref.as_ref().as_bytes();
    let derived_key = crypto::derive_key(master_password.expose_secret(), salt_bytes)?;
    if entry.verify != derived_key {
        return Err("Incorrect master password".into());
    }
    let plaintext = crypto::decrypt(&derived_key, &entry.sub_entry.nonce, &entry.sub_entry.cipher_text)?;
    let (creds, _): (HashMap<String, Credential>, _) = decode_from_slice(&plaintext, config::standard())?;
    Ok(creds)
}

/// Saves credentials to the encrypted vault file.
pub fn save(master_password: &secrecy::Secret<String>, creds: &mut HashMap<String, Credential>, existing_salt: Option<&str>) -> Result<(), Box<dyn Error>> {
    let salt_string = if let Some(salt) = existing_salt {
        argon2::password_hash::SaltString::from_b64(salt).map_err(|e| e.to_string())?
    } else {
        argon2::password_hash::SaltString::generate(&mut OsRng)
    };
    let salt_ref = salt_string.as_salt();
    let salt = salt_ref.as_ref().as_bytes();
    let output_key_material = crypto::derive_key(master_password.expose_secret(), salt)?;
    let serialized_creds = encode_to_vec(&*creds, config::standard())?;
    let (ciphertext, nonce) = crypto::encrypt(&output_key_material, &serialized_creds)?;
    let subentry = SubEntry {
        nonce,
        cipher_text: ciphertext,
    };
    let enter = Entry {
        salt: salt_string.to_string(),
        verify: output_key_material,
        sub_entry: subentry,
    };
    let encoded = encode_to_vec(&enter, config::standard())?;
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open("vault.dat")?;
    file.write_all(&encoded)?;
    Ok(())
} 