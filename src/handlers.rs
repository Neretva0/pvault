//! Command handlers for add, retrieve, and delete operations.

use crate::models::{Credential};
use crate::storage;
use secrecy::Secret;
use std::collections::HashMap;
use std::error::Error;
use zeroize::Zeroizing;

/// Adds a new credential to the vault.
pub fn add(master_password: &Secret<String>, service: &String, username: &String, email: &String, password: &String, creds: &mut HashMap<String, Credential>, existing_salt: Option<&str>) -> Result<(), Box<dyn Error>> {
    if service.trim().is_empty() {
        return Err("Service name cannot be empty".into());
    }
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long".into());
    }
    if !email.contains('@') {
        return Err("Invalid email format".into());
    }
    let adding = Credential {
        username: username.to_string(),
        email: email.to_string(),
        password: password.clone(),
    };
    creds.insert(service.to_string(), adding);
    storage::save(master_password, creds, existing_salt)
}

/// Retrieves and prints a credential from the vault.
pub fn retrieve(service: &String, creds: &mut HashMap<String, Credential>) -> Result<String, Box<dyn Error>> {
    if let Some(cred) = creds.get(service) {
        println!("Service: {}", service);
        println!("  Username: {}", cred.username);
        println!("  Email: {}", cred.email);
        let secret_password: Zeroizing<String> = Zeroizing::new(cred.password.clone());
        println!("  Password: {}", *secret_password);
        Ok(format!("Retrieved credentials for '{}'", service))
    } else {
        println!("Service: {} not found in the vault.", service);
        Ok(format!("Service '{}' not found", service))
    }
}

/// Deletes a credential from the vault.
pub fn delete(service: &String, creds: &mut HashMap<String, Credential>, master_password: &Secret<String>, existing_salt: Option<&str>) -> Result<String, Box<dyn Error>> {
    let output = if !creds.contains_key(service) {
        let msg = format!("Service: {} not found", service);
        println!("{}", msg);
        msg
    } else {
        creds.remove(service);
        let msg = format!("Service: {} deleted", service);
        println!("{}", msg);
        msg
    };
    storage::save(master_password, creds, existing_salt)?;
    Ok(output)
} 