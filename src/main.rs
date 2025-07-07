//! CLI entry point and main application logic.

mod models;
mod crypto;
mod storage;
mod handlers;

use crate::models::{Cli, Commands};
use crate::handlers::{add, retrieve, delete};
use crate::storage::load;
use secrecy::SecretString;
use std::collections::HashMap;
use std::error::Error;
use clap::Parser;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let master_password_input = rpassword::prompt_password("Enter your master password: ")?;
    let master_password = SecretString::new(master_password_input);

    let file_size = match std::fs::metadata("vault.dat") {
        Ok(meta) => meta.len(),
        Err(_) => 0,
    };

    let mut creds = if file_size > 0 {
        load(&master_password)?
    } else {
        HashMap::new()
    };

    let existing_salt = if file_size > 0 {
        use std::fs::File;
        use std::io::Read;
        use bincode::config;
        let mut file = File::open("vault.dat")?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let (entry, _): (models::Entry, _) = bincode::decode_from_slice(&contents, config::standard())?;
        Some(entry.salt)
    } else {
        None
    };

    match &cli.command {
        Commands::Add { service, username, email, password } => {
            add(&master_password, &service, &username, &email, &password, &mut creds, existing_salt.as_deref()).map(|_| ())
        },
        Commands::List => {
            for (service, credential) in &creds {
                println!("Service: {}", service);
                println!("  Username: {}", credential.username);
                println!("  Email: {}", credential.email);
            }
            Ok(())
        }
        Commands::Retrive { service } => {
            retrieve(&service, &mut creds)?;
            Ok(())
        },
        Commands::Delete { service } => {
            delete(&service, &mut creds, &master_password, existing_salt.as_deref()).map(|_| ())
        }
    }
}