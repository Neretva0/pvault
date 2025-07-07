//! Data models and command-line argument structures for the password manager.

use bincode::{Decode, Encode};
use clap::{Parser, Subcommand};
use zeroize::Zeroize;

/// Represents the encrypted vault entry.
#[derive(Encode, Decode, Debug, Zeroize)]
pub struct Entry {
    pub salt: String,
    pub verify: [u8; 32],
    pub sub_entry: SubEntry,
}

/// Represents the encrypted sub-entry (nonce and ciphertext).
#[derive(Encode, Decode, Debug, Zeroize)]
pub struct SubEntry {
    pub nonce: [u8; 12],
    pub cipher_text: Vec<u8>,
}

/// Represents a user credential.
#[derive(Debug, Encode, Decode)]
pub struct Credential {
    pub username: String,
    pub email: String,
    pub password: String,
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username &&
        self.email == other.email &&
        self.password == other.password
    }
}

/// CLI argument parser.
#[derive(Parser)]
#[command(name = "pwmanager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported CLI subcommands.
#[derive(Subcommand)]
pub enum Commands {
    Add {
        service: String,
        username: String,
        email: String,
        password: String,
    },
    List,
    Retrive {
        service: String,
    },
    Delete {
        service: String,
    }
} 