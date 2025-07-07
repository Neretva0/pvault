# pvault

A secure, command-line password manager written in Rust.

## Features
- AES-GCM encryption for all stored credentials
- Argon2id key derivation with per-vault salt
- Master password authentication
- Add, list, retrieve, and delete credentials for any service
- All sensitive data is zeroized from memory when possible
- Vault file is stored as a single encrypted file (`vault.dat`)

## Usage

### Build
```
cargo build --release
```

### Run
```
cargo run -- <COMMAND> [OPTIONS]
```

### Commands
- `add <service> <username> <email> <password>`: Add a new credential
- `list`: List all stored services and usernames/emails
- `retrive <service>`: Retrieve credentials for a service
- `delete <service>`: Delete credentials for a service

You will be prompted for your master password on each run.

### Example
```
cargo run -- add github johndoe johndoe@email.com mysecretpassword
cargo run -- list
cargo run -- retrive github
cargo run -- delete github
```

## Security Notes
- The vault is encrypted with AES-256-GCM using a key derived from your master password via Argon2id.
- The vault file (`vault.dat`) is created with restrictive permissions (read/write for the user only).
- Passwords are zeroized from memory after use when possible.
- **Never share your master password.**

## Requirements
- Rust (edition 2021)
- Linux/macOS/Windows

## License
MIT 

## Note
This is my first time building a password manager, and I'm continuously learning and refining my work. Feedback, suggestions, or code reviews are always welcome and appreciated!
