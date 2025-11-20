// Cryptographic operations abstraction
// This module provides traits for crypto operations to allow mocking in tests

pub mod password;

pub use password::{PasswordHasher, BcryptPasswordHasher};

#[cfg(test)]
pub use password::MockPasswordHasher;
