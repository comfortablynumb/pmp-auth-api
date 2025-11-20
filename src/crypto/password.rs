// Password hashing trait and implementations

use bcrypt::{hash, verify, DEFAULT_COST};

/// Trait for password hashing operations
pub trait PasswordHasher: Send + Sync {
    /// Hash a password
    fn hash_password(&self, password: &str) -> Result<String, String>;

    /// Verify a password against a hash
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, String>;
}

/// Real bcrypt-based password hasher (production use)
pub struct BcryptPasswordHasher {
    cost: u32,
}

impl BcryptPasswordHasher {
    pub fn new() -> Self {
        Self {
            cost: DEFAULT_COST,
        }
    }

    #[allow(dead_code)]
    pub fn with_cost(cost: u32) -> Self {
        Self { cost }
    }
}

impl Default for BcryptPasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher for BcryptPasswordHasher {
    fn hash_password(&self, password: &str) -> Result<String, String> {
        hash(password, self.cost).map_err(|e| format!("Failed to hash password: {}", e))
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, String> {
        verify(password, hash).map_err(|e| format!("Failed to verify password: {}", e))
    }
}

/// Mock password hasher for tests (fast, deterministic)
#[cfg(test)]
pub struct MockPasswordHasher;

#[cfg(test)]
impl MockPasswordHasher {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
impl Default for MockPasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl PasswordHasher for MockPasswordHasher {
    fn hash_password(&self, password: &str) -> Result<String, String> {
        // Simple deterministic "hash" - just prefix with "MOCK_HASH:"
        // This is NOT secure, only for testing
        Ok(format!("MOCK_HASH:{}", password))
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, String> {
        // Check if hash matches our mock format
        let expected = format!("MOCK_HASH:{}", password);
        Ok(hash == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_password_hasher() {
        let hasher = MockPasswordHasher::new();

        let password = "test_password_123";
        let hash = hasher.hash_password(password).unwrap();

        // Should hash instantly
        assert_eq!(hash, "MOCK_HASH:test_password_123");

        // Verification should work
        assert!(hasher.verify_password(password, &hash).unwrap());
        assert!(!hasher.verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_bcrypt_password_hasher() {
        let hasher = BcryptPasswordHasher::new();

        let password = "secure_password";
        let hash = hasher.hash_password(password).unwrap();

        // Hash should not be the password
        assert_ne!(hash, password);

        // Verification should work
        assert!(hasher.verify_password(password, &hash).unwrap());
        assert!(!hasher.verify_password("wrong_password", &hash).unwrap());
    }
}
