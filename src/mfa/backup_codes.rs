// Backup codes for MFA recovery
// Provides one-time use codes for account recovery when MFA device is unavailable

use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// A single backup code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCode {
    /// Hashed code value (for security)
    pub code_hash: String,
    /// Whether this code has been used
    pub used: bool,
    /// When the code was used (if applicable)
    pub used_at: Option<DateTime<Utc>>,
    /// When the code was created
    pub created_at: DateTime<Utc>,
}

/// Backup codes for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBackupCodes {
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// List of backup codes (hashed)
    pub codes: Vec<BackupCode>,
    /// When the codes were generated
    pub generated_at: DateTime<Utc>,
}

/// Manager for backup codes
pub struct BackupCodesManager {
    /// In-memory storage of backup codes
    /// In production, this should use a persistent storage backend
    storage: Arc<RwLock<HashMap<String, UserBackupCodes>>>,
}

impl BackupCodesManager {
    /// Create a new backup codes manager
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate new backup codes for a user
    pub async fn generate_codes(
        &self,
        user_id: &str,
        tenant_id: &str,
        count: usize,
    ) -> Result<Vec<String>, String> {
        let mut rng = rand::thread_rng();
        let mut plain_codes = Vec::new();
        let mut hashed_codes = Vec::new();

        // Generate codes and hash them
        for _ in 0..count {
            // Generate a random 9-digit code
            let code: u64 = rng.gen_range(100000000..999999999);
            let code_str = format!("{:09}", code);

            // Hash the code for storage
            let code_hash = hash(&code_str, DEFAULT_COST)
                .map_err(|e| format!("Failed to hash backup code: {}", e))?;

            plain_codes.push(code_str);
            hashed_codes.push(BackupCode {
                code_hash,
                used: false,
                used_at: None,
                created_at: Utc::now(),
            });
        }

        // Store the hashed codes
        let user_codes = UserBackupCodes {
            user_id: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            codes: hashed_codes,
            generated_at: Utc::now(),
        };

        let mut storage = self.storage.write().await;
        storage.insert(user_id.to_string(), user_codes);

        info!(
            "Generated {} backup codes for user {} in tenant {}",
            count, user_id, tenant_id
        );

        Ok(plain_codes)
    }

    /// Verify and consume a backup code
    /// Returns Ok(true) if the code is valid and has been consumed
    /// Returns Ok(false) if the code is invalid or already used
    pub async fn verify_and_consume(&self, user_id: &str, code: &str) -> Result<bool, String> {
        let mut storage = self.storage.write().await;

        let user_codes = match storage.get_mut(user_id) {
            Some(codes) => codes,
            None => {
                debug!("No backup codes found for user {}", user_id);
                return Ok(false);
            }
        };

        // Try to verify the code against all stored codes
        for backup_code in &mut user_codes.codes {
            if backup_code.used {
                continue;
            }

            // Verify the code
            match verify(code, &backup_code.code_hash) {
                Ok(true) => {
                    // Mark the code as used
                    backup_code.used = true;
                    backup_code.used_at = Some(Utc::now());

                    info!("Backup code verified and consumed for user {}", user_id);
                    return Ok(true);
                }
                Ok(false) => continue,
                Err(e) => {
                    return Err(format!("Failed to verify backup code: {}", e));
                }
            }
        }

        debug!("Invalid backup code for user {}", user_id);
        Ok(false)
    }

    /// Check how many unused backup codes a user has
    pub async fn get_remaining_codes(&self, user_id: &str) -> usize {
        let storage = self.storage.read().await;

        match storage.get(user_id) {
            Some(user_codes) => user_codes.codes.iter().filter(|c| !c.used).count(),
            None => 0,
        }
    }

    /// Regenerate backup codes (invalidates old ones)
    pub async fn regenerate_codes(
        &self,
        user_id: &str,
        tenant_id: &str,
        count: usize,
    ) -> Result<Vec<String>, String> {
        info!(
            "Regenerating backup codes for user {} in tenant {}",
            user_id, tenant_id
        );

        // Remove old codes
        {
            let mut storage = self.storage.write().await;
            storage.remove(user_id);
        }

        // Generate new codes
        self.generate_codes(user_id, tenant_id, count).await
    }

    /// Revoke all backup codes for a user
    pub async fn revoke_codes(&self, user_id: &str) -> Result<(), String> {
        let mut storage = self.storage.write().await;
        storage.remove(user_id);

        info!("Revoked all backup codes for user {}", user_id);
        Ok(())
    }

    /// Get backup codes info for a user (without revealing the actual codes)
    pub async fn get_codes_info(&self, user_id: &str) -> Option<BackupCodesInfo> {
        let storage = self.storage.read().await;

        storage.get(user_id).map(|user_codes| {
            let total = user_codes.codes.len();
            let used = user_codes.codes.iter().filter(|c| c.used).count();
            let remaining = total - used;

            BackupCodesInfo {
                total,
                used,
                remaining,
                generated_at: user_codes.generated_at,
            }
        })
    }
}

impl Default for BackupCodesManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about backup codes (without revealing actual codes)
#[derive(Debug, Serialize)]
pub struct BackupCodesInfo {
    pub total: usize,
    pub used: usize,
    pub remaining: usize,
    pub generated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_and_verify_backup_codes() {
        let manager = BackupCodesManager::new();

        // Generate codes
        let codes = manager
            .generate_codes("test-user", "test-tenant", 10)
            .await
            .unwrap();

        assert_eq!(codes.len(), 10);

        // Verify a valid code
        let valid = manager
            .verify_and_consume("test-user", &codes[0])
            .await
            .unwrap();
        assert!(valid);

        // Try to use the same code again
        let invalid = manager
            .verify_and_consume("test-user", &codes[0])
            .await
            .unwrap();
        assert!(!invalid);

        // Check remaining codes
        let remaining = manager.get_remaining_codes("test-user").await;
        assert_eq!(remaining, 9);
    }

    #[tokio::test]
    async fn test_regenerate_backup_codes() {
        let manager = BackupCodesManager::new();

        // Generate initial codes
        let codes1 = manager
            .generate_codes("test-user", "test-tenant", 5)
            .await
            .unwrap();

        // Regenerate codes
        let codes2 = manager
            .regenerate_codes("test-user", "test-tenant", 5)
            .await
            .unwrap();

        // Old codes should not work
        let invalid = manager
            .verify_and_consume("test-user", &codes1[0])
            .await
            .unwrap();
        assert!(!invalid);

        // New codes should work
        let valid = manager
            .verify_and_consume("test-user", &codes2[0])
            .await
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn test_get_codes_info() {
        let manager = BackupCodesManager::new();

        // Generate codes
        let codes = manager
            .generate_codes("test-user", "test-tenant", 10)
            .await
            .unwrap();

        // Get info before using any codes
        let info = manager.get_codes_info("test-user").await.unwrap();
        assert_eq!(info.total, 10);
        assert_eq!(info.used, 0);
        assert_eq!(info.remaining, 10);

        // Use a code
        manager
            .verify_and_consume("test-user", &codes[0])
            .await
            .unwrap();

        // Get info after using a code
        let info = manager.get_codes_info("test-user").await.unwrap();
        assert_eq!(info.total, 10);
        assert_eq!(info.used, 1);
        assert_eq!(info.remaining, 9);
    }

    #[tokio::test]
    async fn test_revoke_codes() {
        let manager = BackupCodesManager::new();

        // Generate codes
        let codes = manager
            .generate_codes("test-user", "test-tenant", 10)
            .await
            .unwrap();

        // Revoke codes
        manager.revoke_codes("test-user").await.unwrap();

        // Codes should not work anymore
        let invalid = manager
            .verify_and_consume("test-user", &codes[0])
            .await
            .unwrap();
        assert!(!invalid);

        // Info should be None
        let info = manager.get_codes_info("test-user").await;
        assert!(info.is_none());
    }
}
