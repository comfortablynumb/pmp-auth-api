// In-memory storage backend implementation
// Uses HashMap with Mutex for thread-safe access

use super::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// In-memory storage backend
/// Thread-safe storage using HashMap and Mutex
pub struct MemoryStorage {
    authorization_codes: Arc<Mutex<HashMap<String, AuthorizationCodeData>>>,
    refresh_tokens: Arc<Mutex<HashMap<String, RefreshTokenData>>>,
    api_keys: Arc<Mutex<HashMap<String, ApiKeyData>>>,
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
    device_codes: Arc<Mutex<HashMap<String, DeviceCodeData>>>,
    user_code_to_device_code: Arc<Mutex<HashMap<String, String>>>,
    revoked_tokens: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl MemoryStorage {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        Self {
            authorization_codes: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            api_keys: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            device_codes: Arc::new(Mutex::new(HashMap::new())),
            user_code_to_device_code: Arc::new(Mutex::new(HashMap::new())),
            revoked_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for MemoryStorage {
    // Authorization Code operations
    async fn store_authorization_code(
        &self,
        code: &str,
        data: AuthorizationCodeData,
    ) -> Result<(), StorageError> {
        let mut codes = self
            .authorization_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        codes.insert(code.to_string(), data);
        Ok(())
    }

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeData>, StorageError> {
        let codes = self
            .authorization_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(codes.get(code).cloned())
    }

    async fn delete_authorization_code(&self, code: &str) -> Result<(), StorageError> {
        let mut codes = self
            .authorization_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        codes.remove(code);
        Ok(())
    }

    // Refresh Token operations
    async fn store_refresh_token(
        &self,
        token: &str,
        data: RefreshTokenData,
    ) -> Result<(), StorageError> {
        let mut tokens = self
            .refresh_tokens
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        tokens.insert(token.to_string(), data);
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshTokenData>, StorageError> {
        let tokens = self
            .refresh_tokens
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(tokens.get(token).cloned())
    }

    async fn delete_refresh_token(&self, token: &str) -> Result<(), StorageError> {
        let mut tokens = self
            .refresh_tokens
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        tokens.remove(token);
        Ok(())
    }

    // API Key operations
    async fn store_api_key(&self, key_id: &str, data: ApiKeyData) -> Result<(), StorageError> {
        let mut keys = self
            .api_keys
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        keys.insert(key_id.to_string(), data);
        Ok(())
    }

    async fn get_api_key(&self, key_id: &str) -> Result<Option<ApiKeyData>, StorageError> {
        let keys = self
            .api_keys
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(keys.get(key_id).cloned())
    }

    async fn list_api_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyData>, StorageError> {
        let keys = self
            .api_keys
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let result: Vec<ApiKeyData> = keys
            .values()
            .filter(|k| k.tenant_id == tenant_id)
            .cloned()
            .collect();

        Ok(result)
    }

    async fn update_api_key(&self, key_id: &str, data: ApiKeyData) -> Result<(), StorageError> {
        let mut keys = self
            .api_keys
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if !keys.contains_key(key_id) {
            return Err(StorageError::NotFound);
        }

        keys.insert(key_id.to_string(), data);
        Ok(())
    }

    async fn delete_api_key(&self, key_id: &str) -> Result<(), StorageError> {
        let mut keys = self
            .api_keys
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        keys.remove(key_id);
        Ok(())
    }

    // Session operations
    async fn store_session(&self, session_id: &str, data: SessionData) -> Result<(), StorageError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        sessions.insert(session_id.to_string(), data);
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>, StorageError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(sessions.get(session_id).cloned())
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), StorageError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        sessions.remove(session_id);
        Ok(())
    }

    // Device Flow operations
    async fn store_device_code(
        &self,
        device_code: &str,
        data: DeviceCodeData,
    ) -> Result<(), StorageError> {
        let mut codes = self
            .device_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let mut mapping = self
            .user_code_to_device_code
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        mapping.insert(data.user_code.clone(), device_code.to_string());
        codes.insert(device_code.to_string(), data);
        Ok(())
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeData>, StorageError> {
        let codes = self
            .device_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(codes.get(device_code).cloned())
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeData>, StorageError> {
        let mapping = self
            .user_code_to_device_code
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if let Some(device_code) = mapping.get(user_code) {
            let codes = self
                .device_codes
                .lock()
                .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

            Ok(codes.get(device_code).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_device_code(
        &self,
        device_code: &str,
        data: DeviceCodeData,
    ) -> Result<(), StorageError> {
        let mut codes = self
            .device_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if !codes.contains_key(device_code) {
            return Err(StorageError::NotFound);
        }

        codes.insert(device_code.to_string(), data);
        Ok(())
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), StorageError> {
        let codes = self
            .device_codes
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        // Get user_code before removing
        if let Some(data) = codes.get(device_code) {
            let user_code = data.user_code.clone();
            drop(codes);

            let mut mapping = self
                .user_code_to_device_code
                .lock()
                .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;
            mapping.remove(&user_code);

            let mut codes = self
                .device_codes
                .lock()
                .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;
            codes.remove(device_code);
        }

        Ok(())
    }

    // Token Revocation operations
    async fn revoke_token(
        &self,
        token_jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let mut revoked = self
            .revoked_tokens
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        revoked.insert(token_jti.to_string(), expires_at);
        Ok(())
    }

    async fn is_token_revoked(&self, token_jti: &str) -> Result<bool, StorageError> {
        let revoked = self
            .revoked_tokens
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(revoked.contains_key(token_jti))
    }

    async fn cleanup_expired_revocations(&self) -> Result<usize, StorageError> {
        let mut revoked = self
            .revoked_tokens
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let now = Utc::now();
        let before_count = revoked.len();

        revoked.retain(|_, expires_at| *expires_at > now);

        let removed_count = before_count - revoked.len();
        Ok(removed_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authorization_code_operations() {
        let storage = MemoryStorage::new();
        let code = "test_code";
        let data = AuthorizationCodeData {
            tenant_id: "test".to_string(),
            client_id: "client1".to_string(),
            user_id: "user1".to_string(),
            redirect_uri: "http://localhost".to_string(),
            scope: "read".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
        };

        // Store
        storage
            .store_authorization_code(code, data.clone())
            .await
            .unwrap();

        // Get
        let retrieved = storage.get_authorization_code(code).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user1");

        // Delete
        storage.delete_authorization_code(code).await.unwrap();
        let deleted = storage.get_authorization_code(code).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_api_key_operations() {
        let storage = MemoryStorage::new();
        let key_id = "key1";
        let data = ApiKeyData {
            id: key_id.to_string(),
            tenant_id: "test".to_string(),
            name: "Test Key".to_string(),
            scopes: vec!["read".to_string()],
            created_at: Utc::now(),
            expires_at: None,
            last_used: None,
            revoked: false,
        };

        // Store
        storage.store_api_key(key_id, data.clone()).await.unwrap();

        // Get
        let retrieved = storage.get_api_key(key_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Key");

        // List
        let keys = storage.list_api_keys("test").await.unwrap();
        assert_eq!(keys.len(), 1);

        // Update
        let mut updated_data = data.clone();
        updated_data.revoked = true;
        storage.update_api_key(key_id, updated_data).await.unwrap();

        let retrieved = storage.get_api_key(key_id).await.unwrap();
        assert!(retrieved.unwrap().revoked);

        // Delete
        storage.delete_api_key(key_id).await.unwrap();
        let deleted = storage.get_api_key(key_id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_device_code_operations() {
        let storage = MemoryStorage::new();
        let device_code = "device123";
        let user_code = "USER-CODE";
        let data = DeviceCodeData {
            device_code: device_code.to_string(),
            user_code: user_code.to_string(),
            tenant_id: "test".to_string(),
            client_id: "client1".to_string(),
            scope: "read".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            status: DeviceCodeStatus::Pending,
            user_id: None,
        };

        // Store
        storage
            .store_device_code(device_code, data.clone())
            .await
            .unwrap();

        // Get by device code
        let retrieved = storage.get_device_code(device_code).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().status, DeviceCodeStatus::Pending);

        // Get by user code
        let retrieved = storage
            .get_device_code_by_user_code(user_code)
            .await
            .unwrap();
        assert!(retrieved.is_some());

        // Update
        let mut updated_data = data.clone();
        updated_data.status = DeviceCodeStatus::Authorized;
        updated_data.user_id = Some("user1".to_string());
        storage
            .update_device_code(device_code, updated_data)
            .await
            .unwrap();

        let retrieved = storage.get_device_code(device_code).await.unwrap();
        assert_eq!(retrieved.unwrap().status, DeviceCodeStatus::Authorized);

        // Delete
        storage.delete_device_code(device_code).await.unwrap();
        let deleted = storage.get_device_code(device_code).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_token_revocation() {
        let storage = MemoryStorage::new();
        let jti = "token123";
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        // Revoke
        storage.revoke_token(jti, expires_at).await.unwrap();

        // Check revoked
        let is_revoked = storage.is_token_revoked(jti).await.unwrap();
        assert!(is_revoked);

        // Check non-revoked
        let is_revoked = storage.is_token_revoked("other_token").await.unwrap();
        assert!(!is_revoked);
    }

    #[tokio::test]
    async fn test_cleanup_expired_revocations() {
        let storage = MemoryStorage::new();

        // Add expired token
        let expired_jti = "expired_token";
        let expired_at = Utc::now() - chrono::Duration::hours(1);
        storage.revoke_token(expired_jti, expired_at).await.unwrap();

        // Add valid token
        let valid_jti = "valid_token";
        let valid_expires_at = Utc::now() + chrono::Duration::hours(1);
        storage
            .revoke_token(valid_jti, valid_expires_at)
            .await
            .unwrap();

        // Cleanup
        let removed = storage.cleanup_expired_revocations().await.unwrap();
        assert_eq!(removed, 1);

        // Check expired token removed
        let is_revoked = storage.is_token_revoked(expired_jti).await.unwrap();
        assert!(!is_revoked);

        // Check valid token still there
        let is_revoked = storage.is_token_revoked(valid_jti).await.unwrap();
        assert!(is_revoked);
    }
}
