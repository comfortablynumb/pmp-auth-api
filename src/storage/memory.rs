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
    oauth2_clients: Arc<Mutex<HashMap<String, OAuth2ClientData>>>,
    rate_limits: Arc<Mutex<HashMap<String, Vec<DateTime<Utc>>>>>,
    users: Arc<Mutex<HashMap<String, UserData>>>,
    email_to_user_id: Arc<Mutex<HashMap<(String, String), String>>>, // (tenant_id, email) -> user_id
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
            oauth2_clients: Arc::new(Mutex::new(HashMap::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            users: Arc::new(Mutex::new(HashMap::new())),
            email_to_user_id: Arc::new(Mutex::new(HashMap::new())),
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

    // OAuth2 Client operations
    async fn store_oauth2_client(
        &self,
        client_id: &str,
        data: OAuth2ClientData,
    ) -> Result<(), StorageError> {
        let mut clients = self
            .oauth2_clients
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if clients.contains_key(client_id) {
            return Err(StorageError::AlreadyExists);
        }

        clients.insert(client_id.to_string(), data);
        Ok(())
    }

    async fn get_oauth2_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuth2ClientData>, StorageError> {
        let clients = self
            .oauth2_clients
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(clients.get(client_id).cloned())
    }

    async fn list_oauth2_clients(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<OAuth2ClientData>, StorageError> {
        let clients = self
            .oauth2_clients
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(clients
            .values()
            .filter(|client| client.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn update_oauth2_client(
        &self,
        client_id: &str,
        data: OAuth2ClientData,
    ) -> Result<(), StorageError> {
        let mut clients = self
            .oauth2_clients
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if !clients.contains_key(client_id) {
            return Err(StorageError::NotFound);
        }

        clients.insert(client_id.to_string(), data);
        Ok(())
    }

    async fn delete_oauth2_client(&self, client_id: &str) -> Result<(), StorageError> {
        let mut clients = self
            .oauth2_clients
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        clients
            .remove(client_id)
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // Rate Limiting operations
    async fn check_rate_limit(
        &self,
        key: &str,
        max_attempts: u32,
        window_secs: u64,
    ) -> Result<bool, StorageError> {
        let mut rate_limits = self
            .rate_limits
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(window_secs as i64);

        // Get attempts for this key
        let attempts = rate_limits.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove old attempts outside the window
        attempts.retain(|&attempt_time| attempt_time > window_start);

        // Check if limit exceeded
        Ok(attempts.len() >= max_attempts as usize)
    }

    async fn record_rate_limit_attempt(&self, key: &str) -> Result<(), StorageError> {
        let mut rate_limits = self
            .rate_limits
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let attempts = rate_limits.entry(key.to_string()).or_insert_with(Vec::new);
        attempts.push(Utc::now());
        Ok(())
    }

    // User operations
    async fn store_user(&self, user_id: &str, data: UserData) -> Result<(), StorageError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let mut email_mapping = self
            .email_to_user_id
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let email_key = (data.tenant_id.clone(), data.email.clone());

        if email_mapping.contains_key(&email_key) {
            return Err(StorageError::AlreadyExists);
        }

        email_mapping.insert(email_key, user_id.to_string());
        users.insert(user_id.to_string(), data);
        Ok(())
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<UserData>, StorageError> {
        let users = self
            .users
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(users.get(user_id).cloned())
    }

    async fn get_user_by_email(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<UserData>, StorageError> {
        let email_mapping = self
            .email_to_user_id
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        let email_key = (tenant_id.to_string(), email.to_string());

        if let Some(user_id) = email_mapping.get(&email_key) {
            let users = self
                .users
                .lock()
                .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_users(&self, tenant_id: &str) -> Result<Vec<UserData>, StorageError> {
        let users = self
            .users
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        Ok(users
            .values()
            .filter(|user| user.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn update_user(&self, user_id: &str, data: UserData) -> Result<(), StorageError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if !users.contains_key(user_id) {
            return Err(StorageError::NotFound);
        }

        let mut email_mapping = self
            .email_to_user_id
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        // Update email mapping if email changed
        if let Some(old_user) = users.get(user_id) {
            let old_email_key = (old_user.tenant_id.clone(), old_user.email.clone());
            let new_email_key = (data.tenant_id.clone(), data.email.clone());

            if old_email_key != new_email_key {
                email_mapping.remove(&old_email_key);
                email_mapping.insert(new_email_key, user_id.to_string());
            }
        }

        users.insert(user_id.to_string(), data);
        Ok(())
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), StorageError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

        if let Some(user_data) = users.remove(user_id) {
            let mut email_mapping = self
                .email_to_user_id
                .lock()
                .map_err(|e| StorageError::ConnectionError(format!("Lock poisoned: {}", e)))?;

            let email_key = (user_data.tenant_id, user_data.email);
            email_mapping.remove(&email_key);

            Ok(())
        } else {
            Err(StorageError::NotFound)
        }
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

    // Rate Limiting Tests

    #[tokio::test]
    async fn test_rate_limit_not_exceeded_initially() {
        let storage = MemoryStorage::new();
        let key = "test:user1";

        let exceeded = storage.check_rate_limit(key, 5, 60).await.unwrap();
        assert!(!exceeded, "Rate limit should not be exceeded initially");
    }

    #[tokio::test]
    async fn test_rate_limit_records_attempts() {
        let storage = MemoryStorage::new();
        let key = "test:user2";

        // Record 3 attempts
        for _ in 0..3 {
            storage.record_rate_limit_attempt(key).await.unwrap();
        }

        let exceeded = storage.check_rate_limit(key, 5, 60).await.unwrap();
        assert!(
            !exceeded,
            "Should not exceed limit with 3 attempts (limit is 5)"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_exceeded_after_max_attempts() {
        let storage = MemoryStorage::new();
        let key = "test:user3";
        let max_attempts = 5;

        // Record max attempts
        for _ in 0..max_attempts {
            storage.record_rate_limit_attempt(key).await.unwrap();
        }

        let exceeded = storage
            .check_rate_limit(key, max_attempts, 60)
            .await
            .unwrap();
        assert!(
            exceeded,
            "Rate limit should be exceeded after {} attempts",
            max_attempts
        );
    }

    #[tokio::test]
    async fn test_rate_limit_window_expiration() {
        let storage = MemoryStorage::new();
        let key = "test:user4";

        // This test verifies that rate limit checks work within the time window
        // Record an attempt
        storage.record_rate_limit_attempt(key).await.unwrap();

        // Check with a very short window (1 second)
        // The attempt was just recorded (< 1 second ago), so it should count
        let exceeded = storage.check_rate_limit(key, 1, 1).await.unwrap();
        assert!(exceeded, "Recent attempt should be within 1-second window and exceed limit of 1");

        // Check with a longer window - should still be counted
        let exceeded = storage.check_rate_limit(key, 5, 60).await.unwrap();
        assert!(!exceeded, "With higher limit of 5, should not be exceeded");
    }

    #[tokio::test]
    async fn test_rate_limit_different_keys_independent() {
        let storage = MemoryStorage::new();
        let key1 = "test:user5";
        let key2 = "test:user6";

        // Max out key1
        for _ in 0..5 {
            storage.record_rate_limit_attempt(key1).await.unwrap();
        }

        let exceeded1 = storage.check_rate_limit(key1, 5, 60).await.unwrap();
        let exceeded2 = storage.check_rate_limit(key2, 5, 60).await.unwrap();

        assert!(exceeded1, "Key1 should be rate limited");
        assert!(!exceeded2, "Key2 should not be rate limited");
    }
}
