// Storage backend abstraction
// Provides pluggable storage for authorization codes, tokens, API keys, etc.

#![allow(dead_code)]

pub mod memory;
pub mod postgres;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage backend trait for persisting authentication data
#[async_trait]
pub trait StorageBackend: Send + Sync {
    // Authorization Code operations
    async fn store_authorization_code(
        &self,
        code: &str,
        data: AuthorizationCodeData,
    ) -> Result<(), StorageError>;

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeData>, StorageError>;

    async fn delete_authorization_code(&self, code: &str) -> Result<(), StorageError>;

    // Refresh Token operations
    async fn store_refresh_token(
        &self,
        token: &str,
        data: RefreshTokenData,
    ) -> Result<(), StorageError>;

    async fn get_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshTokenData>, StorageError>;

    async fn delete_refresh_token(&self, token: &str) -> Result<(), StorageError>;

    // API Key operations
    async fn store_api_key(&self, key_id: &str, data: ApiKeyData) -> Result<(), StorageError>;

    async fn get_api_key(&self, key_id: &str) -> Result<Option<ApiKeyData>, StorageError>;

    async fn list_api_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyData>, StorageError>;

    async fn update_api_key(&self, key_id: &str, data: ApiKeyData) -> Result<(), StorageError>;

    async fn delete_api_key(&self, key_id: &str) -> Result<(), StorageError>;

    // Session operations (for device flow and OAuth2 sessions)
    async fn store_session(&self, session_id: &str, data: SessionData) -> Result<(), StorageError>;

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>, StorageError>;

    async fn delete_session(&self, session_id: &str) -> Result<(), StorageError>;

    // Device Flow operations (RFC 8628)
    async fn store_device_code(
        &self,
        device_code: &str,
        data: DeviceCodeData,
    ) -> Result<(), StorageError>;

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeData>, StorageError>;

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeData>, StorageError>;

    async fn update_device_code(
        &self,
        device_code: &str,
        data: DeviceCodeData,
    ) -> Result<(), StorageError>;

    async fn delete_device_code(&self, device_code: &str) -> Result<(), StorageError>;

    // Token Revocation operations
    async fn revoke_token(
        &self,
        token_jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StorageError>;

    async fn is_token_revoked(&self, token_jti: &str) -> Result<bool, StorageError>;

    async fn cleanup_expired_revocations(&self) -> Result<usize, StorageError>;
}

/// Authorization code data for OAuth2 flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeData {
    pub tenant_id: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Refresh token data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenData {
    pub tenant_id: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyData {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// Session data for OAuth2 and device flows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub client_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub data: HashMap<String, String>,
}

/// Device flow data (RFC 8628)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeData {
    pub device_code: String,
    pub user_code: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: DeviceCodeStatus,
    pub user_id: Option<String>,
}

/// Device code status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceCodeStatus {
    Pending,
    Authorized,
    Denied,
    Expired,
}

/// Storage errors
#[derive(Debug, Clone)]
pub enum StorageError {
    NotFound,
    AlreadyExists,
    ConnectionError(String),
    SerializationError(String),
    InvalidData(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "Item not found"),
            StorageError::AlreadyExists => write!(f, "Item already exists"),
            StorageError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            StorageError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            StorageError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

/// Factory function to create storage backend based on configuration
pub fn create_storage_backend(config: &crate::models::StorageConfig) -> Box<dyn StorageBackend> {
    match config {
        crate::models::StorageConfig::Memory => Box::new(memory::MemoryStorage::new()),
        crate::models::StorageConfig::Postgres { connection_string } => {
            Box::new(postgres::PostgresStorage::new(connection_string))
        }
    }
}
