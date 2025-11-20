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

    // OAuth2 Client operations
    async fn store_oauth2_client(
        &self,
        client_id: &str,
        data: OAuth2ClientData,
    ) -> Result<(), StorageError>;

    async fn get_oauth2_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuth2ClientData>, StorageError>;

    async fn list_oauth2_clients(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<OAuth2ClientData>, StorageError>;

    async fn update_oauth2_client(
        &self,
        client_id: &str,
        data: OAuth2ClientData,
    ) -> Result<(), StorageError>;

    async fn delete_oauth2_client(&self, client_id: &str) -> Result<(), StorageError>;

    // Rate Limiting operations
    /// Check if rate limit exceeded for a key
    async fn check_rate_limit(
        &self,
        key: &str,
        max_attempts: u32,
        window_secs: u64,
    ) -> Result<bool, StorageError>;

    /// Record a rate limit attempt
    async fn record_rate_limit_attempt(&self, key: &str) -> Result<(), StorageError>;

    // User operations
    async fn store_user(&self, user_id: &str, data: UserData) -> Result<(), StorageError>;

    async fn get_user(&self, user_id: &str) -> Result<Option<UserData>, StorageError>;

    async fn get_user_by_email(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<UserData>, StorageError>;

    async fn list_users(&self, tenant_id: &str) -> Result<Vec<UserData>, StorageError>;

    async fn update_user(&self, user_id: &str, data: UserData) -> Result<(), StorageError>;

    async fn delete_user(&self, user_id: &str) -> Result<(), StorageError>;

    // Federated Identity operations
    /// Store a federated identity link between a user and an external provider
    async fn store_federated_identity(
        &self,
        data: FederatedIdentityData,
    ) -> Result<(), StorageError>;

    /// Get federated identity by provider and provider user ID
    async fn get_federated_identity(
        &self,
        tenant_id: &str,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<FederatedIdentityData>, StorageError>;

    /// Get all federated identities for a user
    async fn get_user_federated_identities(
        &self,
        user_id: &str,
    ) -> Result<Vec<FederatedIdentityData>, StorageError>;

    /// Delete a federated identity
    async fn delete_federated_identity(
        &self,
        tenant_id: &str,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<(), StorageError>;

    /// Get or create a user from federated authentication
    /// This method handles the logic for creating new users or linking to existing ones
    async fn get_or_create_federated_user(
        &self,
        tenant_id: &str,
        provider_id: &str,
        provider_user_info: &crate::auth::federation::ProviderUserInfo,
    ) -> Result<UserData, StorageError>;
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
    pub session_id: String, // Session ID for logout coordination (REQUIRED)
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
    pub session_id: String, // Session ID for logout coordination (REQUIRED)
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

/// OAuth2 client registration data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ClientData {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub grant_types: Vec<String>,
    /// Response types supported by this client (e.g., "code", "token", "id_token")
    #[serde(default)]
    pub response_types: Vec<String>,
    pub client_type: OAuth2ClientType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub active: bool,
    /// Public key (PEM format) for JWT client assertion with RS256/ES256
    #[serde(default)]
    pub public_key_pem: Option<String>,
    /// JWKS URI for retrieving client's public keys
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// JWKS keys (parsed from jwks_uri or provided inline) - stores multiple keys
    #[serde(default)]
    pub jwks_keys: Option<Vec<serde_json::Value>>,
    /// Token endpoint authentication method (client_secret_post, client_secret_basic, private_key_jwt, etc.)
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Back-channel logout URI (RFC 8965) - where to send logout notifications
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// Whether backchannel_logout_uri requires session_id (sid) claim
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// Front-channel logout URI (OIDC Front-Channel Logout) - embedded iframe for logout
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    /// Whether frontchannel_logout_uri requires session_id (sid) parameter
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
    /// Request URIs for pre-registered request objects (RFC 9101)
    #[serde(default)]
    pub request_uris: Option<Vec<String>>,
    /// JWKS for request object validation (inline keys)
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
}

/// OAuth2 client type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OAuth2ClientType {
    /// Confidential client (can securely store client secret)
    Confidential,
    /// Public client (cannot securely store secrets, e.g., SPAs, mobile apps)
    Public,
}

/// User data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub password_hash: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub role: String,
    pub active: bool,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub attributes: HashMap<String, String>,
}

/// Federated identity data - links a user to an external OAuth2/OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentityData {
    /// Unique ID for this federated identity
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Our internal user ID
    pub user_id: String,
    /// Provider ID (e.g., "google", "github", "azure-ad")
    pub provider_id: String,
    /// User ID from the external provider
    pub provider_user_id: String,
    /// Email from the external provider
    pub provider_email: String,
    /// Whether the email is verified by the provider
    pub provider_email_verified: bool,
    /// Full profile data from provider (JSON)
    pub provider_profile_data: serde_json::Value,
    /// When this identity was first linked
    pub created_at: DateTime<Utc>,
    /// When this identity was last updated
    pub updated_at: DateTime<Utc>,
    /// When the user last authenticated via this provider
    pub last_login_at: Option<DateTime<Utc>>,
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
