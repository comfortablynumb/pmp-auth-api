// PostgreSQL storage backend implementation
// Uses sqlx for async database operations

use super::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Error as SqlxError, Row};
use std::time::Duration;

/// PostgreSQL storage backend
/// Uses sqlx connection pool for database operations
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Create a new PostgreSQL storage backend
    ///
    /// # Arguments
    /// * `connection_string` - PostgreSQL connection string (e.g., "postgres://user:pass@localhost/db")
    pub fn new(connection_string: &str) -> Self {
        // Create a pool with default settings
        // Note: This is synchronous initialization, actual connection happens on first query
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .max_lifetime(Duration::from_secs(1800))
            .connect_lazy(connection_string)
            .expect("Failed to create PostgreSQL pool");

        Self { pool }
    }

    /// Create a new PostgreSQL storage backend with custom pool
    pub fn with_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl StorageBackend for PostgresStorage {
    // Authorization Code operations
    async fn store_authorization_code(
        &self,
        code: &str,
        data: AuthorizationCodeData,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO authorization_codes
            (code, tenant_id, client_id, user_id, redirect_uri, scope, created_at, expires_at, code_challenge, code_challenge_method, nonce)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(code)
        .bind(&data.tenant_id)
        .bind(&data.client_id)
        .bind(&data.user_id)
        .bind(&data.redirect_uri)
        .bind(&data.scope)
        .bind(data.created_at)
        .bind(data.expires_at)
        .bind(data.code_challenge.as_deref())
        .bind(data.code_challenge_method.as_deref())
        .bind(data.nonce.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store authorization code: {}", e))
        })?;

        Ok(())
    }

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT tenant_id, client_id, user_id, redirect_uri, scope, created_at, expires_at,
                   code_challenge, code_challenge_method, nonce
            FROM authorization_codes
            WHERE code = $1
            "#,
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get authorization code: {}", e))
        })?;

        Ok(result.map(|row| AuthorizationCodeData {
            tenant_id: row.get("tenant_id"),
            client_id: row.get("client_id"),
            user_id: row.get("user_id"),
            redirect_uri: row.get("redirect_uri"),
            scope: row.get("scope"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            code_challenge: row.get("code_challenge"),
            code_challenge_method: row.get("code_challenge_method"),
            nonce: row.get("nonce"),
        }))
    }

    async fn delete_authorization_code(&self, code: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM authorization_codes WHERE code = $1")
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!("Failed to delete authorization code: {}", e))
            })?;

        Ok(())
    }

    // Refresh Token operations
    async fn store_refresh_token(
        &self,
        token: &str,
        data: RefreshTokenData,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens
            (token, tenant_id, client_id, user_id, scope, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(token)
        .bind(&data.tenant_id)
        .bind(&data.client_id)
        .bind(&data.user_id)
        .bind(&data.scope)
        .bind(data.created_at)
        .bind(data.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store refresh token: {}", e))
        })?;

        Ok(())
    }

    async fn get_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshTokenData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT tenant_id, client_id, user_id, scope, created_at, expires_at
            FROM refresh_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get refresh token: {}", e))
        })?;

        Ok(result.map(|row| RefreshTokenData {
            tenant_id: row.get("tenant_id"),
            client_id: row.get("client_id"),
            user_id: row.get("user_id"),
            scope: row.get("scope"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        }))
    }

    async fn delete_refresh_token(&self, token: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!("Failed to delete refresh token: {}", e))
            })?;

        Ok(())
    }

    // API Key operations
    async fn store_api_key(&self, key_id: &str, data: ApiKeyData) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO api_keys
            (id, tenant_id, name, scopes, created_at, expires_at, last_used, revoked)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(key_id)
        .bind(&data.tenant_id)
        .bind(&data.name)
        .bind(&data.scopes)
        .bind(data.created_at)
        .bind(data.expires_at)
        .bind(data.last_used)
        .bind(data.revoked)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store API key: {}", e))
        })?;

        Ok(())
    }

    async fn get_api_key(&self, key_id: &str) -> Result<Option<ApiKeyData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT id, tenant_id, name, scopes, created_at, expires_at, last_used, revoked
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to get API key: {}", e)))?;

        Ok(result.map(|row| ApiKeyData {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            name: row.get("name"),
            scopes: row.get("scopes"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            last_used: row.get("last_used"),
            revoked: row.get("revoked"),
        }))
    }

    async fn list_api_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyData>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, name, scopes, created_at, expires_at, last_used, revoked
            FROM api_keys
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to list API keys: {}", e)))?;

        Ok(rows
            .into_iter()
            .map(|row| ApiKeyData {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                name: row.get("name"),
                scopes: row.get("scopes"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                last_used: row.get("last_used"),
                revoked: row.get("revoked"),
            })
            .collect())
    }

    async fn update_api_key(&self, key_id: &str, data: ApiKeyData) -> Result<(), StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET name = $2, scopes = $3, expires_at = $4, last_used = $5, revoked = $6
            WHERE id = $1
            "#,
        )
        .bind(key_id)
        .bind(&data.name)
        .bind(&data.scopes)
        .bind(data.expires_at)
        .bind(data.last_used)
        .bind(data.revoked)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to update API key: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    async fn delete_api_key(&self, key_id: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(key_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!("Failed to delete API key: {}", e))
            })?;

        Ok(())
    }

    // Session operations
    async fn store_session(&self, session_id: &str, data: SessionData) -> Result<(), StorageError> {
        let data_json = serde_json::to_value(&data.data).map_err(|e| {
            StorageError::SerializationError(format!("Failed to serialize session data: {}", e))
        })?;

        sqlx::query(
            r#"
            INSERT INTO sessions
            (session_id, tenant_id, user_id, client_id, created_at, expires_at, data)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(session_id)
        .bind(&data.tenant_id)
        .bind(data.user_id.as_deref())
        .bind(&data.client_id)
        .bind(data.created_at)
        .bind(data.expires_at)
        .bind(data_json)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store session: {}", e))
        })?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT session_id, tenant_id, user_id, client_id, created_at, expires_at, data
            FROM sessions
            WHERE session_id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to get session: {}", e)))?;

        Ok(result.map(|row| {
            let data_json: serde_json::Value = row.get("data");
            let data: HashMap<String, String> =
                serde_json::from_value(data_json).unwrap_or_else(|_| HashMap::new());

            SessionData {
                session_id: row.get("session_id"),
                tenant_id: row.get("tenant_id"),
                user_id: row.get("user_id"),
                client_id: row.get("client_id"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                data,
            }
        }))
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM sessions WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!("Failed to delete session: {}", e))
            })?;

        Ok(())
    }

    // Device Flow operations
    async fn store_device_code(
        &self,
        device_code: &str,
        data: DeviceCodeData,
    ) -> Result<(), StorageError> {
        let status = match data.status {
            DeviceCodeStatus::Pending => "pending",
            DeviceCodeStatus::Authorized => "authorized",
            DeviceCodeStatus::Denied => "denied",
            DeviceCodeStatus::Expired => "expired",
        };

        sqlx::query(
            r#"
            INSERT INTO device_codes
            (device_code, user_code, tenant_id, client_id, scope, created_at, expires_at, status, user_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(device_code)
        .bind(&data.user_code)
        .bind(&data.tenant_id)
        .bind(&data.client_id)
        .bind(&data.scope)
        .bind(data.created_at)
        .bind(data.expires_at)
        .bind(status)
        .bind(data.user_id.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store device code: {}", e))
        })?;

        Ok(())
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT device_code, user_code, tenant_id, client_id, scope, created_at, expires_at, status, user_id
            FROM device_codes
            WHERE device_code = $1
            "#,
        )
        .bind(device_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get device code: {}", e))
        })?;

        Ok(result.map(|row| {
            let status_str: String = row.get("status");
            let status = match status_str.as_str() {
                "pending" => DeviceCodeStatus::Pending,
                "authorized" => DeviceCodeStatus::Authorized,
                "denied" => DeviceCodeStatus::Denied,
                "expired" => DeviceCodeStatus::Expired,
                _ => DeviceCodeStatus::Pending,
            };

            DeviceCodeData {
                device_code: row.get("device_code"),
                user_code: row.get("user_code"),
                tenant_id: row.get("tenant_id"),
                client_id: row.get("client_id"),
                scope: row.get("scope"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                status,
                user_id: row.get("user_id"),
            }
        }))
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT device_code, user_code, tenant_id, client_id, scope, created_at, expires_at, status, user_id
            FROM device_codes
            WHERE user_code = $1
            "#,
        )
        .bind(user_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get device code by user code: {}", e))
        })?;

        Ok(result.map(|row| {
            let status_str: String = row.get("status");
            let status = match status_str.as_str() {
                "pending" => DeviceCodeStatus::Pending,
                "authorized" => DeviceCodeStatus::Authorized,
                "denied" => DeviceCodeStatus::Denied,
                "expired" => DeviceCodeStatus::Expired,
                _ => DeviceCodeStatus::Pending,
            };

            DeviceCodeData {
                device_code: row.get("device_code"),
                user_code: row.get("user_code"),
                tenant_id: row.get("tenant_id"),
                client_id: row.get("client_id"),
                scope: row.get("scope"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                status,
                user_id: row.get("user_id"),
            }
        }))
    }

    async fn update_device_code(
        &self,
        device_code: &str,
        data: DeviceCodeData,
    ) -> Result<(), StorageError> {
        let status = match data.status {
            DeviceCodeStatus::Pending => "pending",
            DeviceCodeStatus::Authorized => "authorized",
            DeviceCodeStatus::Denied => "denied",
            DeviceCodeStatus::Expired => "expired",
        };

        let result = sqlx::query(
            r#"
            UPDATE device_codes
            SET status = $2, user_id = $3
            WHERE device_code = $1
            "#,
        )
        .bind(device_code)
        .bind(status)
        .bind(data.user_id.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to update device code: {}", e))
        })?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
            .bind(device_code)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!("Failed to delete device code: {}", e))
            })?;

        Ok(())
    }

    // Token Revocation operations
    async fn revoke_token(
        &self,
        token_jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO revoked_tokens (jti, expires_at)
            VALUES ($1, $2)
            ON CONFLICT (jti) DO NOTHING
            "#,
        )
        .bind(token_jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to revoke token: {}", e)))?;

        Ok(())
    }

    async fn is_token_revoked(&self, token_jti: &str) -> Result<bool, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM revoked_tokens
            WHERE jti = $1
            "#,
        )
        .bind(token_jti)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to check token revocation: {}", e))
        })?;

        let count: i64 = result.get("count");
        Ok(count > 0)
    }

    async fn cleanup_expired_revocations(&self) -> Result<usize, StorageError> {
        let result = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!(
                    "Failed to cleanup expired revocations: {}",
                    e
                ))
            })?;

        Ok(result.rows_affected() as usize)
    }

    // OAuth2 Client operations
    async fn store_oauth2_client(
        &self,
        client_id: &str,
        data: OAuth2ClientData,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO oauth2_clients
            (client_id, client_secret, tenant_id, name, description, redirect_uris,
             allowed_scopes, grant_types, response_types, client_type, created_at, updated_at, active,
             public_key_pem, jwks_uri, jwks_keys, token_endpoint_auth_method,
             backchannel_logout_uri, backchannel_logout_session_required,
             frontchannel_logout_uri, frontchannel_logout_session_required)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
            "#,
        )
        .bind(client_id)
        .bind(&data.client_secret)
        .bind(&data.tenant_id)
        .bind(&data.name)
        .bind(&data.description)
        .bind(&data.redirect_uris)
        .bind(&data.allowed_scopes)
        .bind(&data.grant_types)
        .bind(&data.response_types)
        .bind(match data.client_type {
            OAuth2ClientType::Confidential => "confidential",
            OAuth2ClientType::Public => "public",
        })
        .bind(data.created_at)
        .bind(data.updated_at)
        .bind(data.active)
        .bind(&data.public_key_pem)
        .bind(&data.jwks_uri)
        .bind(&data.jwks_keys)
        .bind(&data.token_endpoint_auth_method)
        .bind(&data.backchannel_logout_uri)
        .bind(data.backchannel_logout_session_required)
        .bind(&data.frontchannel_logout_uri)
        .bind(data.frontchannel_logout_session_required)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store OAuth2 client: {}", e))
        })?;

        Ok(())
    }

    async fn get_oauth2_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuth2ClientData>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT client_id, client_secret, tenant_id, name, description, redirect_uris,
                   allowed_scopes, grant_types, response_types, client_type, created_at, updated_at, active,
                   public_key_pem, jwks_uri, jwks_keys, token_endpoint_auth_method,
                   backchannel_logout_uri, backchannel_logout_session_required,
                   frontchannel_logout_uri, frontchannel_logout_session_required
            FROM oauth2_clients
            WHERE client_id = $1
            "#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get OAuth2 client: {}", e))
        })?;

        match row {
            Some(row) => {
                let client_type_str: String = row.get("client_type");
                let client_type = match client_type_str.as_str() {
                    "confidential" => OAuth2ClientType::Confidential,
                    "public" => OAuth2ClientType::Public,
                    _ => {
                        return Err(StorageError::InvalidData(format!(
                            "Unknown client_type: {}",
                            client_type_str
                        )))
                    }
                };

                Ok(Some(OAuth2ClientData {
                    client_id: row.get("client_id"),
                    client_secret: row.get("client_secret"),
                    tenant_id: row.get("tenant_id"),
                    name: row.get("name"),
                    description: row.get("description"),
                    redirect_uris: row.get("redirect_uris"),
                    allowed_scopes: row.get("allowed_scopes"),
                    grant_types: row.get("grant_types"),
                    response_types: row.get("response_types"),
                    client_type,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                    active: row.get("active"),
                    public_key_pem: row.get("public_key_pem"),
                    jwks_uri: row.get("jwks_uri"),
                    jwks_keys: row.get("jwks_keys"),
                    token_endpoint_auth_method: row.get("token_endpoint_auth_method"),
                    backchannel_logout_uri: row.get("backchannel_logout_uri"),
                    backchannel_logout_session_required: row.get("backchannel_logout_session_required"),
                    frontchannel_logout_uri: row.get("frontchannel_logout_uri"),
                    frontchannel_logout_session_required: row.get("frontchannel_logout_session_required"),
                    request_uris: None, // TODO: Add to database schema
                    jwks: None,          // TODO: Add to database schema
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_oauth2_clients(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<OAuth2ClientData>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT client_id, client_secret, tenant_id, name, description, redirect_uris,
                   allowed_scopes, grant_types, response_types, client_type, created_at, updated_at, active,
                   public_key_pem, jwks_uri, jwks_keys, token_endpoint_auth_method,
                   backchannel_logout_uri, backchannel_logout_session_required,
                   frontchannel_logout_uri, frontchannel_logout_session_required
            FROM oauth2_clients
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to list OAuth2 clients: {}", e))
        })?;

        let mut clients = Vec::new();

        for row in rows {
            let client_type_str: String = row.get("client_type");
            let client_type = match client_type_str.as_str() {
                "confidential" => OAuth2ClientType::Confidential,
                "public" => OAuth2ClientType::Public,
                _ => {
                    return Err(StorageError::InvalidData(format!(
                        "Unknown client_type: {}",
                        client_type_str
                    )))
                }
            };

            clients.push(OAuth2ClientData {
                client_id: row.get("client_id"),
                client_secret: row.get("client_secret"),
                tenant_id: row.get("tenant_id"),
                name: row.get("name"),
                description: row.get("description"),
                redirect_uris: row.get("redirect_uris"),
                allowed_scopes: row.get("allowed_scopes"),
                grant_types: row.get("grant_types"),
                response_types: row.get("response_types"),
                client_type,
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                active: row.get("active"),
                public_key_pem: row.get("public_key_pem"),
                jwks_uri: row.get("jwks_uri"),
                jwks_keys: row.get("jwks_keys"),
                token_endpoint_auth_method: row.get("token_endpoint_auth_method"),
                backchannel_logout_uri: row.get("backchannel_logout_uri"),
                backchannel_logout_session_required: row.get("backchannel_logout_session_required"),
                frontchannel_logout_uri: row.get("frontchannel_logout_uri"),
                frontchannel_logout_session_required: row.get("frontchannel_logout_session_required"),
                request_uris: row.get("request_uris"),
                jwks: row.get("jwks"),
            });
        }

        Ok(clients)
    }

    async fn update_oauth2_client(
        &self,
        client_id: &str,
        data: OAuth2ClientData,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            r#"
            UPDATE oauth2_clients
            SET client_secret = $2, tenant_id = $3, name = $4, description = $5,
                redirect_uris = $6, allowed_scopes = $7, grant_types = $8, response_types = $9,
                client_type = $10, updated_at = $11, active = $12,
                public_key_pem = $13, jwks_uri = $14, jwks_keys = $15, token_endpoint_auth_method = $16,
                backchannel_logout_uri = $17, backchannel_logout_session_required = $18,
                frontchannel_logout_uri = $19, frontchannel_logout_session_required = $20
            WHERE client_id = $1
            "#,
        )
        .bind(client_id)
        .bind(&data.client_secret)
        .bind(&data.tenant_id)
        .bind(&data.name)
        .bind(&data.description)
        .bind(&data.redirect_uris)
        .bind(&data.allowed_scopes)
        .bind(&data.grant_types)
        .bind(&data.response_types)
        .bind(match data.client_type {
            OAuth2ClientType::Confidential => "confidential",
            OAuth2ClientType::Public => "public",
        })
        .bind(data.updated_at)
        .bind(data.active)
        .bind(&data.public_key_pem)
        .bind(&data.jwks_uri)
        .bind(&data.jwks_keys)
        .bind(&data.token_endpoint_auth_method)
        .bind(&data.backchannel_logout_uri)
        .bind(data.backchannel_logout_session_required)
        .bind(&data.frontchannel_logout_uri)
        .bind(data.frontchannel_logout_session_required)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to update OAuth2 client: {}", e))
        })?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    async fn delete_oauth2_client(&self, client_id: &str) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM oauth2_clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::ConnectionError(format!("Failed to delete OAuth2 client: {}", e))
            })?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    // Rate Limiting operations
    async fn check_rate_limit(
        &self,
        _key: &str,
        _max_attempts: u32,
        _window_secs: u64,
    ) -> Result<bool, StorageError> {
        // For PostgreSQL, we'll use a simple query
        // In production, consider using Redis for better performance
        // This is a placeholder - rate limiting in PostgreSQL should use a dedicated table

        // For now, return false (not rate limited)
        Ok(false)
    }

    async fn record_rate_limit_attempt(&self, _key: &str) -> Result<(), StorageError> {
        // Placeholder - would insert into rate_limit table
        Ok(())
    }

    // User operations
    async fn store_user(&self, user_id: &str, data: UserData) -> Result<(), StorageError> {
        let attributes_json = serde_json::to_value(&data.attributes).map_err(|e| {
            StorageError::SerializationError(format!("Failed to serialize user attributes: {}", e))
        })?;

        sqlx::query(
            r#"
            INSERT INTO users
            (id, tenant_id, email, password_hash, name, picture, role, active, email_verified, created_at, updated_at, attributes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(user_id)
        .bind(&data.tenant_id)
        .bind(&data.email)
        .bind(&data.password_hash)
        .bind(data.name.as_deref())
        .bind(data.picture.as_deref())
        .bind(&data.role)
        .bind(data.active)
        .bind(data.email_verified)
        .bind(data.created_at)
        .bind(data.updated_at)
        .bind(attributes_json)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let SqlxError::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return StorageError::AlreadyExists;
                }
            }
            StorageError::ConnectionError(format!("Failed to store user: {}", e))
        })?;

        Ok(())
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<UserData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT id, tenant_id, email, password_hash, name, picture, role, active, email_verified, created_at, updated_at, attributes
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to get user: {}", e)))?;

        Ok(result.map(|row| {
            let attributes_json: serde_json::Value = row.get("attributes");
            let attributes: HashMap<String, String> =
                serde_json::from_value(attributes_json).unwrap_or_else(|_| HashMap::new());

            UserData {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                name: row.get("name"),
                picture: row.get("picture"),
                role: row.get("role"),
                active: row.get("active"),
                email_verified: row.get("email_verified"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                attributes,
            }
        }))
    }

    async fn get_user_by_email(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<UserData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT id, tenant_id, email, password_hash, name, picture, role, active, email_verified, created_at, updated_at, attributes
            FROM users
            WHERE tenant_id = $1 AND email = $2
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get user by email: {}", e))
        })?;

        Ok(result.map(|row| {
            let attributes_json: serde_json::Value = row.get("attributes");
            let attributes: HashMap<String, String> =
                serde_json::from_value(attributes_json).unwrap_or_else(|_| HashMap::new());

            UserData {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                name: row.get("name"),
                picture: row.get("picture"),
                role: row.get("role"),
                active: row.get("active"),
                email_verified: row.get("email_verified"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                attributes,
            }
        }))
    }

    async fn list_users(&self, tenant_id: &str) -> Result<Vec<UserData>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, email, password_hash, name, picture, role, active, email_verified, created_at, updated_at, attributes
            FROM users
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to list users: {}", e)))?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let attributes_json: serde_json::Value = row.get("attributes");
                let attributes: HashMap<String, String> =
                    serde_json::from_value(attributes_json).unwrap_or_else(|_| HashMap::new());

                UserData {
                    id: row.get("id"),
                    tenant_id: row.get("tenant_id"),
                    email: row.get("email"),
                    password_hash: row.get("password_hash"),
                    name: row.get("name"),
                    picture: row.get("picture"),
                    role: row.get("role"),
                    active: row.get("active"),
                    email_verified: row.get("email_verified"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                    attributes,
                }
            })
            .collect())
    }

    async fn update_user(&self, user_id: &str, data: UserData) -> Result<(), StorageError> {
        let attributes_json = serde_json::to_value(&data.attributes).map_err(|e| {
            StorageError::SerializationError(format!("Failed to serialize user attributes: {}", e))
        })?;

        let result = sqlx::query(
            r#"
            UPDATE users
            SET email = $2, password_hash = $3, name = $4, picture = $5, role = $6, active = $7, email_verified = $8, updated_at = $9, attributes = $10
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(&data.email)
        .bind(&data.password_hash)
        .bind(data.name.as_deref())
        .bind(data.picture.as_deref())
        .bind(&data.role)
        .bind(data.active)
        .bind(data.email_verified)
        .bind(data.updated_at)
        .bind(attributes_json)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionError(format!("Failed to update user: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::ConnectionError(format!("Failed to delete user: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    // Federated Identity operations
    async fn store_federated_identity(
        &self,
        data: FederatedIdentityData,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO federated_identities
            (id, tenant_id, user_id, provider_id, provider_user_id, provider_email,
             provider_email_verified, provider_profile_data, created_at, updated_at, last_login_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (tenant_id, provider_id, provider_user_id)
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                provider_email = EXCLUDED.provider_email,
                provider_email_verified = EXCLUDED.provider_email_verified,
                provider_profile_data = EXCLUDED.provider_profile_data,
                updated_at = EXCLUDED.updated_at,
                last_login_at = EXCLUDED.last_login_at
            "#,
        )
        .bind(&data.id)
        .bind(&data.tenant_id)
        .bind(&data.user_id)
        .bind(&data.provider_id)
        .bind(&data.provider_user_id)
        .bind(&data.provider_email)
        .bind(data.provider_email_verified)
        .bind(&data.provider_profile_data)
        .bind(data.created_at)
        .bind(data.updated_at)
        .bind(data.last_login_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to store federated identity: {}", e))
        })?;

        Ok(())
    }

    async fn get_federated_identity(
        &self,
        tenant_id: &str,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<FederatedIdentityData>, StorageError> {
        let result = sqlx::query(
            r#"
            SELECT id, tenant_id, user_id, provider_id, provider_user_id, provider_email,
                   provider_email_verified, provider_profile_data, created_at, updated_at, last_login_at
            FROM federated_identities
            WHERE tenant_id = $1 AND provider_id = $2 AND provider_user_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(provider_id)
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to get federated identity: {}", e))
        })?;

        match result {
            Some(row) => Ok(Some(FederatedIdentityData {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                user_id: row.get("user_id"),
                provider_id: row.get("provider_id"),
                provider_user_id: row.get("provider_user_id"),
                provider_email: row.get("provider_email"),
                provider_email_verified: row.get("provider_email_verified"),
                provider_profile_data: row.get("provider_profile_data"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                last_login_at: row.get("last_login_at"),
            })),
            None => Ok(None),
        }
    }

    async fn get_user_federated_identities(
        &self,
        user_id: &str,
    ) -> Result<Vec<FederatedIdentityData>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, user_id, provider_id, provider_user_id, provider_email,
                   provider_email_verified, provider_profile_data, created_at, updated_at, last_login_at
            FROM federated_identities
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!(
                "Failed to get user federated identities: {}",
                e
            ))
        })?;

        Ok(rows
            .iter()
            .map(|row| FederatedIdentityData {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                user_id: row.get("user_id"),
                provider_id: row.get("provider_id"),
                provider_user_id: row.get("provider_user_id"),
                provider_email: row.get("provider_email"),
                provider_email_verified: row.get("provider_email_verified"),
                provider_profile_data: row.get("provider_profile_data"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                last_login_at: row.get("last_login_at"),
            })
            .collect())
    }

    async fn delete_federated_identity(
        &self,
        tenant_id: &str,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "DELETE FROM federated_identities WHERE tenant_id = $1 AND provider_id = $2 AND provider_user_id = $3",
        )
        .bind(tenant_id)
        .bind(provider_id)
        .bind(provider_user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::ConnectionError(format!("Failed to delete federated identity: {}", e))
        })?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }

        Ok(())
    }

    async fn get_or_create_federated_user(
        &self,
        tenant_id: &str,
        provider_id: &str,
        provider_user_info: &crate::auth::federation::ProviderUserInfo,
    ) -> Result<UserData, StorageError> {
        use uuid::Uuid;

        // Check if this federated identity already exists
        if let Some(existing_identity) = self
            .get_federated_identity(tenant_id, provider_id, &provider_user_info.provider_user_id)
            .await?
        {
            // Update last login time
            let mut updated_identity = existing_identity.clone();
            updated_identity.last_login_at = Some(Utc::now());
            updated_identity.updated_at = Utc::now();
            updated_identity.provider_email = provider_user_info.email.clone();
            updated_identity.provider_email_verified = provider_user_info.email_verified.unwrap_or(false);
            updated_identity.provider_profile_data = provider_user_info.raw_profile.clone();

            self.store_federated_identity(updated_identity).await?;

            // Return existing user
            return self
                .get_user(&existing_identity.user_id)
                .await?
                .ok_or(StorageError::NotFound);
        }

        // Check if user exists with this email
        let existing_user = self.get_user_by_email(tenant_id, &provider_user_info.email).await?;

        // TODO: Check federation configuration for disallow_user_creation
        // For now, we'll always allow user creation if they don't exist

        let user = if let Some(mut user) = existing_user {
            // TODO: Check federation configuration for disallow_user_from_multiple_providers
            // For now, we'll allow linking multiple providers to the same user

            // Update user information if needed
            if user.name.is_none() && provider_user_info.name.is_some() {
                user.name = provider_user_info.name.clone();
            }

            if user.picture.is_none() && provider_user_info.picture.is_some() {
                user.picture = provider_user_info.picture.clone();
            }

            // Email verification from trusted providers
            if provider_user_info.email_verified.unwrap_or(false) && !user.email_verified {
                user.email_verified = true;
            }

            user.updated_at = Utc::now();

            // Update user in database
            self.update_user(&user.id, user.clone()).await?;

            user
        } else {
            // Create new user
            let user_id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let new_user = UserData {
                id: user_id.clone(),
                tenant_id: tenant_id.to_string(),
                email: provider_user_info.email.clone(),
                password_hash: String::new(), // No password for federated users
                name: provider_user_info.name.clone(),
                picture: provider_user_info.picture.clone(),
                role: "user".to_string(),
                active: true,
                email_verified: provider_user_info.email_verified.unwrap_or(false),
                created_at: now,
                updated_at: now,
                attributes: std::collections::HashMap::new(),
            };

            self.store_user(&user_id, new_user.clone()).await?;

            new_user
        };

        // Create federated identity link
        let federated_identity = FederatedIdentityData {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            user_id: user.id.clone(),
            provider_id: provider_id.to_string(),
            provider_user_id: provider_user_info.provider_user_id.clone(),
            provider_email: provider_user_info.email.clone(),
            provider_email_verified: provider_user_info.email_verified.unwrap_or(false),
            provider_profile_data: provider_user_info.raw_profile.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: Some(Utc::now()),
        };

        self.store_federated_identity(federated_identity).await?;

        Ok(user)
    }
}
