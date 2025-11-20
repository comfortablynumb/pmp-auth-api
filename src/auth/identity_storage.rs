// Identity Storage Implementation
// This module handles user authentication and lookup from various storage sources

#![allow(dead_code)]

use crate::models::{
    DatabaseStorageConfig, IdentityStorage, LdapStorageConfig, UserRole,
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;

/// User information retrieved from identity storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub role: UserRole,
    pub attributes: HashMap<String, String>,
}

/// Result from identity storage authentication
#[derive(Debug)]
pub struct AuthenticationResult {
    pub user: StorageUser,
    pub success: bool,
}

/// Trait for identity storage implementations
pub trait IdentityStorageTrait {
    /// Authenticate a user with username/password
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationResult, StorageError>;

    /// Look up a user by ID
    fn get_user_by_id(&self, user_id: &str) -> Result<StorageUser, StorageError>;

    /// Look up a user by email
    fn get_user_by_email(&self, email: &str) -> Result<StorageUser, StorageError>;

    /// Validate user exists
    fn validate_user(&self, email: &str) -> Result<StorageUser, StorageError>;
}

#[derive(Debug)]
pub enum StorageError {
    AuthenticationFailed,
    UserNotFound,
    ConnectionError(String),
    ConfigurationError(String),
    NotImplemented,
}

impl StorageError {
    pub fn to_status_code(&self) -> StatusCode {
        match self {
            StorageError::AuthenticationFailed => StatusCode::UNAUTHORIZED,
            StorageError::UserNotFound => StatusCode::NOT_FOUND,
            StorageError::ConnectionError(_) => StatusCode::SERVICE_UNAVAILABLE,
            StorageError::ConfigurationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StorageError::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::AuthenticationFailed => write!(f, "Authentication failed"),
            StorageError::UserNotFound => write!(f, "User not found"),
            StorageError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            StorageError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            StorageError::NotImplemented => write!(f, "Storage not implemented"),
        }
    }
}

impl From<ldap3::LdapError> for StorageError {
    fn from(error: ldap3::LdapError) -> Self {
        StorageError::ConnectionError(format!("LDAP error: {}", error))
    }
}

/// LDAP storage implementation
pub struct LdapStorage {
    _config: LdapStorageConfig,
}

impl LdapStorage {
    pub fn new(config: &LdapStorageConfig) -> Self {
        LdapStorage {
            _config: config.clone(),
        }
    }
}

impl IdentityStorageTrait for LdapStorage {
    fn authenticate(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<AuthenticationResult, StorageError> {
        // TODO: Implement LDAP bind authentication
        Err(StorageError::NotImplemented)
    }

    fn get_user_by_id(&self, _user_id: &str) -> Result<StorageUser, StorageError> {
        // TODO: Implement LDAP user lookup
        Err(StorageError::NotImplemented)
    }

    fn get_user_by_email(&self, _email: &str) -> Result<StorageUser, StorageError> {
        // TODO: Implement LDAP email lookup
        Err(StorageError::NotImplemented)
    }

    fn validate_user(&self, _email: &str) -> Result<StorageUser, StorageError> {
        // TODO: Implement LDAP user validation
        Err(StorageError::NotImplemented)
    }
}

/// Database storage implementation
pub struct DatabaseStorage {
    config: DatabaseStorageConfig,
    pool: sqlx::PgPool,
}

impl DatabaseStorage {
    pub fn new(config: &DatabaseStorageConfig) -> Self {
        // For test/mock connection URLs, create a dummy pool that will never be used
        // This avoids the "cannot start runtime from within runtime" error in tests
        if config.connection_url.starts_with("memory://")
            || config.connection_url.starts_with("test://")
            || config.connection_url == "memory://" {
            // Create minimal connection options without actually connecting
            let options = sqlx::postgres::PgConnectOptions::new()
                .host("localhost")
                .port(5432)
                .database("test");

            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy_with(options);

            return DatabaseStorage {
                config: config.clone(),
                pool,
            };
        }

        // Create a connection pool synchronously for real database URLs
        let pool = tokio::runtime::Handle::current()
            .block_on(async {
                sqlx::PgPool::connect(&config.connection_url)
                    .await
                    .expect("Failed to connect to database")
            });

        DatabaseStorage {
            config: config.clone(),
            pool,
        }
    }

    fn map_row_to_user(&self, row: &sqlx::postgres::PgRow) -> Result<StorageUser, StorageError> {
        let id: String = row
            .try_get(self.config.id_column.as_str())
            .map_err(|e| StorageError::ConfigurationError(format!("Missing id column: {}", e)))?;

        let email: String = row
            .try_get(self.config.email_column.as_str())
            .map_err(|e| {
                StorageError::ConfigurationError(format!("Missing email column: {}", e))
            })?;

        // Extract mapped attributes
        let mut attributes = HashMap::new();
        for (attr_name, column_name) in &self.config.attribute_mappings {
            if let Ok(value) = row.try_get::<String, _>(column_name.as_str()) {
                attributes.insert(attr_name.clone(), value);
            }
        }

        // Try to get name from attributes or use default
        let name = attributes.get("name").cloned();

        // Try to get role from attributes, default to User
        let role = attributes
            .get("role")
            .and_then(|r| match r.as_str() {
                "admin" | "Admin" => Some(UserRole::Admin),
                _ => Some(UserRole::User),
            })
            .unwrap_or(UserRole::User);

        Ok(StorageUser {
            id,
            email,
            name,
            picture: attributes.get("picture").cloned(),
            role,
            attributes,
        })
    }
}

impl IdentityStorageTrait for DatabaseStorage {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationResult, StorageError> {
        // For test/mock configurations, authentication should not be used
        // Tests should use the storage backend directly (MemoryStorage, etc.)
        if self.config.connection_url.starts_with("memory://")
            || self.config.connection_url.starts_with("test://")
            || self.config.connection_url == "memory://" {
            return Err(StorageError::ConfigurationError(
                "Database identity storage cannot be used with mock connection URLs. Use storage backend directly for authentication in tests.".to_string()
            ));
        }

        tokio::runtime::Handle::current().block_on(async {
            let query = format!(
                "SELECT * FROM {} WHERE {} = $1 OR {} = $1",
                self.config.users_table, self.config.email_column, self.config.id_column
            );

            let row = sqlx::query(&query)
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::ConnectionError(format!("Database query failed: {}", e)))?
                .ok_or(StorageError::AuthenticationFailed)?;

            // Get password hash from row
            let password_hash: String = row
                .try_get("password_hash")
                .map_err(|e| {
                    StorageError::ConfigurationError(format!("Missing password_hash column: {}", e))
                })?;

            // Verify password
            let valid = bcrypt::verify(password, &password_hash)
                .map_err(|e| StorageError::ConnectionError(format!("Password verification failed: {}", e)))?;

            if !valid {
                return Err(StorageError::AuthenticationFailed);
            }

            let user = self.map_row_to_user(&row)?;

            Ok(AuthenticationResult {
                user,
                success: true,
            })
        })
    }

    fn get_user_by_id(&self, user_id: &str) -> Result<StorageUser, StorageError> {
        if self.config.connection_url.starts_with("memory://")
            || self.config.connection_url.starts_with("test://")
            || self.config.connection_url == "memory://" {
            return Err(StorageError::ConfigurationError(
                "Database identity storage cannot be used with mock connection URLs".to_string()
            ));
        }

        tokio::runtime::Handle::current().block_on(async {
            let query = format!(
                "SELECT * FROM {} WHERE {} = $1",
                self.config.users_table, self.config.id_column
            );

            let row = sqlx::query(&query)
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::ConnectionError(format!("Database query failed: {}", e)))?
                .ok_or(StorageError::UserNotFound)?;

            self.map_row_to_user(&row)
        })
    }

    fn get_user_by_email(&self, email: &str) -> Result<StorageUser, StorageError> {
        if self.config.connection_url.starts_with("memory://")
            || self.config.connection_url.starts_with("test://")
            || self.config.connection_url == "memory://" {
            return Err(StorageError::ConfigurationError(
                "Database identity storage cannot be used with mock connection URLs".to_string()
            ));
        }

        tokio::runtime::Handle::current().block_on(async {
            let query = format!(
                "SELECT * FROM {} WHERE {} = $1",
                self.config.users_table, self.config.email_column
            );

            let row = sqlx::query(&query)
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::ConnectionError(format!("Database query failed: {}", e)))?
                .ok_or(StorageError::UserNotFound)?;

            self.map_row_to_user(&row)
        })
    }

    fn validate_user(&self, email: &str) -> Result<StorageUser, StorageError> {
        self.get_user_by_email(email)
    }
}

/// In-memory identity storage implementation that uses StorageBackend
pub struct MemoryIdentityStorage {
    storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
    tenant_id: String,
}

impl MemoryIdentityStorage {
    pub fn new(storage: std::sync::Arc<dyn crate::storage::StorageBackend>, tenant_id: String) -> Self {
        MemoryIdentityStorage { storage, tenant_id }
    }
}

impl IdentityStorageTrait for MemoryIdentityStorage {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationResult, StorageError> {
        // Use async runtime to call the storage backend
        let storage = self.storage.clone();
        let tenant_id = self.tenant_id.clone();
        let username = username.to_string();
        let password = password.to_string();

        // Use spawn and wait to execute async code from sync context
        let handle = tokio::runtime::Handle::current();
        let result = handle.block_on(async move {
            // Get user by email
            let user_data = storage
                .get_user_by_email(&tenant_id, &username)
                .await
                .map_err(|e| match e {
                    crate::storage::StorageError::NotFound => StorageError::UserNotFound,
                    _ => StorageError::ConnectionError(format!("Storage error: {}", e)),
                })?
                .ok_or(StorageError::UserNotFound)?;

            // Verify password
            let valid = bcrypt::verify(&password, &user_data.password_hash)
                .map_err(|e| StorageError::ConnectionError(format!("Password verification failed: {}", e)))?;

            if !valid {
                return Err(StorageError::AuthenticationFailed);
            }

            // Convert to StorageUser
            let user = StorageUser {
                id: user_data.id,
                email: user_data.email,
                name: user_data.name,
                picture: user_data.picture,
                role: UserRole::from_str(&user_data.role).unwrap_or(UserRole::User),
                attributes: user_data.attributes,
            };

            Ok(AuthenticationResult {
                user,
                success: true,
            })
        });
        result
    }

    fn get_user_by_id(&self, user_id: &str) -> Result<StorageUser, StorageError> {
        let storage = self.storage.clone();
        let user_id = user_id.to_string();

        let handle = tokio::runtime::Handle::current();
        let result = handle.block_on(async move {
            let user_data = storage
                .get_user(&user_id)
                .await
                .map_err(|e| match e {
                    crate::storage::StorageError::NotFound => StorageError::UserNotFound,
                    _ => StorageError::ConnectionError(format!("Storage error: {}", e)),
                })?
                .ok_or(StorageError::UserNotFound)?;

            Ok(StorageUser {
                id: user_data.id.clone(),
                email: user_data.email.clone(),
                name: user_data.name.clone(),
                picture: user_data.picture.clone(),
                role: UserRole::from_str(&user_data.role).unwrap_or(UserRole::User),
                attributes: user_data.attributes.clone(),
            })
        });
        result
    }

    fn get_user_by_email(&self, email: &str) -> Result<StorageUser, StorageError> {
        let storage = self.storage.clone();
        let tenant_id = self.tenant_id.clone();
        let email = email.to_string();

        let handle = tokio::runtime::Handle::current();
        let result = handle.block_on(async move {
            let user_data = storage
                .get_user_by_email(&tenant_id, &email)
                .await
                .map_err(|e| match e {
                    crate::storage::StorageError::NotFound => StorageError::UserNotFound,
                    _ => StorageError::ConnectionError(format!("Storage error: {}", e)),
                })?
                .ok_or(StorageError::UserNotFound)?;

            Ok(StorageUser {
                id: user_data.id.clone(),
                email: user_data.email.clone(),
                name: user_data.name.clone(),
                picture: user_data.picture.clone(),
                role: UserRole::from_str(&user_data.role).unwrap_or(UserRole::User),
                attributes: user_data.attributes.clone(),
            })
        });
        result
    }

    fn validate_user(&self, email: &str) -> Result<StorageUser, StorageError> {
        self.get_user_by_email(email)
    }
}

/// Factory function to create identity storage from configuration
pub fn create_identity_storage(
    config: &IdentityStorage,
) -> Box<dyn IdentityStorageTrait + Send + Sync> {
    match config {
        IdentityStorage::Ldap(c) => Box::new(LdapStorage::new(c)),
        IdentityStorage::Database(c) => Box::new(DatabaseStorage::new(c)),
    }
}

/// Factory function to create identity storage from configuration with storage backend
/// This is used when the configuration uses a memory:// URL for testing
pub fn create_identity_storage_with_backend(
    config: &IdentityStorage,
    storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
    tenant_id: &str,
) -> Box<dyn IdentityStorageTrait + Send + Sync> {
    match config {
        IdentityStorage::Database(db_config)
            if db_config.connection_url.starts_with("memory://")
            || db_config.connection_url.starts_with("test://") => {
            Box::new(MemoryIdentityStorage::new(storage, tenant_id.to_string()))
        }
        _ => create_identity_storage(config),
    }
}

