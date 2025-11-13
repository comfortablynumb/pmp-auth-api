use crate::auth::identity_backend::{AuthenticationResult, BackendError, BackendUser};
use crate::models::{LdapBackendConfig, UserRole};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// LDAP connection wrapper
pub struct LdapConnection {
    url: String,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    settings: LdapConnSettings,
}

impl LdapConnection {
    pub fn new(config: &LdapBackendConfig) -> Self {
        let mut settings = LdapConnSettings::new();
        settings = settings.set_conn_timeout(Duration::from_secs(10));

        // Enable StartTLS if configured
        if config.use_starttls.unwrap_or(false) {
            settings = settings.set_starttls(true);
        }

        Self {
            url: config.url.clone(),
            bind_dn: config.bind_dn.clone(),
            bind_password: config.bind_password.clone(),
            settings,
        }
    }

    /// Create an LDAP connection
    pub async fn connect(&self) -> Result<ldap3::Ldap, BackendError> {
        let (conn, mut ldap) = LdapConnAsync::with_settings(self.settings.clone(), &self.url)
            .await
            .map_err(|e| {
                error!("LDAP connection failed: {}", e);
                BackendError::ConnectionError(format!("Failed to connect to LDAP server: {}", e))
            })?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection driver error: {}", e);
            }
        });

        // Bind with service account if configured
        if let (Some(bind_dn), Some(bind_password)) = (&self.bind_dn, &self.bind_password) {
            ldap.simple_bind(bind_dn, bind_password)
                .await
                .map_err(|e| {
                    error!("LDAP bind failed: {}", e);
                    BackendError::ConnectionError(format!("Failed to bind to LDAP server: {}", e))
                })?;
        }

        Ok(ldap)
    }
}

/// Complete LDAP backend implementation
pub struct LdapBackendImpl {
    config: LdapBackendConfig,
    connection: LdapConnection,
}

impl LdapBackendImpl {
    pub fn new(config: LdapBackendConfig) -> Self {
        let connection = LdapConnection::new(&config);
        Self { config, connection }
    }

    /// Authenticate user with LDAP bind
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationResult, BackendError> {
        debug!("Attempting LDAP authentication for user: {}", username);

        // First, find the user's DN
        let user_dn = self.find_user_dn(username).await?;

        // Try to bind with the user's credentials
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(self.connection.settings.clone(), &self.connection.url)
                .await
                .map_err(|e| {
                    error!("LDAP connection failed during authentication: {}", e);
                    BackendError::ConnectionError(format!("Connection failed: {}", e))
                })?;

        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection driver error: {}", e);
            }
        });

        // Attempt user bind
        let bind_result = ldap.simple_bind(&user_dn, password).await;

        match bind_result {
            Ok(result) => {
                if result.success().is_ok() {
                    info!("LDAP authentication successful for user: {}", username);

                    // Now fetch user details
                    let user = self.get_user_by_username(username).await?;

                    Ok(AuthenticationResult {
                        user,
                        success: true,
                    })
                } else {
                    warn!("LDAP bind failed for user: {}", username);
                    Err(BackendError::AuthenticationFailed)
                }
            }
            Err(e) => {
                error!("LDAP bind error for user {}: {}", username, e);
                Err(BackendError::AuthenticationFailed)
            }
        }
    }

    /// Find user's DN by username
    async fn find_user_dn(&self, username: &str) -> Result<String, BackendError> {
        let mut ldap = self.connection.connect().await?;

        // Replace {username} placeholder in user filter
        let filter = self
            .config
            .user_filter
            .as_ref()
            .map(|f| f.replace("{username}", username))
            .unwrap_or_else(|| format!("(uid={})", username));

        debug!(
            "Searching for user DN with filter: {} in base: {}",
            filter, self.config.base_dn
        );

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &filter, vec!["dn"])
            .await
            .map_err(|e| {
                error!("LDAP search failed: {}", e);
                BackendError::ConnectionError(format!("Search failed: {}", e))
            })?;

        if rs.is_empty() {
            warn!("No user found with username: {}", username);
            return Err(BackendError::UserNotFound);
        }

        let entry = SearchEntry::construct(rs[0].clone());
        Ok(entry.dn)
    }

    /// Get user by username
    async fn get_user_by_username(&self, username: &str) -> Result<BackendUser, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let filter = self
            .config
            .user_filter
            .as_ref()
            .map(|f| f.replace("{username}", username))
            .unwrap_or_else(|| format!("(uid={})", username));

        let attributes = self
            .config
            .attributes
            .as_ref()
            .map(|attrs| attrs.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(|| vec!["uid", "mail", "cn", "displayName", "memberOf"]);

        debug!("Fetching user attributes for: {}", username);

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &filter, attributes)
            .await
            .map_err(|e| {
                error!("LDAP search failed: {}", e);
                BackendError::ConnectionError(format!("Search failed: {}", e))
            })?;

        if rs.is_empty() {
            return Err(BackendError::UserNotFound);
        }

        let entry = SearchEntry::construct(rs[0].clone());
        self.entry_to_backend_user(entry)
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<BackendUser, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let id_attr = self.config.id_attribute.as_deref().unwrap_or("uid");
        let filter = format!("({}={})", id_attr, user_id);

        let attributes = self
            .config
            .attributes
            .as_ref()
            .map(|attrs| attrs.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(|| vec!["uid", "mail", "cn", "displayName", "memberOf"]);

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &filter, attributes)
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Search failed: {}", e)))?;

        if rs.is_empty() {
            return Err(BackendError::UserNotFound);
        }

        let entry = SearchEntry::construct(rs[0].clone());
        self.entry_to_backend_user(entry)
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<BackendUser, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let email_attr = self.config.email_attribute.as_deref().unwrap_or("mail");
        let filter = format!("({}={})", email_attr, email);

        let attributes = self
            .config
            .attributes
            .as_ref()
            .map(|attrs| attrs.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(|| vec!["uid", "mail", "cn", "displayName", "memberOf"]);

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &filter, attributes)
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Search failed: {}", e)))?;

        if rs.is_empty() {
            return Err(BackendError::UserNotFound);
        }

        let entry = SearchEntry::construct(rs[0].clone());
        self.entry_to_backend_user(entry)
    }

    /// Convert LDAP entry to BackendUser
    fn entry_to_backend_user(&self, entry: SearchEntry) -> Result<BackendUser, BackendError> {
        let id_attr = self.config.id_attribute.as_deref().unwrap_or("uid");
        let email_attr = self.config.email_attribute.as_deref().unwrap_or("mail");
        let name_attr = self.config.name_attribute.as_deref().unwrap_or("cn");

        let id = entry
            .attrs
            .get(id_attr)
            .and_then(|v| v.first())
            .ok_or_else(|| {
                BackendError::ConfigurationError(format!("Missing {} attribute", id_attr))
            })?
            .clone();

        let email = entry
            .attrs
            .get(email_attr)
            .and_then(|v| v.first())
            .ok_or_else(|| {
                BackendError::ConfigurationError(format!("Missing {} attribute", email_attr))
            })?
            .clone();

        let name = entry.attrs.get(name_attr).and_then(|v| v.first()).cloned();

        // Extract all attributes
        let mut attributes = HashMap::new();
        for (key, values) in entry.attrs.iter() {
            if let Some(value) = values.first() {
                attributes.insert(key.clone(), value.clone());
            }
        }

        // Determine role based on group membership if configured
        let role = self.determine_role(&entry);

        Ok(BackendUser {
            id,
            email,
            name,
            picture: None,
            role,
            attributes,
        })
    }

    /// Determine user role based on LDAP group membership
    fn determine_role(&self, entry: &SearchEntry) -> UserRole {
        // Check if user is in admin group
        if let Some(admin_group) = &self.config.admin_group {
            if let Some(member_of) = entry.attrs.get("memberOf") {
                if member_of.iter().any(|dn| dn.contains(admin_group)) {
                    return UserRole::Admin;
                }
            }
        }

        UserRole::User
    }

    /// Get user's groups
    pub async fn get_user_groups(&self, user_dn: &str) -> Result<Vec<String>, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let filter = format!("(member={})", user_dn);
        let group_base = self
            .config
            .group_base_dn
            .as_ref()
            .unwrap_or(&self.config.base_dn);

        let (rs, _) = ldap
            .search(group_base, Scope::Subtree, &filter, vec!["cn", "dn"])
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Group search failed: {}", e)))?;

        let groups: Vec<String> = rs
            .into_iter()
            .map(|entry| SearchEntry::construct(entry).dn)
            .collect();

        Ok(groups)
    }

    /// Validate user exists
    pub async fn validate_user(&self, email: &str) -> Result<BackendUser, BackendError> {
        self.get_user_by_email(email).await
    }

    /// Health check - test LDAP connection
    pub async fn health_check(&self) -> Result<(), BackendError> {
        let mut ldap = self.connection.connect().await?;

        // Simple search to verify connection
        let (rs, _) = ldap
            .search(
                &self.config.base_dn,
                Scope::Base,
                "(objectClass=*)",
                vec!["1.1"],
            )
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Health check failed: {}", e)))?;

        if rs.is_empty() {
            Err(BackendError::ConnectionError(
                "Base DN not accessible".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_connection_creation() {
        let config = LdapBackendConfig {
            url: "ldap://localhost:389".to_string(),
            bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
            bind_password: Some("password".to_string()),
            base_dn: "dc=example,dc=com".to_string(),
            user_filter: Some("(uid={username})".to_string()),
            attributes: Some(vec!["uid".to_string(), "mail".to_string()]),
            id_attribute: Some("uid".to_string()),
            email_attribute: Some("mail".to_string()),
            name_attribute: Some("cn".to_string()),
            group_base_dn: None,
            admin_group: None,
            use_starttls: Some(false),
        };

        let backend = LdapBackendImpl::new(config);
        assert_eq!(backend.config.url, "ldap://localhost:389");
    }
}
