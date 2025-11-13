// Audit logger implementation

use super::storage::AuditStorage;
use super::types::{AuditAction, AuditEntry, AuditLevel, ResourceType};
use axum::extract::Request;
use std::sync::Arc;
use tracing::{error, info};

/// Audit logger for recording security and compliance events
#[derive(Clone)]
pub struct AuditLogger {
    storage: Arc<dyn AuditStorage>,
}

impl AuditLogger {
    /// Create a new audit logger with the specified storage backend
    pub fn new(storage: Arc<dyn AuditStorage>) -> Self {
        Self { storage }
    }

    /// Log an audit event
    pub async fn log(&self, entry: AuditEntry) {
        info!(
            "Audit: {} - {:?} by {:?} - success: {}",
            entry.action.as_str(),
            entry.resource_type,
            entry.user_id,
            entry.success
        );

        if let Err(e) = self.storage.store(entry).await {
            error!("Failed to store audit entry: {}", e);
        }
    }

    /// Log a successful authentication event
    pub async fn log_login(
        &self,
        tenant_id: &str,
        user_id: &str,
        ip_address: &str,
        user_agent: Option<&str>,
    ) {
        let entry = AuditEntry::builder()
            .tenant_id(tenant_id)
            .user_id(user_id)
            .ip_address(ip_address)
            .user_agent(user_agent.unwrap_or("unknown"))
            .action(AuditAction::Login)
            .resource_type(ResourceType::User)
            .level(AuditLevel::Info)
            .success(true)
            .build();

        self.log(entry).await;
    }

    /// Log a failed authentication event
    pub async fn log_login_failed(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        ip_address: &str,
        user_agent: Option<&str>,
        reason: &str,
    ) {
        let mut builder = AuditEntry::builder()
            .tenant_id(tenant_id)
            .ip_address(ip_address)
            .user_agent(user_agent.unwrap_or("unknown"))
            .action(AuditAction::LoginFailed)
            .resource_type(ResourceType::User)
            .level(AuditLevel::Security)
            .error(reason);

        if let Some(uid) = user_id {
            builder = builder.user_id(uid);
        }

        self.log(builder.build()).await;
    }

    /// Log token generation
    pub async fn log_token_generated(
        &self,
        tenant_id: &str,
        user_id: &str,
        client_id: &str,
        ip_address: &str,
        grant_type: &str,
    ) {
        let entry = AuditEntry::builder()
            .tenant_id(tenant_id)
            .user_id(user_id)
            .client_id(client_id)
            .ip_address(ip_address)
            .action(AuditAction::TokenGenerated)
            .resource_type(ResourceType::Token)
            .level(AuditLevel::Info)
            .success(true)
            .metadata("grant_type", grant_type)
            .build();

        self.log(entry).await;
    }

    /// Log admin action (tenant/client/user management)
    pub async fn log_admin_action(
        &self,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: &str,
        tenant_id: &str,
        admin_user_id: &str,
        ip_address: &str,
        success: bool,
        error: Option<&str>,
    ) {
        let mut builder = AuditEntry::builder()
            .tenant_id(tenant_id)
            .user_id(admin_user_id)
            .ip_address(ip_address)
            .action(action)
            .resource_type(resource_type)
            .resource_id(resource_id)
            .level(AuditLevel::Info)
            .success(success);

        if let Some(err) = error {
            builder = builder.error(err);
        }

        self.log(builder.build()).await;
    }

    /// Log security event (rate limit, brute force, etc.)
    pub async fn log_security_event(
        &self,
        action: AuditAction,
        tenant_id: Option<&str>,
        user_id: Option<&str>,
        ip_address: &str,
        description: &str,
    ) {
        let mut builder = AuditEntry::builder()
            .ip_address(ip_address)
            .action(action)
            .resource_type(ResourceType::User)
            .level(AuditLevel::Critical)
            .success(false)
            .metadata("description", description);

        if let Some(tid) = tenant_id {
            builder = builder.tenant_id(tid);
        }

        if let Some(uid) = user_id {
            builder = builder.user_id(uid);
        }

        self.log(builder.build()).await;
    }

    /// Log MFA event
    pub async fn log_mfa_event(
        &self,
        action: AuditAction,
        tenant_id: &str,
        user_id: &str,
        ip_address: &str,
        success: bool,
        method: &str,
    ) {
        let entry = AuditEntry::builder()
            .tenant_id(tenant_id)
            .user_id(user_id)
            .ip_address(ip_address)
            .action(action)
            .resource_type(ResourceType::User)
            .level(if success {
                AuditLevel::Info
            } else {
                AuditLevel::Security
            })
            .success(success)
            .metadata("mfa_method", method)
            .build();

        self.log(entry).await;
    }

    /// Log data export for GDPR compliance
    pub async fn log_data_export(
        &self,
        tenant_id: &str,
        user_id: &str,
        admin_user_id: &str,
        ip_address: &str,
    ) {
        let entry = AuditEntry::builder()
            .tenant_id(tenant_id)
            .user_id(admin_user_id)
            .ip_address(ip_address)
            .action(AuditAction::DataExported)
            .resource_type(ResourceType::Data)
            .resource_id(user_id)
            .level(AuditLevel::Security)
            .success(true)
            .build();

        self.log(entry).await;
    }

    /// Extract IP address from request
    pub fn extract_ip(req: &Request) -> String {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .or_else(|| req.headers().get("x-real-ip").and_then(|h| h.to_str().ok()))
            .unwrap_or("unknown")
            .to_string()
    }

    /// Extract user agent from request
    pub fn extract_user_agent(req: &Request) -> Option<String> {
        req.headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }
}

/// Audit logger state for use in Axum handlers
#[derive(Clone)]
pub struct AuditLoggerState {
    pub logger: Arc<AuditLogger>,
}

impl AuditLoggerState {
    pub fn new(storage: Arc<dyn AuditStorage>) -> Self {
        Self {
            logger: Arc::new(AuditLogger::new(storage)),
        }
    }
}

impl AuditAction {
    /// Get a string representation of the action
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
            AuditAction::LoginFailed => "login_failed",
            AuditAction::TokenGenerated => "token_generated",
            AuditAction::TokenRefreshed => "token_refreshed",
            AuditAction::TokenRevoked => "token_revoked",
            AuditAction::PasswordChanged => "password_changed",
            AuditAction::PasswordResetRequested => "password_reset_requested",
            AuditAction::PasswordResetCompleted => "password_reset_completed",
            AuditAction::MfaEnabled => "mfa_enabled",
            AuditAction::MfaDisabled => "mfa_disabled",
            AuditAction::MfaVerified => "mfa_verified",
            AuditAction::MfaFailed => "mfa_failed",
            AuditAction::AuthorizationGranted => "authorization_granted",
            AuditAction::AuthorizationDenied => "authorization_denied",
            AuditAction::ScopeRequested => "scope_requested",
            AuditAction::DeviceCodeGenerated => "device_code_generated",
            AuditAction::DeviceCodeAuthorized => "device_code_authorized",
            AuditAction::DeviceCodeRejected => "device_code_rejected",
            AuditAction::TenantCreated => "tenant_created",
            AuditAction::TenantUpdated => "tenant_updated",
            AuditAction::TenantDeleted => "tenant_deleted",
            AuditAction::TenantViewed => "tenant_viewed",
            AuditAction::TenantListed => "tenant_listed",
            AuditAction::ClientCreated => "client_created",
            AuditAction::ClientUpdated => "client_updated",
            AuditAction::ClientDeleted => "client_deleted",
            AuditAction::ClientViewed => "client_viewed",
            AuditAction::ClientListed => "client_listed",
            AuditAction::ClientSecretRotated => "client_secret_rotated",
            AuditAction::UserCreated => "user_created",
            AuditAction::UserUpdated => "user_updated",
            AuditAction::UserDeleted => "user_deleted",
            AuditAction::UserViewed => "user_viewed",
            AuditAction::UserListed => "user_listed",
            AuditAction::UserActivated => "user_activated",
            AuditAction::UserDeactivated => "user_deactivated",
            AuditAction::RateLimitExceeded => "rate_limit_exceeded",
            AuditAction::BruteForceDetected => "brute_force_detected",
            AuditAction::AccountLocked => "account_locked",
            AuditAction::AccountUnlocked => "account_unlocked",
            AuditAction::SuspiciousActivity => "suspicious_activity",
            AuditAction::DataExported => "data_exported",
            AuditAction::DataDeleted => "data_deleted",
            AuditAction::ConsentGranted => "consent_granted",
            AuditAction::ConsentRevoked => "consent_revoked",
            AuditAction::ConfigurationChanged => "configuration_changed",
            AuditAction::ApiKeyCreated => "api_key_created",
            AuditAction::ApiKeyRevoked => "api_key_revoked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::storage::MemoryAuditStorage;

    #[tokio::test]
    async fn test_audit_logger_login() {
        let storage = Arc::new(MemoryAuditStorage::new());
        let logger = AuditLogger::new(storage.clone());

        logger
            .log_login("test-tenant", "test-user", "127.0.0.1", Some("Mozilla/5.0"))
            .await;

        // Query the storage to verify the entry was logged
        let query = crate::audit::types::AuditQuery {
            tenant_id: Some("test-tenant".to_string()),
            user_id: None,
            client_id: None,
            action: None,
            resource_type: None,
            success: None,
            min_level: None,
            start_time: None,
            end_time: None,
            ip_address: None,
            limit: None,
            offset: None,
        };

        let results = storage.query(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, AuditAction::Login);
        assert_eq!(results[0].success, true);
    }

    #[tokio::test]
    async fn test_audit_logger_failed_login() {
        let storage = Arc::new(MemoryAuditStorage::new());
        let logger = AuditLogger::new(storage.clone());

        logger
            .log_login_failed(
                "test-tenant",
                Some("test-user"),
                "127.0.0.1",
                None,
                "Invalid password",
            )
            .await;

        let query = crate::audit::types::AuditQuery {
            tenant_id: Some("test-tenant".to_string()),
            user_id: None,
            client_id: None,
            action: Some(AuditAction::LoginFailed),
            resource_type: None,
            success: None,
            min_level: None,
            start_time: None,
            end_time: None,
            ip_address: None,
            limit: None,
            offset: None,
        };

        let results = storage.query(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].success, false);
        assert_eq!(
            results[0].error_message,
            Some("Invalid password".to_string())
        );
    }
}
