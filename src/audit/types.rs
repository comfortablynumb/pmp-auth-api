// Audit log types and structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Audit log entry representing a single auditable event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for the audit entry
    pub id: String,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Tenant ID associated with the event
    pub tenant_id: Option<String>,
    /// User ID who performed the action
    pub user_id: Option<String>,
    /// Client ID if the action was performed by a client
    pub client_id: Option<String>,
    /// IP address of the requester
    pub ip_address: String,
    /// User agent string from the request
    pub user_agent: Option<String>,
    /// Action that was performed
    pub action: AuditAction,
    /// Resource type that was affected
    pub resource_type: ResourceType,
    /// Resource ID that was affected
    pub resource_id: Option<String>,
    /// Severity level of the audit event
    pub level: AuditLevel,
    /// Whether the action was successful
    pub success: bool,
    /// Error message if the action failed
    pub error_message: Option<String>,
    /// Additional metadata about the event
    pub metadata: HashMap<String, String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
}

/// Types of auditable actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication actions
    Login,
    Logout,
    LoginFailed,
    TokenGenerated,
    TokenRefreshed,
    TokenRevoked,
    PasswordChanged,
    PasswordResetRequested,
    PasswordResetCompleted,
    MfaEnabled,
    MfaDisabled,
    MfaVerified,
    MfaFailed,

    // Authorization actions
    AuthorizationGranted,
    AuthorizationDenied,
    ScopeRequested,

    // Device flow actions
    DeviceCodeGenerated,
    DeviceCodeAuthorized,
    DeviceCodeRejected,

    // Admin actions - Tenants
    TenantCreated,
    TenantUpdated,
    TenantDeleted,
    TenantViewed,
    TenantListed,

    // Admin actions - Clients
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    ClientViewed,
    ClientListed,
    ClientSecretRotated,

    // Admin actions - Users
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserViewed,
    UserListed,
    UserActivated,
    UserDeactivated,

    // Security events
    RateLimitExceeded,
    BruteForceDetected,
    AccountLocked,
    AccountUnlocked,
    SuspiciousActivity,

    // Compliance events
    DataExported,
    DataDeleted,
    ConsentGranted,
    ConsentRevoked,

    // System events
    ConfigurationChanged,
    ApiKeyCreated,
    ApiKeyRevoked,
}

/// Resource types that can be audited
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    User,
    Client,
    Tenant,
    Token,
    Session,
    Device,
    ApiKey,
    Configuration,
    Data,
}

/// Severity level of audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    /// Informational events (normal operations)
    Info,
    /// Warning events (unusual but not critical)
    Warning,
    /// Security-relevant events
    Security,
    /// Critical security events
    Critical,
}

/// Query parameters for searching audit logs
#[derive(Debug, Clone, Deserialize)]
pub struct AuditQuery {
    /// Filter by tenant ID
    pub tenant_id: Option<String>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by action type
    pub action: Option<AuditAction>,
    /// Filter by resource type
    pub resource_type: Option<ResourceType>,
    /// Filter by success status
    pub success: Option<bool>,
    /// Filter by minimum severity level
    pub min_level: Option<AuditLevel>,
    /// Filter by start timestamp
    pub start_time: Option<DateTime<Utc>>,
    /// Filter by end timestamp
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by IP address
    pub ip_address: Option<String>,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Compliance report for GDPR, SOC2, etc.
#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Start of the reporting period
    pub period_start: DateTime<Utc>,
    /// End of the reporting period
    pub period_end: DateTime<Utc>,
    /// Tenant ID (if tenant-specific report)
    pub tenant_id: Option<String>,
    /// Total number of audit events
    pub total_events: usize,
    /// Number of successful authentications
    pub successful_authentications: usize,
    /// Number of failed authentications
    pub failed_authentications: usize,
    /// Number of security events
    pub security_events: usize,
    /// Number of admin actions
    pub admin_actions: usize,
    /// Number of data access events
    pub data_access_events: usize,
    /// Number of data modification events
    pub data_modification_events: usize,
    /// Unique users who accessed the system
    pub unique_users: usize,
    /// Unique IP addresses
    pub unique_ips: usize,
    /// Events by action type
    pub events_by_action: HashMap<String, usize>,
    /// Failed login attempts by user
    pub failed_logins_by_user: HashMap<String, usize>,
    /// Top IP addresses by event count
    pub top_ips: Vec<(String, usize)>,
}

impl AuditEntry {
    /// Create a new audit entry builder
    pub fn builder() -> AuditEntryBuilder {
        AuditEntryBuilder::default()
    }
}

/// Builder for creating audit entries
#[derive(Default)]
pub struct AuditEntryBuilder {
    tenant_id: Option<String>,
    user_id: Option<String>,
    client_id: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    action: Option<AuditAction>,
    resource_type: Option<ResourceType>,
    resource_id: Option<String>,
    level: Option<AuditLevel>,
    success: Option<bool>,
    error_message: Option<String>,
    metadata: HashMap<String, String>,
    session_id: Option<String>,
    request_id: Option<String>,
}

impl AuditEntryBuilder {
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn resource_type(mut self, resource_type: ResourceType) -> Self {
        self.resource_type = Some(resource_type);
        self
    }

    pub fn resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    pub fn level(mut self, level: AuditLevel) -> Self {
        self.level = Some(level);
        self
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }

    pub fn error(mut self, error: impl Into<String>) -> Self {
        self.error_message = Some(error.into());
        self.success = Some(false);
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn build(self) -> AuditEntry {
        AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            client_id: self.client_id,
            ip_address: self.ip_address.unwrap_or_else(|| "unknown".to_string()),
            user_agent: self.user_agent,
            action: self.action.unwrap_or(AuditAction::SuspiciousActivity),
            resource_type: self.resource_type.unwrap_or(ResourceType::Data),
            resource_id: self.resource_id,
            level: self.level.unwrap_or(AuditLevel::Info),
            success: self.success.unwrap_or(true),
            error_message: self.error_message,
            metadata: self.metadata,
            session_id: self.session_id,
            request_id: self.request_id,
        }
    }
}
