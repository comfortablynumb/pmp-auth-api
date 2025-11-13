// Session types and data structures

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: usize,
    /// Session timeout duration (idle timeout)
    pub session_timeout_secs: i64,
    /// Absolute session lifetime (regardless of activity)
    pub absolute_timeout_secs: i64,
    /// Whether to track session activity
    pub track_activity: bool,
    /// Minimum interval between activity updates (to reduce writes)
    pub activity_update_interval_secs: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 5,
            session_timeout_secs: 3600,         // 1 hour idle timeout
            absolute_timeout_secs: 86400,       // 24 hours absolute timeout
            track_activity: true,
            activity_update_interval_secs: 60,  // Update activity at most once per minute
        }
    }
}

/// Session status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session is active
    Active,
    /// Session expired due to inactivity
    Expired,
    /// Session was explicitly terminated
    Terminated,
    /// Session was forcefully invalidated (e.g., by admin)
    Invalidated,
}

/// Active user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub session_id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Client ID (OAuth2 client that initiated the session)
    pub client_id: Option<String>,
    /// Session status
    pub status: SessionStatus,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity_at: DateTime<Utc>,
    /// When the session expires (absolute timeout)
    pub expires_at: DateTime<Utc>,
    /// IP address from which the session was created
    pub ip_address: String,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device information (parsed from user agent)
    pub device_info: Option<DeviceInfo>,
    /// Geolocation information (if available)
    pub location: Option<Location>,
    /// Session metadata (custom key-value pairs)
    pub metadata: HashMap<String, String>,
    /// Access token associated with this session (optional)
    pub access_token: Option<String>,
    /// Refresh token associated with this session (optional)
    pub refresh_token: Option<String>,
}

/// Device information parsed from user agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device type (desktop, mobile, tablet, etc.)
    pub device_type: String,
    /// Operating system
    pub os: String,
    /// Browser name
    pub browser: String,
    /// Browser version
    pub browser_version: Option<String>,
}

/// Location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
}

/// Session activity event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionActivity {
    /// Session ID
    pub session_id: String,
    /// Timestamp of the activity
    pub timestamp: DateTime<Utc>,
    /// Type of activity (e.g., "api_call", "page_view", "token_refresh")
    pub activity_type: String,
    /// IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Endpoint or resource accessed
    pub resource: Option<String>,
    /// HTTP method
    pub method: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Session query parameters for searching/filtering sessions
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SessionQuery {
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by tenant ID
    pub tenant_id: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by status
    pub status: Option<SessionStatus>,
    /// Filter by IP address
    pub ip_address: Option<String>,
    /// Include expired sessions
    pub include_expired: bool,
    /// Include terminated sessions
    pub include_terminated: bool,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Session information for display (without sensitive tokens)
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub client_id: Option<String>,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub device_info: Option<DeviceInfo>,
    pub location: Option<Location>,
    pub is_current: bool,
}

impl Session {
    /// Create a new session
    pub fn new(
        user_id: String,
        tenant_id: String,
        ip_address: String,
        user_agent: Option<String>,
        config: &SessionConfig,
    ) -> Self {
        let now = Utc::now();
        let session_id = uuid::Uuid::new_v4().to_string();

        Self {
            session_id,
            user_id,
            tenant_id,
            client_id: None,
            status: SessionStatus::Active,
            created_at: now,
            last_activity_at: now,
            expires_at: now + Duration::seconds(config.absolute_timeout_secs),
            ip_address,
            user_agent: user_agent.clone(),
            device_info: user_agent.as_ref().map(|ua| parse_user_agent(ua)),
            location: None,
            metadata: HashMap::new(),
            access_token: None,
            refresh_token: None,
        }
    }

    /// Check if the session is active (not expired or terminated)
    pub fn is_active(&self, config: &SessionConfig) -> bool {
        if self.status != SessionStatus::Active {
            return false;
        }

        let now = Utc::now();

        // Check absolute timeout
        if now > self.expires_at {
            return false;
        }

        // Check idle timeout
        let idle_duration = now - self.last_activity_at;
        if idle_duration.num_seconds() > config.session_timeout_secs {
            return false;
        }

        true
    }

    /// Update the last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity_at = Utc::now();
    }

    /// Terminate the session
    pub fn terminate(&mut self) {
        self.status = SessionStatus::Terminated;
    }

    /// Invalidate the session (forced logout)
    pub fn invalidate(&mut self) {
        self.status = SessionStatus::Invalidated;
    }

    /// Mark as expired
    pub fn expire(&mut self) {
        self.status = SessionStatus::Expired;
    }

    /// Convert to SessionInfo (without sensitive tokens)
    pub fn to_info(&self, is_current: bool) -> SessionInfo {
        SessionInfo {
            session_id: self.session_id.clone(),
            user_id: self.user_id.clone(),
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
            last_activity_at: self.last_activity_at,
            expires_at: self.expires_at,
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            device_info: self.device_info.clone(),
            location: self.location.clone(),
            is_current,
        }
    }
}

/// Parse user agent string to extract device information
/// This is a simplified implementation - in production, use a proper UA parser library
fn parse_user_agent(user_agent: &str) -> DeviceInfo {
    let ua_lower = user_agent.to_lowercase();

    let device_type = if ua_lower.contains("mobile") {
        "mobile"
    } else if ua_lower.contains("tablet") || ua_lower.contains("ipad") {
        "tablet"
    } else {
        "desktop"
    }
    .to_string();

    // Check for mobile OS first since they may contain generic patterns
    let os = if ua_lower.contains("android") {
        "Android"
    } else if ua_lower.contains("ios") || ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        "iOS"
    } else if ua_lower.contains("windows") {
        "Windows"
    } else if ua_lower.contains("mac os") || ua_lower.contains("macos") {
        "macOS"
    } else if ua_lower.contains("linux") {
        "Linux"
    } else {
        "Unknown"
    }
    .to_string();

    let browser = if ua_lower.contains("chrome") && !ua_lower.contains("edg") {
        "Chrome"
    } else if ua_lower.contains("firefox") {
        "Firefox"
    } else if ua_lower.contains("safari") && !ua_lower.contains("chrome") {
        "Safari"
    } else if ua_lower.contains("edg") {
        "Edge"
    } else {
        "Unknown"
    }
    .to_string();

    DeviceInfo {
        device_type,
        os,
        browser,
        browser_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let config = SessionConfig::default();
        let session = Session::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            "192.168.1.1".to_string(),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0".to_string()),
            &config,
        );

        assert_eq!(session.user_id, "user-123");
        assert_eq!(session.tenant_id, "tenant-456");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(session.is_active(&config));
        assert!(session.device_info.is_some());
    }

    #[test]
    fn test_session_activity_update() {
        let config = SessionConfig::default();
        let mut session = Session::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            "192.168.1.1".to_string(),
            None,
            &config,
        );

        let original_activity = session.last_activity_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.update_activity();

        assert!(session.last_activity_at > original_activity);
    }

    #[test]
    fn test_session_termination() {
        let config = SessionConfig::default();
        let mut session = Session::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            "192.168.1.1".to_string(),
            None,
            &config,
        );

        assert!(session.is_active(&config));

        session.terminate();
        assert_eq!(session.status, SessionStatus::Terminated);
        assert!(!session.is_active(&config));
    }

    #[test]
    fn test_user_agent_parsing() {
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
        let device = parse_user_agent(chrome_ua);

        assert_eq!(device.device_type, "desktop");
        assert_eq!(device.os, "Windows");
        assert_eq!(device.browser, "Chrome");
    }

    #[test]
    fn test_mobile_user_agent_parsing() {
        let mobile_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1";
        let device = parse_user_agent(mobile_ua);

        assert_eq!(device.device_type, "mobile");
        assert_eq!(device.os, "iOS");
        assert_eq!(device.browser, "Safari");
    }
}
