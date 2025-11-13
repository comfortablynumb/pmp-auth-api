// Session manager for high-level session operations

use super::storage::SessionStorage;
use super::types::{
    Session, SessionActivity, SessionConfig, SessionInfo, SessionQuery, SessionStatus,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Session manager for handling session lifecycle and operations
pub struct SessionManager {
    storage: Arc<dyn SessionStorage>,
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(storage: Arc<dyn SessionStorage>, config: SessionConfig) -> Self {
        Self { storage, config }
    }

    /// Create a new session for a user
    /// Enforces concurrent session limits
    pub async fn create_session(
        &self,
        user_id: &str,
        tenant_id: &str,
        ip_address: &str,
        user_agent: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<Session, String> {
        // Check concurrent session limit
        let active_sessions = self.get_active_session_count(user_id).await?;

        if active_sessions >= self.config.max_concurrent_sessions {
            warn!(
                "User {} has reached max concurrent sessions ({})",
                user_id, self.config.max_concurrent_sessions
            );

            // Optionally, terminate the oldest session to make room
            self.terminate_oldest_session(user_id).await?;
        }

        // Create new session
        let mut session = Session::new(
            user_id.to_string(),
            tenant_id.to_string(),
            ip_address.to_string(),
            user_agent.map(|s| s.to_string()),
            &self.config,
        );

        if let Some(cid) = client_id {
            session.client_id = Some(cid.to_string());
        }

        self.storage.create_session(session.clone()).await?;

        info!(
            "Created session {} for user {} in tenant {}",
            session.session_id, user_id, tenant_id
        );

        Ok(session)
    }

    /// Get a session by ID and validate it
    pub async fn get_session(&self, session_id: &str) -> Result<Option<Session>, String> {
        let session = self.storage.get_session(session_id).await?;

        if let Some(mut session) = session {
            // Check if session is still valid
            if !session.is_active(&self.config) {
                // Mark as expired if it's past the timeout
                if session.status == SessionStatus::Active {
                    session.expire();
                    self.storage.update_session(session.clone()).await?;
                }
                return Ok(None);
            }

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    /// Update session activity
    pub async fn update_activity(
        &self,
        session_id: &str,
        ip_address: &str,
        user_agent: Option<&str>,
        resource: Option<&str>,
        method: Option<&str>,
    ) -> Result<(), String> {
        if let Some(mut session) = self.storage.get_session(session_id).await? {
            // Update last activity timestamp
            let now = Utc::now();
            let time_since_last_update = (now - session.last_activity_at).num_seconds();

            // Only update if enough time has passed (to reduce write operations)
            if time_since_last_update >= self.config.activity_update_interval_secs {
                session.update_activity();
                self.storage.update_session(session).await?;
            }

            // Record activity if tracking is enabled
            if self.config.track_activity {
                let activity = SessionActivity {
                    session_id: session_id.to_string(),
                    timestamp: now,
                    activity_type: "request".to_string(),
                    ip_address: ip_address.to_string(),
                    user_agent: user_agent.map(|s| s.to_string()),
                    resource: resource.map(|s| s.to_string()),
                    method: method.map(|s| s.to_string()),
                    metadata: HashMap::new(),
                };

                self.storage.record_activity(activity).await?;
            }

            Ok(())
        } else {
            Err(format!("Session not found: {}", session_id))
        }
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(
        &self,
        user_id: &str,
        include_inactive: bool,
    ) -> Result<Vec<SessionInfo>, String> {
        let sessions = self.storage.get_user_sessions(user_id).await?;

        let session_infos: Vec<SessionInfo> = sessions
            .into_iter()
            .filter(|s| {
                if include_inactive {
                    true
                } else {
                    s.is_active(&self.config)
                }
            })
            .enumerate()
            .map(|(i, s)| s.to_info(i == 0)) // Mark first session as current
            .collect();

        Ok(session_infos)
    }

    /// Get active session count for a user
    async fn get_active_session_count(&self, user_id: &str) -> Result<usize, String> {
        let sessions = self.storage.get_user_sessions(user_id).await?;
        let count = sessions
            .iter()
            .filter(|s| s.is_active(&self.config))
            .count();
        Ok(count)
    }

    /// Terminate the oldest session for a user
    async fn terminate_oldest_session(&self, user_id: &str) -> Result<(), String> {
        let mut sessions = self.storage.get_user_sessions(user_id).await?;

        // Filter active sessions and sort by creation time (oldest first)
        sessions.retain(|s| s.is_active(&self.config));
        sessions.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        if let Some(oldest) = sessions.first() {
            info!(
                "Terminating oldest session {} for user {}",
                oldest.session_id, user_id
            );
            self.storage.terminate_session(&oldest.session_id).await?;
        }

        Ok(())
    }

    /// Terminate a specific session
    pub async fn terminate_session(&self, session_id: &str) -> Result<(), String> {
        self.storage.terminate_session(session_id).await?;
        info!("Session {} terminated", session_id);
        Ok(())
    }

    /// Terminate all sessions for a user (force logout from all devices)
    pub async fn terminate_all_user_sessions(&self, user_id: &str) -> Result<usize, String> {
        let count = self.storage.terminate_user_sessions(user_id).await?;
        info!("Terminated {} sessions for user {}", count, user_id);
        Ok(count)
    }

    /// Invalidate a session (admin force logout)
    pub async fn invalidate_session(&self, session_id: &str, reason: &str) -> Result<(), String> {
        self.storage.invalidate_session(session_id).await?;
        info!("Session {} invalidated: {}", session_id, reason);
        Ok(())
    }

    /// Get session activity history
    pub async fn get_session_activity(
        &self,
        session_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<SessionActivity>, String> {
        self.storage.get_activity_history(session_id, limit).await
    }

    /// Query sessions with filters
    pub async fn query_sessions(&self, query: SessionQuery) -> Result<Vec<SessionInfo>, String> {
        let sessions = self.storage.query_sessions(query).await?;

        let session_infos: Vec<SessionInfo> = sessions
            .into_iter()
            .enumerate()
            .map(|(i, s)| s.to_info(i == 0))
            .collect();

        Ok(session_infos)
    }

    /// Cleanup expired sessions (should be run periodically)
    pub async fn cleanup_expired_sessions(&self) -> Result<usize, String> {
        let count = self.storage.cleanup_expired_sessions().await?;
        if count > 0 {
            debug!("Cleaned up {} expired sessions", count);
        }
        Ok(count)
    }

    /// Validate session and check if it's still active
    pub async fn validate_session(&self, session_id: &str) -> Result<bool, String> {
        if let Some(session) = self.get_session(session_id).await? {
            Ok(session.is_active(&self.config))
        } else {
            Ok(false)
        }
    }

    /// Get session statistics for monitoring
    pub async fn get_session_stats(&self) -> Result<SessionStats, String> {
        let query = SessionQuery {
            status: Some(SessionStatus::Active),
            ..Default::default()
        };

        let active_sessions = self.storage.query_sessions(query).await?;

        let mut stats = SessionStats {
            total_active: active_sessions.len(),
            by_tenant: HashMap::new(),
            by_device: HashMap::new(),
        };

        for session in active_sessions {
            // Count by tenant
            *stats
                .by_tenant
                .entry(session.tenant_id.clone())
                .or_insert(0) += 1;

            // Count by device type
            if let Some(device) = &session.device_info {
                *stats
                    .by_device
                    .entry(device.device_type.clone())
                    .or_insert(0) += 1;
            }
        }

        Ok(stats)
    }
}

/// Session manager state for use in Axum handlers
#[derive(Clone)]
pub struct SessionManagerState {
    pub manager: Arc<SessionManager>,
}

impl SessionManagerState {
    pub fn new(storage: Arc<dyn SessionStorage>, config: SessionConfig) -> Self {
        Self {
            manager: Arc::new(SessionManager::new(storage, config)),
        }
    }
}

/// Session statistics for monitoring
#[derive(Debug, serde::Serialize)]
pub struct SessionStats {
    pub total_active: usize,
    pub by_tenant: HashMap<String, usize>,
    pub by_device: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::storage::MemorySessionStorage;

    #[tokio::test]
    async fn test_create_session() {
        let storage = Arc::new(MemorySessionStorage::new());
        let config = SessionConfig::default();
        let manager = SessionManager::new(storage, config);

        let session = manager
            .create_session(
                "user-123",
                "tenant-456",
                "192.168.1.1",
                Some("Mozilla/5.0"),
                Some("client-789"),
            )
            .await
            .unwrap();

        assert_eq!(session.user_id, "user-123");
        assert_eq!(session.client_id, Some("client-789".to_string()));
    }

    #[tokio::test]
    async fn test_concurrent_session_limit() {
        let storage = Arc::new(MemorySessionStorage::new());
        let mut config = SessionConfig::default();
        config.max_concurrent_sessions = 2;

        let manager = SessionManager::new(storage, config);

        // Create 2 sessions (at the limit)
        for i in 0..2 {
            manager
                .create_session(
                    "user-123",
                    "tenant-456",
                    &format!("192.168.1.{}", i),
                    None,
                    None,
                )
                .await
                .unwrap();
        }

        // Creating a 3rd session should terminate the oldest
        manager
            .create_session("user-123", "tenant-456", "192.168.1.3", None, None)
            .await
            .unwrap();

        let sessions = manager.get_user_sessions("user-123", false).await.unwrap();
        assert_eq!(sessions.len(), 2); // Should still have only 2 active sessions
    }

    #[tokio::test]
    async fn test_session_validation() {
        let storage = Arc::new(MemorySessionStorage::new());
        let config = SessionConfig::default();
        let manager = SessionManager::new(storage, config);

        let session = manager
            .create_session("user-123", "tenant-456", "192.168.1.1", None, None)
            .await
            .unwrap();

        // Session should be valid
        assert!(manager.validate_session(&session.session_id).await.unwrap());

        // Terminate the session
        manager
            .terminate_session(&session.session_id)
            .await
            .unwrap();

        // Session should no longer be valid
        assert!(!manager.validate_session(&session.session_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_terminate_all_user_sessions() {
        let storage = Arc::new(MemorySessionStorage::new());
        let config = SessionConfig::default();
        let manager = SessionManager::new(storage, config);

        // Create multiple sessions
        for i in 0..5 {
            manager
                .create_session(
                    "user-123",
                    "tenant-456",
                    &format!("192.168.1.{}", i),
                    None,
                    None,
                )
                .await
                .unwrap();
        }

        let count = manager
            .terminate_all_user_sessions("user-123")
            .await
            .unwrap();
        assert_eq!(count, 5);

        let active_sessions = manager.get_user_sessions("user-123", false).await.unwrap();
        assert_eq!(active_sessions.len(), 0);
    }

    #[tokio::test]
    async fn test_session_activity_tracking() {
        let storage = Arc::new(MemorySessionStorage::new());
        let config = SessionConfig::default();
        let manager = SessionManager::new(storage, config);

        let session = manager
            .create_session("user-123", "tenant-456", "192.168.1.1", None, None)
            .await
            .unwrap();

        // Record some activity
        for _ in 0..3 {
            manager
                .update_activity(
                    &session.session_id,
                    "192.168.1.1",
                    Some("Mozilla/5.0"),
                    Some("/api/test"),
                    Some("GET"),
                )
                .await
                .unwrap();
        }

        let activity = manager
            .get_session_activity(&session.session_id, Some(10))
            .await
            .unwrap();

        assert_eq!(activity.len(), 3);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let storage = Arc::new(MemorySessionStorage::new());
        let config = SessionConfig::default();
        let manager = SessionManager::new(storage, config);

        // Create sessions for different tenants
        manager
            .create_session("user-1", "tenant-1", "192.168.1.1", None, None)
            .await
            .unwrap();
        manager
            .create_session("user-2", "tenant-1", "192.168.1.2", None, None)
            .await
            .unwrap();
        manager
            .create_session("user-3", "tenant-2", "192.168.1.3", None, None)
            .await
            .unwrap();

        let stats = manager.get_session_stats().await.unwrap();
        assert_eq!(stats.total_active, 3);
        assert_eq!(stats.by_tenant.get("tenant-1"), Some(&2));
        assert_eq!(stats.by_tenant.get("tenant-2"), Some(&1));
    }
}
