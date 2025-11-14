// Session storage backends

use super::types::{Session, SessionActivity, SessionQuery, SessionStatus};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Trait for session storage backends
#[async_trait]
pub trait SessionStorage: Send + Sync {
    /// Store a new session
    async fn create_session(&self, session: Session) -> Result<(), String>;

    /// Get a session by ID
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, String>;

    /// Update an existing session
    async fn update_session(&self, session: Session) -> Result<(), String>;

    /// Delete a session
    async fn delete_session(&self, session_id: &str) -> Result<(), String>;

    /// Get all sessions for a user
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, String>;

    /// Query sessions with filters
    async fn query_sessions(&self, query: SessionQuery) -> Result<Vec<Session>, String>;

    /// Record session activity
    async fn record_activity(&self, activity: SessionActivity) -> Result<(), String>;

    /// Get session activity history
    async fn get_activity_history(
        &self,
        session_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<SessionActivity>, String>;

    /// Cleanup expired sessions
    async fn cleanup_expired_sessions(&self) -> Result<usize, String>;

    /// Get session count for a user
    async fn get_user_session_count(&self, user_id: &str) -> Result<usize, String>;

    /// Terminate all sessions for a user
    async fn terminate_user_sessions(&self, user_id: &str) -> Result<usize, String>;

    /// Terminate a specific session
    async fn terminate_session(&self, session_id: &str) -> Result<(), String>;

    /// Invalidate a session (force logout)
    async fn invalidate_session(&self, session_id: &str) -> Result<(), String>;
}

/// In-memory session storage implementation
pub struct MemorySessionStorage {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    activities: Arc<RwLock<HashMap<String, Vec<SessionActivity>>>>,
}

impl MemorySessionStorage {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            activities: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemorySessionStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStorage for MemorySessionStorage {
    async fn create_session(&self, session: Session) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        info!(
            "Creating session {} for user {} in tenant {}",
            session.session_id, session.user_id, session.tenant_id
        );
        sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, String> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn update_session(&self, session: Session) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, String> {
        let sessions = self.sessions.read().await;
        let user_sessions: Vec<Session> = sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect();
        Ok(user_sessions)
    }

    async fn query_sessions(&self, query: SessionQuery) -> Result<Vec<Session>, String> {
        let sessions = self.sessions.read().await;

        let mut results: Vec<Session> = sessions
            .values()
            .filter(|session| {
                // Filter by user_id
                if let Some(ref user_id) = query.user_id
                    && &session.user_id != user_id
                {
                    return false;
                }

                // Filter by tenant_id
                if let Some(ref tenant_id) = query.tenant_id
                    && &session.tenant_id != tenant_id
                {
                    return false;
                }

                // Filter by client_id
                if let Some(ref client_id) = query.client_id
                    && session.client_id.as_ref() != Some(client_id)
                {
                    return false;
                }

                // Filter by status
                if let Some(ref status) = query.status
                    && &session.status != status
                {
                    return false;
                }

                // Filter by IP address
                if let Some(ref ip_address) = query.ip_address
                    && &session.ip_address != ip_address
                {
                    return false;
                }

                // Filter expired sessions
                if !query.include_expired && session.status == SessionStatus::Expired {
                    return false;
                }

                // Filter terminated sessions
                if !query.include_terminated && session.status == SessionStatus::Terminated {
                    return false;
                }

                true
            })
            .cloned()
            .collect();

        // Sort by creation time (most recent first)
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply pagination
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);

        let results = results.into_iter().skip(offset).take(limit).collect();

        Ok(results)
    }

    async fn record_activity(&self, activity: SessionActivity) -> Result<(), String> {
        let mut activities = self.activities.write().await;
        activities
            .entry(activity.session_id.clone())
            .or_insert_with(Vec::new)
            .push(activity);
        Ok(())
    }

    async fn get_activity_history(
        &self,
        session_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<SessionActivity>, String> {
        let activities = self.activities.read().await;

        if let Some(session_activities) = activities.get(session_id) {
            let mut history = session_activities.clone();
            // Sort by timestamp (most recent first)
            history.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

            if let Some(limit) = limit {
                history.truncate(limit);
            }

            Ok(history)
        } else {
            Ok(Vec::new())
        }
    }

    async fn cleanup_expired_sessions(&self) -> Result<usize, String> {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();

        let expired_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now > session.expires_at)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_sessions.len();

        for session_id in expired_sessions {
            sessions.remove(&session_id);
        }

        if count > 0 {
            debug!("Cleaned up {} expired sessions", count);
        }

        Ok(count)
    }

    async fn get_user_session_count(&self, user_id: &str) -> Result<usize, String> {
        let sessions = self.sessions.read().await;
        let count = sessions
            .values()
            .filter(|s| s.user_id == user_id && s.status == SessionStatus::Active)
            .count();
        Ok(count)
    }

    async fn terminate_user_sessions(&self, user_id: &str) -> Result<usize, String> {
        let mut sessions = self.sessions.write().await;
        let mut count = 0;

        for session in sessions.values_mut() {
            if session.user_id == user_id && session.status == SessionStatus::Active {
                session.status = SessionStatus::Terminated;
                count += 1;
            }
        }

        info!("Terminated {} sessions for user {}", count, user_id);
        Ok(count)
    }

    async fn terminate_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.status = SessionStatus::Terminated;
            info!("Terminated session {}", session_id);
            Ok(())
        } else {
            Err(format!("Session not found: {}", session_id))
        }
    }

    async fn invalidate_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.status = SessionStatus::Invalidated;
            info!("Invalidated session {}", session_id);
            Ok(())
        } else {
            Err(format!("Session not found: {}", session_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::types::SessionConfig;

    #[tokio::test]
    async fn test_create_and_get_session() {
        let storage = MemorySessionStorage::new();
        let config = SessionConfig::default();

        let session = Session::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            "192.168.1.1".to_string(),
            None,
            &config,
        );

        let session_id = session.session_id.clone();

        storage.create_session(session).await.unwrap();

        let retrieved = storage.get_session(&session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user-123");
    }

    #[tokio::test]
    async fn test_get_user_sessions() {
        let storage = MemorySessionStorage::new();
        let config = SessionConfig::default();

        // Create multiple sessions for the same user
        for i in 0..3 {
            let session = Session::new(
                "user-123".to_string(),
                "tenant-456".to_string(),
                format!("192.168.1.{}", i),
                None,
                &config,
            );
            storage.create_session(session).await.unwrap();
        }

        let sessions = storage.get_user_sessions("user-123").await.unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[tokio::test]
    async fn test_terminate_session() {
        let storage = MemorySessionStorage::new();
        let config = SessionConfig::default();

        let session = Session::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            "192.168.1.1".to_string(),
            None,
            &config,
        );

        let session_id = session.session_id.clone();
        storage.create_session(session).await.unwrap();

        storage.terminate_session(&session_id).await.unwrap();

        let terminated = storage.get_session(&session_id).await.unwrap().unwrap();
        assert_eq!(terminated.status, SessionStatus::Terminated);
    }

    #[tokio::test]
    async fn test_session_activity_tracking() {
        let storage = MemorySessionStorage::new();

        let activity = SessionActivity {
            session_id: "session-123".to_string(),
            timestamp: Utc::now(),
            activity_type: "api_call".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: None,
            resource: Some("/api/users".to_string()),
            method: Some("GET".to_string()),
            metadata: HashMap::new(),
        };

        storage.record_activity(activity).await.unwrap();

        let history = storage
            .get_activity_history("session-123", Some(10))
            .await
            .unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].activity_type, "api_call");
    }

    #[tokio::test]
    async fn test_terminate_user_sessions() {
        let storage = MemorySessionStorage::new();
        let config = SessionConfig::default();

        // Create multiple sessions for the user
        for i in 0..5 {
            let session = Session::new(
                "user-123".to_string(),
                "tenant-456".to_string(),
                format!("192.168.1.{}", i),
                None,
                &config,
            );
            storage.create_session(session).await.unwrap();
        }

        let count = storage.terminate_user_sessions("user-123").await.unwrap();
        assert_eq!(count, 5);

        let sessions = storage.get_user_sessions("user-123").await.unwrap();
        for session in sessions {
            assert_eq!(session.status, SessionStatus::Terminated);
        }
    }
}
