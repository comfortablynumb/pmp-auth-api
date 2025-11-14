// Audit log storage backends

use super::types::{AuditEntry, AuditQuery, ComplianceReport};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error};

/// Trait for audit log storage backends
#[async_trait]
pub trait AuditStorage: Send + Sync {
    /// Store an audit entry
    async fn store(&self, entry: AuditEntry) -> Result<(), String>;

    /// Query audit entries
    async fn query(&self, query: AuditQuery) -> Result<Vec<AuditEntry>, String>;

    /// Generate a compliance report
    async fn generate_report(
        &self,
        tenant_id: Option<String>,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<ComplianceReport, String>;

    /// Delete audit entries older than the specified timestamp
    /// Used for data retention policies
    async fn cleanup_old_entries(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, String>;
}

/// In-memory audit storage implementation
/// Suitable for development and testing
pub struct MemoryAuditStorage {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
}

impl MemoryAuditStorage {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for MemoryAuditStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditStorage for MemoryAuditStorage {
    async fn store(&self, entry: AuditEntry) -> Result<(), String> {
        let mut entries = self.entries.write().await;
        debug!("Storing audit entry: {:?}", entry.action);
        entries.push(entry);
        Ok(())
    }

    async fn query(&self, query: AuditQuery) -> Result<Vec<AuditEntry>, String> {
        let entries = self.entries.read().await;

        let mut results: Vec<AuditEntry> = entries
            .iter()
            .filter(|entry| {
                // Filter by tenant_id
                if let Some(ref tenant_id) = query.tenant_id
                    && entry.tenant_id.as_ref() != Some(tenant_id)
                {
                    return false;
                }

                // Filter by user_id
                if let Some(ref user_id) = query.user_id
                    && entry.user_id.as_ref() != Some(user_id)
                {
                    return false;
                }

                // Filter by client_id
                if let Some(ref client_id) = query.client_id
                    && entry.client_id.as_ref() != Some(client_id)
                {
                    return false;
                }

                // Filter by action
                if let Some(ref action) = query.action
                    && &entry.action != action
                {
                    return false;
                }

                // Filter by resource_type
                if let Some(ref resource_type) = query.resource_type
                    && &entry.resource_type != resource_type
                {
                    return false;
                }

                // Filter by success
                if let Some(success) = query.success
                    && entry.success != success
                {
                    return false;
                }

                // Filter by minimum level
                if let Some(ref min_level) = query.min_level
                    && entry.level < *min_level
                {
                    return false;
                }

                // Filter by time range
                if let Some(start_time) = query.start_time
                    && entry.timestamp < start_time
                {
                    return false;
                }
                if let Some(end_time) = query.end_time
                    && entry.timestamp > end_time
                {
                    return false;
                }

                // Filter by IP address
                if let Some(ref ip_address) = query.ip_address
                    && &entry.ip_address != ip_address
                {
                    return false;
                }

                true
            })
            .cloned()
            .collect();

        // Sort by timestamp (most recent first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);

        let results = results.into_iter().skip(offset).take(limit).collect();

        Ok(results)
    }

    async fn generate_report(
        &self,
        tenant_id: Option<String>,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<ComplianceReport, String> {
        let entries = self.entries.read().await;

        // Filter entries by tenant and time range
        let filtered: Vec<&AuditEntry> = entries
            .iter()
            .filter(|e| {
                if let Some(ref tid) = tenant_id
                    && e.tenant_id.as_ref() != Some(tid)
                {
                    return false;
                }
                e.timestamp >= start && e.timestamp <= end
            })
            .collect();

        let total_events = filtered.len();

        let successful_authentications = filtered
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    super::types::AuditAction::Login | super::types::AuditAction::TokenGenerated
                ) && e.success
            })
            .count();

        let failed_authentications = filtered
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    super::types::AuditAction::LoginFailed | super::types::AuditAction::MfaFailed
                )
            })
            .count();

        let security_events = filtered
            .iter()
            .filter(|e| e.level >= super::types::AuditLevel::Security)
            .count();

        let admin_actions = filtered
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    super::types::AuditAction::TenantCreated
                        | super::types::AuditAction::TenantUpdated
                        | super::types::AuditAction::TenantDeleted
                        | super::types::AuditAction::ClientCreated
                        | super::types::AuditAction::ClientUpdated
                        | super::types::AuditAction::ClientDeleted
                        | super::types::AuditAction::UserCreated
                        | super::types::AuditAction::UserUpdated
                        | super::types::AuditAction::UserDeleted
                )
            })
            .count();

        let data_access_events = filtered
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    super::types::AuditAction::UserViewed
                        | super::types::AuditAction::ClientViewed
                        | super::types::AuditAction::TenantViewed
                )
            })
            .count();

        let data_modification_events = filtered
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    super::types::AuditAction::UserUpdated
                        | super::types::AuditAction::ClientUpdated
                        | super::types::AuditAction::TenantUpdated
                        | super::types::AuditAction::UserDeleted
                        | super::types::AuditAction::ClientDeleted
                        | super::types::AuditAction::TenantDeleted
                )
            })
            .count();

        let mut unique_users = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();
        let mut events_by_action: HashMap<String, usize> = HashMap::new();
        let mut failed_logins_by_user: HashMap<String, usize> = HashMap::new();
        let mut ip_counts: HashMap<String, usize> = HashMap::new();

        for entry in filtered.iter() {
            if let Some(ref user_id) = entry.user_id {
                unique_users.insert(user_id.clone());

                if matches!(entry.action, super::types::AuditAction::LoginFailed) {
                    *failed_logins_by_user.entry(user_id.clone()).or_insert(0) += 1;
                }
            }

            unique_ips.insert(entry.ip_address.clone());
            *ip_counts.entry(entry.ip_address.clone()).or_insert(0) += 1;

            let action_name = format!("{:?}", entry.action);
            *events_by_action.entry(action_name).or_insert(0) += 1;
        }

        // Get top 10 IPs by event count
        let mut top_ips: Vec<(String, usize)> = ip_counts.into_iter().collect();
        top_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_ips.truncate(10);

        Ok(ComplianceReport {
            generated_at: Utc::now(),
            period_start: start,
            period_end: end,
            tenant_id,
            total_events,
            successful_authentications,
            failed_authentications,
            security_events,
            admin_actions,
            data_access_events,
            data_modification_events,
            unique_users: unique_users.len(),
            unique_ips: unique_ips.len(),
            events_by_action,
            failed_logins_by_user,
            top_ips,
        })
    }

    async fn cleanup_old_entries(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, String> {
        let mut entries = self.entries.write().await;
        let original_count = entries.len();

        entries.retain(|entry| entry.timestamp >= before);

        let removed = original_count - entries.len();
        debug!("Cleaned up {} old audit entries", removed);

        Ok(removed)
    }
}

/// PostgreSQL audit storage implementation
/// For production use with persistent storage
pub struct PostgresAuditStorage {
    // TODO: Add PostgreSQL connection pool
    #[allow(dead_code)]
    connection_string: String,
}

impl PostgresAuditStorage {
    pub fn new(connection_string: String) -> Self {
        Self { connection_string }
    }
}

#[async_trait]
impl AuditStorage for PostgresAuditStorage {
    async fn store(&self, _entry: AuditEntry) -> Result<(), String> {
        // TODO: Implement PostgreSQL storage
        error!("PostgreSQL audit storage not yet implemented");
        Err("Not implemented".to_string())
    }

    async fn query(&self, _query: AuditQuery) -> Result<Vec<AuditEntry>, String> {
        // TODO: Implement PostgreSQL query
        error!("PostgreSQL audit query not yet implemented");
        Err("Not implemented".to_string())
    }

    async fn generate_report(
        &self,
        _tenant_id: Option<String>,
        _start: chrono::DateTime<chrono::Utc>,
        _end: chrono::DateTime<chrono::Utc>,
    ) -> Result<ComplianceReport, String> {
        // TODO: Implement PostgreSQL report generation
        error!("PostgreSQL report generation not yet implemented");
        Err("Not implemented".to_string())
    }

    async fn cleanup_old_entries(
        &self,
        _before: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, String> {
        // TODO: Implement PostgreSQL cleanup
        error!("PostgreSQL cleanup not yet implemented");
        Err("Not implemented".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{AuditAction, AuditLevel, ResourceType};

    #[tokio::test]
    async fn test_memory_storage_store_and_query() {
        let storage = MemoryAuditStorage::new();

        let entry = AuditEntry::builder()
            .tenant_id("test-tenant")
            .user_id("test-user")
            .ip_address("127.0.0.1")
            .action(AuditAction::Login)
            .resource_type(ResourceType::User)
            .level(AuditLevel::Info)
            .success(true)
            .build();

        storage.store(entry).await.unwrap();

        let query = AuditQuery {
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
        assert_eq!(results[0].user_id, Some("test-user".to_string()));
    }

    #[tokio::test]
    async fn test_memory_storage_generate_report() {
        let storage = MemoryAuditStorage::new();

        // Store some test entries
        for i in 0..5 {
            let entry = AuditEntry::builder()
                .tenant_id("test-tenant")
                .user_id(format!("user-{}", i))
                .ip_address("127.0.0.1")
                .action(AuditAction::Login)
                .resource_type(ResourceType::User)
                .level(AuditLevel::Info)
                .success(true)
                .build();

            storage.store(entry).await.unwrap();
        }

        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now() + chrono::Duration::hours(1);

        let report = storage
            .generate_report(Some("test-tenant".to_string()), start, end)
            .await
            .unwrap();

        assert_eq!(report.total_events, 5);
        assert_eq!(report.successful_authentications, 5);
        assert_eq!(report.unique_users, 5);
    }
}
