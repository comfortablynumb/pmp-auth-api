#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{error, info, warn};

use super::groups::{GroupInfo, NestedGroupResolver};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSyncPolicy {
    /// Tenant ID this policy applies to
    pub tenant_id: String,
    /// Groups to synchronize (empty = all groups)
    pub group_filter: Option<String>,
    /// Sync interval in seconds
    pub sync_interval_secs: u64,
    /// Include nested groups
    pub include_nested: bool,
    /// Maximum recursion depth for nested groups
    pub max_depth: usize,
    /// Whether sync is enabled
    pub enabled: bool,
    /// Last successful sync time
    pub last_sync: Option<DateTime<Utc>>,
    /// Attribute mappings for group data
    pub attribute_mappings: HashMap<String, String>,
}

impl GroupSyncPolicy {
    pub fn new(tenant_id: String) -> Self {
        Self {
            tenant_id,
            group_filter: None,
            sync_interval_secs: 3600, // Default: sync every hour
            include_nested: true,
            max_depth: 10,
            enabled: true,
            last_sync: None,
            attribute_mappings: HashMap::new(),
        }
    }

    pub fn with_filter(mut self, filter: String) -> Self {
        self.group_filter = Some(filter);
        self
    }

    pub fn with_interval(mut self, seconds: u64) -> Self {
        self.sync_interval_secs = seconds;
        self
    }

    pub fn with_nested(mut self, include_nested: bool, max_depth: usize) -> Self {
        self.include_nested = include_nested;
        self.max_depth = max_depth;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub tenant_id: String,
    pub sync_time: DateTime<Utc>,
    pub groups_synced: usize,
    pub users_synced: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

/// Synchronized group data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedGroup {
    pub dn: String,
    pub cn: String,
    pub members: Vec<String>,
    pub nested_members: Vec<String>, // All members including nested
    pub attributes: HashMap<String, Vec<String>>,
    pub last_updated: DateTime<Utc>,
}

/// Group synchronization manager
pub struct GroupSyncManager {
    policies: Arc<RwLock<HashMap<String, GroupSyncPolicy>>>,
    synced_groups: Arc<RwLock<HashMap<String, Vec<SyncedGroup>>>>, // tenant_id -> groups
    resolvers: Arc<RwLock<HashMap<String, Arc<NestedGroupResolver>>>>, // tenant_id -> resolver
}

impl GroupSyncManager {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            synced_groups: Arc::new(RwLock::new(HashMap::new())),
            resolvers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a sync policy
    pub async fn add_policy(&self, policy: GroupSyncPolicy) {
        let mut policies = self.policies.write().await;
        policies.insert(policy.tenant_id.clone(), policy);
    }

    /// Remove a sync policy
    pub async fn remove_policy(&self, tenant_id: &str) {
        let mut policies = self.policies.write().await;
        policies.remove(tenant_id);
    }

    /// Register a group resolver for a tenant
    pub async fn register_resolver(&self, tenant_id: String, resolver: Arc<NestedGroupResolver>) {
        let mut resolvers = self.resolvers.write().await;
        resolvers.insert(tenant_id, resolver);
    }

    /// Get policy for a tenant
    pub async fn get_policy(&self, tenant_id: &str) -> Option<GroupSyncPolicy> {
        let policies = self.policies.read().await;
        policies.get(tenant_id).cloned()
    }

    /// Get synced groups for a tenant
    pub async fn get_synced_groups(&self, tenant_id: &str) -> Vec<SyncedGroup> {
        let groups = self.synced_groups.read().await;
        groups.get(tenant_id).cloned().unwrap_or_default()
    }

    /// Find synced group by DN
    pub async fn find_group(&self, tenant_id: &str, group_dn: &str) -> Option<SyncedGroup> {
        let groups = self.synced_groups.read().await;
        groups
            .get(tenant_id)?
            .iter()
            .find(|g| g.dn == group_dn)
            .cloned()
    }

    /// Check if user is member of a group (including nested)
    pub async fn is_user_in_group(&self, tenant_id: &str, user_dn: &str, group_dn: &str) -> bool {
        let groups = self.synced_groups.read().await;
        if let Some(tenant_groups) = groups.get(tenant_id) {
            if let Some(group) = tenant_groups.iter().find(|g| g.dn == group_dn) {
                return group.nested_members.contains(&user_dn.to_string());
            }
        }
        false
    }

    /// Manually trigger sync for a tenant
    pub async fn sync_now(&self, tenant_id: &str) -> Result<SyncResult, String> {
        let policy = {
            let policies = self.policies.read().await;
            policies
                .get(tenant_id)
                .cloned()
                .ok_or_else(|| format!("No sync policy for tenant: {}", tenant_id))?
        };

        let resolver = {
            let resolvers = self.resolvers.read().await;
            resolvers
                .get(tenant_id)
                .cloned()
                .ok_or_else(|| format!("No resolver registered for tenant: {}", tenant_id))?
        };

        self.perform_sync(tenant_id, &policy, &resolver).await
    }

    /// Perform actual synchronization
    async fn perform_sync(
        &self,
        tenant_id: &str,
        policy: &GroupSyncPolicy,
        resolver: &NestedGroupResolver,
    ) -> Result<SyncResult, String> {
        let start_time = Utc::now();
        info!("Starting group sync for tenant: {}", tenant_id);

        let mut errors = Vec::new();
        let mut synced_groups = Vec::new();
        let mut users_set = std::collections::HashSet::new();

        // Get all groups based on filter
        let groups = match &policy.group_filter {
            Some(filter) => resolver
                .resolver
                .search_groups(filter)
                .await
                .map_err(|e| format!("Failed to search groups: {}", e))?,
            None => resolver
                .resolver
                .list_all_groups()
                .await
                .map_err(|e| format!("Failed to list groups: {}", e))?,
        };

        info!("Found {} groups to sync", groups.len());

        // Process each group
        for group in groups {
            match self
                .sync_group(&group, policy.include_nested, resolver)
                .await
            {
                Ok(synced_group) => {
                    users_set.extend(synced_group.nested_members.iter().cloned());
                    synced_groups.push(synced_group);
                }
                Err(e) => {
                    error!("Failed to sync group {}: {}", group.cn, e);
                    errors.push(format!("Group {}: {}", group.cn, e));
                }
            }
        }

        // Store synced groups
        {
            let mut groups_store = self.synced_groups.write().await;
            groups_store.insert(tenant_id.to_string(), synced_groups.clone());
        }

        // Update last sync time
        {
            let mut policies = self.policies.write().await;
            if let Some(p) = policies.get_mut(tenant_id) {
                p.last_sync = Some(Utc::now());
            }
        }

        let duration_ms = (Utc::now() - start_time).num_milliseconds() as u64;

        let result = SyncResult {
            tenant_id: tenant_id.to_string(),
            sync_time: Utc::now(),
            groups_synced: synced_groups.len(),
            users_synced: users_set.len(),
            errors,
            duration_ms,
        };

        info!(
            "Completed group sync for tenant {}: {} groups, {} users, {} errors, {}ms",
            tenant_id,
            result.groups_synced,
            result.users_synced,
            result.errors.len(),
            duration_ms
        );

        Ok(result)
    }

    /// Sync a single group
    async fn sync_group(
        &self,
        group: &GroupInfo,
        include_nested: bool,
        resolver: &NestedGroupResolver,
    ) -> Result<SyncedGroup, String> {
        let nested_members = if include_nested {
            resolver
                .get_all_group_members(&group.dn)
                .await
                .map_err(|e| format!("Failed to get nested members: {}", e))?
        } else {
            group.members.clone()
        };

        Ok(SyncedGroup {
            dn: group.dn.clone(),
            cn: group.cn.clone(),
            members: group.members.clone(),
            nested_members,
            attributes: group.attributes.clone(),
            last_updated: Utc::now(),
        })
    }

    /// Start background sync scheduler
    pub async fn start_scheduler(self: Arc<Self>) {
        info!("Starting group sync scheduler");

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(60)); // Check every minute

            loop {
                interval.tick().await;

                let policies = {
                    let p = self.policies.read().await;
                    p.clone()
                };

                for (tenant_id, policy) in policies.iter() {
                    if !policy.enabled {
                        continue;
                    }

                    // Check if sync is due
                    let should_sync = match policy.last_sync {
                        Some(last) => {
                            let elapsed = Utc::now() - last;
                            elapsed.num_seconds() >= policy.sync_interval_secs as i64
                        }
                        None => true, // Never synced before
                    };

                    if should_sync {
                        info!("Triggering scheduled sync for tenant: {}", tenant_id);

                        match self.sync_now(tenant_id).await {
                            Ok(result) => {
                                if !result.errors.is_empty() {
                                    warn!(
                                        "Sync completed with {} errors for tenant: {}",
                                        result.errors.len(),
                                        tenant_id
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Sync failed for tenant {}: {}", tenant_id, e);
                            }
                        }
                    }
                }
            }
        });
    }

    /// Get sync statistics
    pub async fn get_stats(&self, tenant_id: &str) -> Option<SyncStats> {
        let groups = self.synced_groups.read().await;
        let tenant_groups = groups.get(tenant_id)?;

        let total_groups = tenant_groups.len();
        let total_members: usize = tenant_groups.iter().map(|g| g.nested_members.len()).sum();

        let policy = {
            let policies = self.policies.read().await;
            policies.get(tenant_id).cloned()?
        };

        Some(SyncStats {
            tenant_id: tenant_id.to_string(),
            total_groups,
            total_members,
            last_sync: policy.last_sync,
            sync_enabled: policy.enabled,
        })
    }
}

impl Default for GroupSyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    pub tenant_id: String,
    pub total_groups: usize,
    pub total_members: usize,
    pub last_sync: Option<DateTime<Utc>>,
    pub sync_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_policy_creation() {
        let policy = GroupSyncPolicy::new("tenant1".to_string())
            .with_filter("(objectClass=group)".to_string())
            .with_interval(1800)
            .with_nested(true, 5);

        assert_eq!(policy.tenant_id, "tenant1");
        assert_eq!(policy.sync_interval_secs, 1800);
        assert!(policy.include_nested);
        assert_eq!(policy.max_depth, 5);
    }

    #[tokio::test]
    async fn test_sync_manager() {
        let manager = GroupSyncManager::new();

        let policy = GroupSyncPolicy::new("tenant1".to_string());
        manager.add_policy(policy).await;

        let retrieved = manager.get_policy("tenant1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tenant_id, "tenant1");
    }
}
