use crate::auth::identity_backend::BackendError;
use ldap3::{Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, info};

use super::backend::LdapConnection;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub dn: String,
    pub cn: String,
    pub members: Vec<String>,
    pub member_groups: Vec<String>, // Nested groups
    pub attributes: HashMap<String, Vec<String>>,
}

/// Group resolver for LDAP/AD
pub struct GroupResolver {
    connection: LdapConnection,
    base_dn: String,
    group_base_dn: Option<String>,
}

impl GroupResolver {
    pub fn new(connection: LdapConnection, base_dn: String, group_base_dn: Option<String>) -> Self {
        Self {
            connection,
            base_dn,
            group_base_dn,
        }
    }

    /// Get group information by DN
    pub async fn get_group(&self, group_dn: &str) -> Result<GroupInfo, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let (rs, _) = ldap
            .search(
                group_dn,
                Scope::Base,
                "(objectClass=*)",
                vec!["cn", "member", "memberOf", "objectClass"],
            )
            .await
            .map_err(|e| {
                error!("Failed to fetch group {}: {}", group_dn, e);
                BackendError::ConnectionError(format!("Group search failed: {}", e))
            })?
            .success()?;

        if rs.is_empty() {
            return Err(BackendError::UserNotFound);
        }

        let entry = SearchEntry::construct(rs[0].clone());
        Ok(self.entry_to_group_info(entry))
    }

    /// Get all groups a user belongs to (direct membership only)
    pub async fn get_user_groups(&self, user_dn: &str) -> Result<Vec<GroupInfo>, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let filter = format!("(member={})", user_dn);
        let search_base = self.group_base_dn.as_ref().unwrap_or(&self.base_dn);

        debug!(
            "Searching for groups with member: {} in base: {}",
            user_dn, search_base
        );

        let (rs, _) = ldap
            .search(
                search_base,
                Scope::Subtree,
                &filter,
                vec!["cn", "member", "memberOf", "objectClass"],
            )
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Group search failed: {}", e)))?
            .success()?;

        let groups: Vec<GroupInfo> = rs
            .into_iter()
            .map(|entry| self.entry_to_group_info(SearchEntry::construct(entry)))
            .collect();

        Ok(groups)
    }

    /// List all groups in the directory
    pub async fn list_all_groups(&self) -> Result<Vec<GroupInfo>, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let filter = "(objectClass=group)"; // AD groups
        let search_base = self.group_base_dn.as_ref().unwrap_or(&self.base_dn);

        let (rs, _) = ldap
            .search(
                search_base,
                Scope::Subtree,
                filter,
                vec!["cn", "member", "memberOf", "objectClass", "description"],
            )
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Group list failed: {}", e)))?
            .success()?;

        let groups: Vec<GroupInfo> = rs
            .into_iter()
            .map(|entry| self.entry_to_group_info(SearchEntry::construct(entry)))
            .collect();

        Ok(groups)
    }

    /// Search groups by filter
    pub async fn search_groups(&self, filter: &str) -> Result<Vec<GroupInfo>, BackendError> {
        let mut ldap = self.connection.connect().await?;

        let search_base = self.group_base_dn.as_ref().unwrap_or(&self.base_dn);

        let (rs, _) = ldap
            .search(
                search_base,
                Scope::Subtree,
                filter,
                vec!["cn", "member", "memberOf", "objectClass"],
            )
            .await
            .map_err(|e| BackendError::ConnectionError(format!("Group search failed: {}", e)))?
            .success()?;

        let groups: Vec<GroupInfo> = rs
            .into_iter()
            .map(|entry| self.entry_to_group_info(SearchEntry::construct(entry)))
            .collect();

        Ok(groups)
    }

    /// Get group members (users and groups)
    pub async fn get_group_members(&self, group_dn: &str) -> Result<Vec<String>, BackendError> {
        let group = self.get_group(group_dn).await?;
        Ok(group.members)
    }

    /// Convert LDAP entry to GroupInfo
    fn entry_to_group_info(&self, entry: SearchEntry) -> GroupInfo {
        let cn = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let members = entry.attrs.get("member").cloned().unwrap_or_default();

        let member_groups = entry.attrs.get("memberOf").cloned().unwrap_or_default();

        GroupInfo {
            dn: entry.dn.clone(),
            cn,
            members,
            member_groups,
            attributes: entry.attrs,
        }
    }
}

/// Nested group resolver with recursive expansion
pub struct NestedGroupResolver {
    pub resolver: GroupResolver,
    max_depth: usize,
}

impl NestedGroupResolver {
    pub fn new(resolver: GroupResolver) -> Self {
        Self {
            resolver,
            max_depth: 10, // Default max recursion depth
        }
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Get all groups a user belongs to, including nested groups
    pub async fn get_all_user_groups(&self, user_dn: &str) -> Result<Vec<GroupInfo>, BackendError> {
        let mut all_groups = HashSet::new();
        let mut groups_to_process = vec![user_dn.to_string()];
        let mut processed = HashSet::new();
        let mut depth = 0;

        info!("Resolving nested groups for user: {}", user_dn);

        while !groups_to_process.is_empty() && depth < self.max_depth {
            let current_dn = groups_to_process.pop().unwrap();

            if processed.contains(&current_dn) {
                continue;
            }

            processed.insert(current_dn.clone());

            // Get direct groups
            let groups = self.resolver.get_user_groups(&current_dn).await?;

            for group in groups {
                if all_groups.insert(group.dn.clone()) {
                    // New group found, add its parent groups to process
                    for parent_group_dn in &group.member_groups {
                        if !processed.contains(parent_group_dn) {
                            groups_to_process.push(parent_group_dn.clone());
                        }
                    }
                }
            }

            depth += 1;
        }

        if depth >= self.max_depth {
            error!(
                "Maximum recursion depth ({}) reached while resolving groups for {}",
                self.max_depth, user_dn
            );
        }

        info!(
            "Found {} total groups (including nested) for user: {}",
            all_groups.len(),
            user_dn
        );

        // Fetch full group info for all discovered groups
        let mut result = Vec::new();
        for group_dn in all_groups {
            match self.resolver.get_group(&group_dn).await {
                Ok(group_info) => result.push(group_info),
                Err(e) => {
                    error!("Failed to fetch group info for {}: {}", group_dn, e);
                }
            }
        }

        Ok(result)
    }

    /// Get all members of a group, including nested groups
    pub async fn get_all_group_members(&self, group_dn: &str) -> Result<Vec<String>, BackendError> {
        let mut all_members = HashSet::new();
        let mut groups_to_process = vec![group_dn.to_string()];
        let mut processed = HashSet::new();
        let mut depth = 0;

        info!("Resolving nested members for group: {}", group_dn);

        while !groups_to_process.is_empty() && depth < self.max_depth {
            let current_group_dn = groups_to_process.pop().unwrap();

            if processed.contains(&current_group_dn) {
                continue;
            }

            processed.insert(current_group_dn.clone());

            // Get group members
            let members = match self.resolver.get_group_members(&current_group_dn).await {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        "Failed to get members for group {}: {}",
                        current_group_dn, e
                    );
                    continue;
                }
            };

            for member_dn in members {
                // Check if this is a group or user
                // Groups typically have "CN=...,OU=Groups,..." or similar
                if self.is_group_dn(&member_dn) {
                    // It's a nested group
                    if !processed.contains(&member_dn) {
                        groups_to_process.push(member_dn);
                    }
                } else {
                    // It's a user
                    all_members.insert(member_dn);
                }
            }

            depth += 1;
        }

        if depth >= self.max_depth {
            error!(
                "Maximum recursion depth ({}) reached while resolving members for {}",
                self.max_depth, group_dn
            );
        }

        info!(
            "Found {} total members (including nested) for group: {}",
            all_members.len(),
            group_dn
        );

        Ok(all_members.into_iter().collect())
    }

    /// Check if a DN represents a group (heuristic)
    fn is_group_dn(&self, dn: &str) -> bool {
        // Simple heuristic: check if DN contains common group indicators
        dn.to_lowercase().contains("ou=groups")
            || dn.to_lowercase().contains("cn=groups")
            || dn.to_lowercase().contains("ou=security groups")
    }

    /// Get group hierarchy as a tree structure
    pub async fn get_group_hierarchy(
        &self,
        root_group_dn: &str,
    ) -> Result<GroupHierarchy, BackendError> {
        let root_group = self.resolver.get_group(root_group_dn).await?;
        let mut hierarchy = GroupHierarchy {
            group: root_group.clone(),
            children: Vec::new(),
        };

        self.build_hierarchy(&mut hierarchy, &mut HashSet::new(), 0)
            .await?;

        Ok(hierarchy)
    }

    async fn build_hierarchy(
        &self,
        node: &mut GroupHierarchy,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> Result<(), BackendError> {
        if depth >= self.max_depth {
            return Ok(());
        }

        visited.insert(node.group.dn.clone());

        // Find child groups (groups that have this group as memberOf)
        let filter = format!("(memberOf={})", node.group.dn);
        let child_groups = self.resolver.search_groups(&filter).await?;

        for child_group in child_groups {
            if !visited.contains(&child_group.dn) {
                let mut child_node = GroupHierarchy {
                    group: child_group,
                    children: Vec::new(),
                };

                Box::pin(self.build_hierarchy(&mut child_node, visited, depth + 1))
                    .await?;

                node.children.push(child_node);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupHierarchy {
    pub group: GroupInfo,
    pub children: Vec<GroupHierarchy>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_group_dn() {
        let resolver = NestedGroupResolver::new(GroupResolver {
            connection: LdapConnection {
                url: "ldap://localhost".to_string(),
                bind_dn: None,
                bind_password: None,
                settings: ldap3::LdapConnSettings::new(),
            },
            base_dn: "dc=example,dc=com".to_string(),
            group_base_dn: None,
        });

        assert!(resolver.is_group_dn("CN=Admins,OU=Groups,DC=example,DC=com"));
        assert!(resolver.is_group_dn("CN=Users,CN=Groups,DC=example,DC=com"));
        assert!(!resolver.is_group_dn("CN=John Doe,OU=Users,DC=example,DC=com"));
    }
}
