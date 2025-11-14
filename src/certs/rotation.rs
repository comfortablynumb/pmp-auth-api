#![allow(dead_code)]

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{Duration as TokioDuration, sleep};
use tracing::{error, info};

use super::manager::CertificateManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Tenant ID this policy applies to
    pub tenant_id: String,
    /// How often to rotate keys (in days)
    pub rotation_interval_days: i64,
    /// Key validity period (in days)
    pub key_validity_days: i64,
    /// Grace period before deactivating old keys (in days)
    pub grace_period_days: i64,
    /// Algorithm to use for new keys
    pub algorithm: Algorithm,
    /// Whether automatic rotation is enabled
    pub enabled: bool,
    /// Next scheduled rotation time
    pub next_rotation: Option<DateTime<Utc>>,
}

impl RotationPolicy {
    pub fn new(tenant_id: String, algorithm: Algorithm) -> Self {
        Self {
            tenant_id,
            rotation_interval_days: 90, // Default: rotate every 90 days
            key_validity_days: 365,     // Default: 1 year validity
            grace_period_days: 30,      // Default: 30 day grace period
            algorithm,
            enabled: true,
            next_rotation: Some(Utc::now() + Duration::days(90)),
        }
    }

    pub fn with_interval(mut self, days: i64) -> Self {
        self.rotation_interval_days = days;
        self.next_rotation = Some(Utc::now() + Duration::days(days));
        self
    }

    pub fn with_validity(mut self, days: i64) -> Self {
        self.key_validity_days = days;
        self
    }

    pub fn with_grace_period(mut self, days: i64) -> Self {
        self.grace_period_days = days;
        self
    }

    pub fn is_due(&self) -> bool {
        if !self.enabled {
            return false;
        }
        match self.next_rotation {
            Some(next) => Utc::now() >= next,
            None => false,
        }
    }

    pub fn schedule_next_rotation(&mut self) {
        self.next_rotation = Some(Utc::now() + Duration::days(self.rotation_interval_days));
    }
}

pub struct RotationScheduler {
    cert_manager: Arc<CertificateManager>,
    policies: Arc<tokio::sync::RwLock<Vec<RotationPolicy>>>,
    check_interval: TokioDuration,
}

impl RotationScheduler {
    pub fn new(cert_manager: Arc<CertificateManager>) -> Self {
        Self {
            cert_manager,
            policies: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            check_interval: TokioDuration::from_secs(3600), // Check every hour
        }
    }

    pub fn with_check_interval(mut self, interval: TokioDuration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Add a rotation policy for a tenant
    pub async fn add_policy(&self, policy: RotationPolicy) {
        let mut policies = self.policies.write().await;
        // Remove existing policy for same tenant if any
        policies.retain(|p| p.tenant_id != policy.tenant_id);
        policies.push(policy);
    }

    /// Remove a rotation policy
    pub async fn remove_policy(&self, tenant_id: &str) {
        let mut policies = self.policies.write().await;
        policies.retain(|p| p.tenant_id != tenant_id);
    }

    /// Get all policies
    pub async fn get_policies(&self) -> Vec<RotationPolicy> {
        let policies = self.policies.read().await;
        policies.clone()
    }

    /// Get policy for a specific tenant
    pub async fn get_policy(&self, tenant_id: &str) -> Option<RotationPolicy> {
        let policies = self.policies.read().await;
        policies.iter().find(|p| p.tenant_id == tenant_id).cloned()
    }

    /// Update a policy
    pub async fn update_policy(&self, policy: RotationPolicy) {
        let mut policies = self.policies.write().await;
        if let Some(p) = policies
            .iter_mut()
            .find(|p| p.tenant_id == policy.tenant_id)
        {
            *p = policy;
        }
    }

    /// Start the rotation scheduler
    pub async fn start(self: Arc<Self>) {
        info!("Starting certificate rotation scheduler");

        loop {
            sleep(self.check_interval).await;

            match self.check_and_rotate().await {
                Ok(rotated_count) => {
                    if rotated_count > 0 {
                        info!("Rotated {} certificates", rotated_count);
                    }
                }
                Err(e) => {
                    error!("Error during certificate rotation check: {}", e);
                }
            }

            // Also cleanup expired keys
            match self.cert_manager.cleanup_expired_keys().await {
                0 => {}
                count => {
                    info!("Cleaned up {} expired keys", count);
                }
            }
        }
    }

    /// Check all policies and rotate keys if needed
    async fn check_and_rotate(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut rotated_count = 0;
        let policies = {
            let p = self.policies.read().await;
            p.clone()
        };

        for policy in policies.iter() {
            if policy.is_due() {
                info!("Certificate rotation due for tenant: {}", policy.tenant_id);

                match self
                    .cert_manager
                    .rotate_key(
                        &policy.tenant_id,
                        policy.algorithm,
                        Some(policy.key_validity_days),
                        policy.grace_period_days,
                    )
                    .await
                {
                    Ok(metadata) => {
                        info!(
                            "Successfully rotated key for tenant {}: {}",
                            policy.tenant_id, metadata.kid
                        );
                        rotated_count += 1;

                        // Update the policy's next rotation time
                        let mut policies = self.policies.write().await;
                        if let Some(p) = policies
                            .iter_mut()
                            .find(|p| p.tenant_id == policy.tenant_id)
                        {
                            p.schedule_next_rotation();
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to rotate key for tenant {}: {}",
                            policy.tenant_id, e
                        );
                    }
                }
            }
        }

        Ok(rotated_count)
    }

    /// Manually trigger rotation for a tenant
    pub async fn rotate_now(&self, tenant_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let policy = {
            let policies = self.policies.read().await;
            policies
                .iter()
                .find(|p| p.tenant_id == tenant_id)
                .cloned()
                .ok_or("Policy not found")?
        };

        self.cert_manager
            .rotate_key(
                &policy.tenant_id,
                policy.algorithm,
                Some(policy.key_validity_days),
                policy.grace_period_days,
            )
            .await?;

        // Update next rotation time
        let mut policies = self.policies.write().await;
        if let Some(p) = policies.iter_mut().find(|p| p.tenant_id == tenant_id) {
            p.schedule_next_rotation();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rotation_policy_creation() {
        let policy = RotationPolicy::new("tenant1".to_string(), Algorithm::RS256)
            .with_interval(30)
            .with_validity(365)
            .with_grace_period(7);

        assert_eq!(policy.tenant_id, "tenant1");
        assert_eq!(policy.rotation_interval_days, 30);
        assert_eq!(policy.key_validity_days, 365);
        assert_eq!(policy.grace_period_days, 7);
        assert!(policy.enabled);
    }

    #[tokio::test]
    async fn test_add_and_get_policy() {
        let cert_manager = Arc::new(CertificateManager::new());
        let scheduler = RotationScheduler::new(cert_manager);

        let policy = RotationPolicy::new("tenant1".to_string(), Algorithm::RS256);
        scheduler.add_policy(policy.clone()).await;

        let retrieved = scheduler.get_policy("tenant1").await.unwrap();
        assert_eq!(retrieved.tenant_id, "tenant1");
    }

    #[tokio::test]
    #[ignore = "Certificate key format compatibility issue - needs fixing"]
    async fn test_manual_rotation() {
        let cert_manager = Arc::new(CertificateManager::new());
        let scheduler = Arc::new(RotationScheduler::new(cert_manager.clone()));

        // Create initial key
        cert_manager
            .generate_key("tenant1", Algorithm::RS256, Some(365))
            .await
            .unwrap();

        // Add policy
        let policy = RotationPolicy::new("tenant1".to_string(), Algorithm::RS256);
        scheduler.add_policy(policy).await;

        // Trigger manual rotation
        scheduler.rotate_now("tenant1").await.unwrap();

        // Should now have 2 keys for tenant1
        let keys = cert_manager.list_keys("tenant1").await;
        assert_eq!(keys.len(), 2);
    }
}
