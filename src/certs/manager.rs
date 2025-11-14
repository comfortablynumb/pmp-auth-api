#![allow(dead_code)]

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyMetadata {
    pub kid: String,
    pub algorithm: Algorithm,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub tenant_id: String,
}

#[derive(Clone)]
pub struct SigningKey {
    pub metadata: SigningKeyMetadata,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub certificate: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct CertificateManager {
    keys: Arc<RwLock<HashMap<String, HashMap<String, SigningKey>>>>, // tenant_id -> kid -> SigningKey
}

impl CertificateManager {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new signing key for a tenant
    pub async fn generate_key(
        &self,
        tenant_id: &str,
        algorithm: Algorithm,
        validity_days: Option<i64>,
    ) -> Result<SigningKeyMetadata, Box<dyn std::error::Error>> {
        let kid = format!("{}_{}", tenant_id, Utc::now().timestamp());
        let expires_at = validity_days.map(|days| Utc::now() + Duration::days(days));

        let (encoding_key, decoding_key, certificate) = match algorithm {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                self.generate_rsa_keypair(algorithm)?
            }
            Algorithm::ES256 | Algorithm::ES384 => self.generate_ec_keypair(algorithm)?,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                self.generate_hmac_key(algorithm)?
            }
            _ => return Err("Unsupported algorithm".into()),
        };

        let metadata = SigningKeyMetadata {
            kid: kid.clone(),
            algorithm,
            created_at: Utc::now(),
            expires_at,
            active: true,
            tenant_id: tenant_id.to_string(),
        };

        let signing_key = SigningKey {
            metadata: metadata.clone(),
            encoding_key,
            decoding_key,
            certificate,
        };

        let mut keys = self.keys.write().await;
        keys.entry(tenant_id.to_string())
            .or_insert_with(HashMap::new)
            .insert(kid, signing_key);

        Ok(metadata)
    }

    /// Get the active signing key for a tenant
    pub async fn get_active_key(&self, tenant_id: &str) -> Option<SigningKey> {
        let keys = self.keys.read().await;
        let tenant_keys = keys.get(tenant_id)?;

        // Find the most recent active key
        tenant_keys
            .values()
            .filter(|k| k.metadata.active)
            .filter(|k| k.metadata.expires_at.is_none_or(|exp| exp > Utc::now()))
            .max_by_key(|k| k.metadata.created_at)
            .cloned()
    }

    /// Get all active keys for a tenant (for JWKS endpoint)
    pub async fn get_active_keys(&self, tenant_id: &str) -> Vec<SigningKey> {
        let keys = self.keys.read().await;
        let tenant_keys = match keys.get(tenant_id) {
            Some(k) => k,
            None => return vec![],
        };

        tenant_keys
            .values()
            .filter(|k| k.metadata.active)
            .filter(|k| k.metadata.expires_at.is_none_or(|exp| exp > Utc::now()))
            .cloned()
            .collect()
    }

    /// Get a specific key by kid
    pub async fn get_key(&self, tenant_id: &str, kid: &str) -> Option<SigningKey> {
        let keys = self.keys.read().await;
        keys.get(tenant_id)?.get(kid).cloned()
    }

    /// Rotate keys - mark old key as inactive and create new one
    pub async fn rotate_key(
        &self,
        tenant_id: &str,
        algorithm: Algorithm,
        validity_days: Option<i64>,
        grace_period_days: i64,
    ) -> Result<SigningKeyMetadata, Box<dyn std::error::Error>> {
        // Generate new key
        let new_metadata = self
            .generate_key(tenant_id, algorithm, validity_days)
            .await?;

        // Mark old keys as inactive after grace period
        let mut keys = self.keys.write().await;
        if let Some(tenant_keys) = keys.get_mut(tenant_id) {
            let deactivation_time = Utc::now() + Duration::days(grace_period_days);
            for key in tenant_keys.values_mut() {
                if key.metadata.kid != new_metadata.kid && key.metadata.active {
                    // Schedule deactivation
                    key.metadata.expires_at = Some(deactivation_time);
                }
            }
        }

        Ok(new_metadata)
    }

    /// Deactivate a specific key
    pub async fn deactivate_key(
        &self,
        tenant_id: &str,
        kid: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut keys = self.keys.write().await;
        if let Some(tenant_keys) = keys.get_mut(tenant_id) {
            if let Some(key) = tenant_keys.get_mut(kid) {
                key.metadata.active = false;
                return Ok(());
            }
        }
        Err("Key not found".into())
    }

    /// List all keys for a tenant
    pub async fn list_keys(&self, tenant_id: &str) -> Vec<SigningKeyMetadata> {
        let keys = self.keys.read().await;
        match keys.get(tenant_id) {
            Some(tenant_keys) => tenant_keys.values().map(|k| k.metadata.clone()).collect(),
            None => vec![],
        }
    }

    /// Clean up expired keys
    pub async fn cleanup_expired_keys(&self) -> usize {
        let mut keys = self.keys.write().await;
        let mut removed_count = 0;

        for tenant_keys in keys.values_mut() {
            let before_count = tenant_keys.len();
            tenant_keys
                .retain(|_, key| key.metadata.expires_at.is_none_or(|exp| exp > Utc::now()));
            removed_count += before_count - tenant_keys.len();
        }

        removed_count
    }

    // Helper methods for key generation

    #[allow(clippy::type_complexity)]
    fn generate_rsa_keypair(
        &self,
        _algorithm: Algorithm,
    ) -> Result<(EncodingKey, DecodingKey, Option<Vec<u8>>), Box<dyn std::error::Error>> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        let private_pem = key_pair.serialize_pem();
        let public_pem = cert.pem();

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())?;

        Ok((encoding_key, decoding_key, Some(public_pem.into_bytes())))
    }

    #[allow(clippy::type_complexity)]
    fn generate_ec_keypair(
        &self,
        algorithm: Algorithm,
    ) -> Result<(EncodingKey, DecodingKey, Option<Vec<u8>>), Box<dyn std::error::Error>> {
        let alg = match algorithm {
            Algorithm::ES256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            Algorithm::ES384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => return Err("Unsupported EC algorithm".into()),
        };

        let key_pair = KeyPair::generate_for(alg)?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let cert = params.self_signed(&key_pair)?;

        let private_pem = key_pair.serialize_pem();
        let public_pem = cert.pem();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes())?;
        let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())?;

        Ok((encoding_key, decoding_key, Some(public_pem.into_bytes())))
    }

    #[allow(clippy::type_complexity)]
    fn generate_hmac_key(
        &self,
        algorithm: Algorithm,
    ) -> Result<(EncodingKey, DecodingKey, Option<Vec<u8>>), Box<dyn std::error::Error>> {
        use rand::Rng;

        let key_size = match algorithm {
            Algorithm::HS256 => 32,
            Algorithm::HS384 => 48,
            Algorithm::HS512 => 64,
            _ => return Err("Unsupported HMAC algorithm".into()),
        };

        let secret: Vec<u8> = rand::thread_rng()
            .sample_iter(rand::distributions::Standard)
            .take(key_size)
            .collect();

        let encoding_key = EncodingKey::from_secret(&secret);
        let decoding_key = DecodingKey::from_secret(&secret);

        Ok((encoding_key, decoding_key, None))
    }

    /// Import an existing key from PEM
    pub async fn import_key(
        &self,
        tenant_id: &str,
        kid: &str,
        algorithm: Algorithm,
        private_pem: &[u8],
        public_pem: Option<&[u8]>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<SigningKeyMetadata, Box<dyn std::error::Error>> {
        let (encoding_key, decoding_key) = match algorithm {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let encoding = EncodingKey::from_rsa_pem(private_pem)?;
                let decoding = match public_pem {
                    Some(pem) => DecodingKey::from_rsa_pem(pem)?,
                    None => return Err("Public key required for RSA".into()),
                };
                (encoding, decoding)
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let encoding = EncodingKey::from_ec_pem(private_pem)?;
                let decoding = match public_pem {
                    Some(pem) => DecodingKey::from_ec_pem(pem)?,
                    None => return Err("Public key required for EC".into()),
                };
                (encoding, decoding)
            }
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let encoding = EncodingKey::from_secret(private_pem);
                let decoding = DecodingKey::from_secret(private_pem);
                (encoding, decoding)
            }
            _ => return Err("Unsupported algorithm".into()),
        };

        let metadata = SigningKeyMetadata {
            kid: kid.to_string(),
            algorithm,
            created_at: Utc::now(),
            expires_at,
            active: true,
            tenant_id: tenant_id.to_string(),
        };

        let signing_key = SigningKey {
            metadata: metadata.clone(),
            encoding_key,
            decoding_key,
            certificate: public_pem.map(|p| p.to_vec()),
        };

        let mut keys = self.keys.write().await;
        keys.entry(tenant_id.to_string())
            .or_insert_with(HashMap::new)
            .insert(kid.to_string(), signing_key);

        Ok(metadata)
    }
}

impl Default for CertificateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_and_retrieve_key() {
        let manager = CertificateManager::new();
        let metadata = manager
            .generate_key("tenant1", Algorithm::RS256, Some(365))
            .await
            .unwrap();

        assert_eq!(metadata.tenant_id, "tenant1");
        assert_eq!(metadata.algorithm, Algorithm::RS256);
        assert!(metadata.active);

        let key = manager.get_active_key("tenant1").await.unwrap();
        assert_eq!(key.metadata.kid, metadata.kid);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = CertificateManager::new();

        let first_key = manager
            .generate_key("tenant1", Algorithm::RS256, Some(365))
            .await
            .unwrap();

        let second_key = manager
            .rotate_key("tenant1", Algorithm::RS256, Some(365), 30)
            .await
            .unwrap();

        assert_ne!(first_key.kid, second_key.kid);

        let keys = manager.list_keys("tenant1").await;
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_multiple_tenants() {
        let manager = CertificateManager::new();

        manager
            .generate_key("tenant1", Algorithm::RS256, Some(365))
            .await
            .unwrap();

        manager
            .generate_key("tenant2", Algorithm::ES256, Some(365))
            .await
            .unwrap();

        let key1 = manager.get_active_key("tenant1").await.unwrap();
        let key2 = manager.get_active_key("tenant2").await.unwrap();

        assert_eq!(key1.metadata.algorithm, Algorithm::RS256);
        assert_eq!(key2.metadata.algorithm, Algorithm::ES256);
    }
}
