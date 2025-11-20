// Library exports for testing
pub mod admin;
pub mod audit;
pub mod auth;
pub mod certs;
pub mod config;
pub mod crypto;
pub mod handlers;
pub mod health;
pub mod ldap;
pub mod metrics;
pub mod mfa;
pub mod middleware;
pub mod models;
pub mod session;
pub mod storage;

use std::sync::Arc;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Application configuration
    pub config: Arc<models::AppConfig>,
    /// Storage backend for persistence
    pub storage: Arc<dyn storage::StorageBackend>,
}
