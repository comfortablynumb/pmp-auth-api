// Temporary stub file - old auth strategies removed
// Will be replaced with OAuth2/OIDC/SAML token generation

use crate::models::{Claims, UserRole};

/// Stub: Create local token (removed - no local auth)
pub fn create_local_token(
    _user_id: &str,
    _email: &str,
    _role: UserRole,
    _config: &serde_json::Value,
) -> Result<String, String> {
    Err("Local authentication removed. Use OAuth2/OIDC/SAML.".to_string())
}

/// Stub: Create secret token (removed - no simple JWT auth)
pub fn create_secret_token(
    _user_id: &str,
    _email: &str,
    _role: UserRole,
    _config: &serde_json::Value,
) -> Result<String, String> {
    Err("Secret JWT authentication removed. Use OAuth2/OIDC/SAML.".to_string())
}

/// Stub: Validate token (removed - will use OAuth2 token introspection)
pub fn validate_token(_token: &str, _config: &serde_json::Value) -> Result<Claims, String> {
    Err("Old token validation removed. Use OAuth2 token introspection.".to_string())
}
