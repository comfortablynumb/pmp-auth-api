use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,    // Subject (user ID)
    pub email: String,  // User email
    pub role: UserRole, // User role
    pub exp: usize,     // Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>, // Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>, // Audience (client_ids)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, // Space-separated scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>, // Tenant identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>, // Authorized party (client_id)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>, // JWT ID
}
