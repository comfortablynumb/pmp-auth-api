use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
}

impl UserRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "user" => Some(UserRole::User),
            "admin" => Some(UserRole::Admin),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            UserRole::User => "user".to_string(),
            UserRole::Admin => "admin".to_string(),
        }
    }
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
