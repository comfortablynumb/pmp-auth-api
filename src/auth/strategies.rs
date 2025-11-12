use crate::models::{
    AuthStrategy, Claims, JwkConfig, LocalAuthConfig, OAuth2Config, SecretJwtConfig,
};
use alcoholic_jwt::{token_kid, validate, ValidJWT, Validation, JWKS};
use axum::http::StatusCode;
use jsonwebtoken::{decode, DecodingKey, Validation as JwtValidation};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Cache entry for JWK sets
#[derive(Clone)]
struct JwkCacheEntry {
    jwks: JWKS,
    cached_at: Instant,
}

/// Global JWK cache
lazy_static::lazy_static! {
    static ref JWK_CACHE: Arc<Mutex<HashMap<String, JwkCacheEntry>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// Validate a JWT token using the appropriate strategy
pub async fn validate_token(
    token: &str,
    strategy: &AuthStrategy,
) -> Result<Claims, (StatusCode, String)> {
    match strategy {
        AuthStrategy::JwkJwt(config) => validate_jwk_token(token, config).await,
        AuthStrategy::SecretJwt(config) => validate_secret_token(token, config),
        AuthStrategy::OAuth2(_) => {
            // OAuth2 tokens are validated differently (typically by calling the userinfo endpoint)
            Err((
                StatusCode::BAD_REQUEST,
                "OAuth2 tokens should be validated via the OAuth2 flow".to_string(),
            ))
        }
        AuthStrategy::Local(config) => validate_local_token(token, config),
    }
}

/// Validate JWT token using JWK (e.g., Auth0, Okta)
async fn validate_jwk_token(
    token: &str,
    config: &JwkConfig,
) -> Result<Claims, (StatusCode, String)> {
    debug!("Validating JWT token using JWK strategy");

    // Get JWKS (from cache or fetch)
    let jwks = fetch_jwks(&config.jwks_uri, config.cache_duration_secs)
        .await
        .map_err(|e| {
            error!("Failed to fetch JWKS: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch JWKS: {}", e),
            )
        })?;

    // Extract the kid (key ID) from token header
    let kid = token_kid(token).map_err(|e| {
        warn!("Failed to extract kid from token: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            format!("Invalid token format: {}", e),
        )
    })?;

    let kid = kid.ok_or_else(|| {
        warn!("Token missing kid in header");
        (StatusCode::UNAUTHORIZED, "Token missing kid".to_string())
    })?;

    // Find the matching JWK
    let jwk = jwks.find(&kid).ok_or_else(|| {
        warn!("No matching JWK found for kid: {}", kid);
        (
            StatusCode::UNAUTHORIZED,
            format!("No matching key found for kid: {}", kid),
        )
    })?;

    // Create validations
    let mut validations = vec![Validation::Issuer(
        config.issuer.clone().unwrap_or_default(),
    )];

    if let Some(audience) = &config.audience {
        if !audience.is_empty() {
            validations.push(Validation::Audience(audience[0].clone()));
        }
    }

    // Validate the token
    let valid_jwt: ValidJWT = validate(token, jwk, validations).map_err(|e| {
        warn!("JWT validation failed: {}", e);
        (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e))
    })?;

    // Extract claims
    let claims_value: Value = serde_json::from_str(&valid_jwt.claims.to_string()).map_err(|e| {
        error!("Failed to parse claims: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse claims: {}", e),
        )
    })?;

    // Convert to our Claims structure
    let sub = claims_value["sub"]
        .as_str()
        .ok_or_else(|| {
            warn!("Token missing sub claim");
            (
                StatusCode::UNAUTHORIZED,
                "Token missing sub claim".to_string(),
            )
        })?
        .to_string();

    let email = claims_value["email"]
        .as_str()
        .unwrap_or("unknown@example.com")
        .to_string();

    let role = crate::models::UserRole::User; // Default role for external JWT

    let exp = claims_value["exp"].as_i64().unwrap_or(0);

    Ok(Claims {
        sub,
        email,
        role,
        exp: exp as usize,
    })
}

/// Validate JWT token using a shared secret
fn validate_secret_token(
    token: &str,
    config: &SecretJwtConfig,
) -> Result<Claims, (StatusCode, String)> {
    debug!("Validating JWT token using secret strategy");

    let mut validation = JwtValidation::default();

    if let Some(issuer) = &config.issuer {
        validation.set_issuer(&[issuer]);
    }

    if let Some(audience) = &config.audience {
        validation.set_audience(audience);
    }

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        warn!("JWT validation failed: {}", e);
        (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e))
    })?;

    Ok(token_data.claims)
}

/// Validate JWT token for local authentication
fn validate_local_token(
    token: &str,
    config: &LocalAuthConfig,
) -> Result<Claims, (StatusCode, String)> {
    debug!("Validating JWT token using local strategy");

    let validation = JwtValidation::default();

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        warn!("JWT validation failed: {}", e);
        (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e))
    })?;

    Ok(token_data.claims)
}

/// Fetch JWKS from a URL with caching
async fn fetch_jwks(jwks_uri: &str, cache_duration_secs: u64) -> Result<JWKS, String> {
    // Check cache first
    {
        let cache = JWK_CACHE.lock().unwrap();
        if let Some(entry) = cache.get(jwks_uri) {
            if entry.cached_at.elapsed() < Duration::from_secs(cache_duration_secs) {
                debug!("Using cached JWKS for {}", jwks_uri);
                return Ok(entry.jwks.clone());
            }
        }
    }

    // Fetch from URL
    info!("Fetching JWKS from {}", jwks_uri);
    let client = reqwest::Client::new();
    let response = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "JWKS endpoint returned status: {}",
            response.status()
        ));
    }

    let jwks_json = response
        .text()
        .await
        .map_err(|e| format!("Failed to read JWKS response: {}", e))?;

    let jwks: JWKS =
        serde_json::from_str(&jwks_json).map_err(|e| format!("Failed to parse JWKS: {}", e))?;

    // Update cache
    {
        let mut cache = JWK_CACHE.lock().unwrap();
        cache.insert(
            jwks_uri.to_string(),
            JwkCacheEntry {
                jwks: jwks.clone(),
                cached_at: Instant::now(),
            },
        );
    }

    Ok(jwks)
}

/// Create a JWT token for local authentication
pub fn create_local_token(
    user_id: &str,
    email: &str,
    role: crate::models::UserRole,
    config: &LocalAuthConfig,
) -> Result<String, String> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(config.expiration_secs))
        .ok_or_else(|| "Failed to calculate expiration time".to_string())?
        .timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role,
        exp: expiration as usize,
    };

    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| format!("Failed to create token: {}", e))
}

/// Create a JWT token for secret-based authentication
pub fn create_secret_token(
    user_id: &str,
    email: &str,
    role: crate::models::UserRole,
    config: &SecretJwtConfig,
) -> Result<String, String> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(config.expiration_secs))
        .ok_or_else(|| "Failed to calculate expiration time".to_string())?
        .timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role,
        exp: expiration as usize,
    };

    let header = jsonwebtoken::Header::default();

    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(config.secret.as_bytes()),
    )
    .map_err(|e| format!("Failed to create token: {}", e))
}
