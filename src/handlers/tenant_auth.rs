use crate::auth::{
    create_local_token, create_secret_token, generate_auth_url, handle_oauth2_callback,
    hash_password, verify_password, OAuth2CallbackResult,
};
use crate::models::{
    AppConfig, AuthResponse, AuthStrategy, LoginRequest, RegisterRequest, User, UserInfo, UserRole,
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};
use uuid::Uuid;

// Tenant-specific user storage (in production, use a real database with tenant isolation)
lazy_static::lazy_static! {
    static ref TENANT_USERS: Arc<Mutex<HashMap<String, HashMap<Uuid, User>>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref TENANT_EMAIL_INDEX: Arc<Mutex<HashMap<String, HashMap<String, Uuid>>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// Register a new user (local auth strategy)
pub async fn register(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, strategy_name)): Path<(String, String)>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Registration request for tenant '{}' strategy '{}'",
        tenant_id, strategy_name
    );

    // Get tenant and auth strategy
    let strategy = config
        .get_auth_strategy(&tenant_id, &strategy_name)
        .ok_or_else(|| {
            warn!(
                "Tenant or strategy not found: {}/{}",
                tenant_id, strategy_name
            );
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Tenant or auth strategy not found" })),
            )
        })?;

    // Only local auth supports registration
    let local_config = match strategy {
        AuthStrategy::Local(config) => config,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Registration is only supported for local auth strategy" })),
            ));
        }
    };

    if !local_config.allow_registration {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Registration is not allowed for this tenant" })),
        ));
    }

    // Validate password length
    if payload.password.len() < local_config.min_password_length {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Password must be at least {} characters long", local_config.min_password_length)
            })),
        ));
    }

    // Check if email already exists for this tenant
    {
        let email_index = TENANT_EMAIL_INDEX.lock().unwrap();
        if let Some(tenant_emails) = email_index.get(&tenant_id) {
            if tenant_emails.contains_key(&payload.email) {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "Email already registered" })),
                ));
            }
        }
    }

    // Hash password
    let password_hash = hash_password(&payload.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })?;

    // Create user
    let user = User {
        id: Uuid::new_v4(),
        email: payload.email.clone(),
        username: payload.username.clone(),
        password_hash,
        role: UserRole::User,
        created_at: Utc::now(),
    };

    // Store user
    {
        let mut users = TENANT_USERS.lock().unwrap();
        users
            .entry(tenant_id.clone())
            .or_default()
            .insert(user.id, user.clone());
    }

    // Update email index
    {
        let mut email_index = TENANT_EMAIL_INDEX.lock().unwrap();
        email_index
            .entry(tenant_id.clone())
            .or_default()
            .insert(payload.email.clone(), user.id);
    }

    // Create token
    let token = create_local_token(&user.id.to_string(), &user.email, user.role, local_config)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
        })?;

    info!(
        "User registered successfully for tenant '{}': {}",
        tenant_id, user.email
    );

    Ok(Json(AuthResponse {
        token,
        user: UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
        },
    }))
}

/// Login with username/password (local auth strategy)
pub async fn login(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, strategy_name)): Path<(String, String)>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Login request for tenant '{}' strategy '{}'",
        tenant_id, strategy_name
    );

    // Get tenant and auth strategy
    let strategy = config
        .get_auth_strategy(&tenant_id, &strategy_name)
        .ok_or_else(|| {
            warn!(
                "Tenant or strategy not found: {}/{}",
                tenant_id, strategy_name
            );
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Tenant or auth strategy not found" })),
            )
        })?;

    // Get user by email
    let user_id = {
        let email_index = TENANT_EMAIL_INDEX.lock().unwrap();
        email_index
            .get(&tenant_id)
            .and_then(|tenant_emails| tenant_emails.get(&payload.email))
            .copied()
    }
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid credentials" })),
        )
    })?;

    let user = {
        let users = TENANT_USERS.lock().unwrap();
        users
            .get(&tenant_id)
            .and_then(|tenant_users| tenant_users.get(&user_id))
            .cloned()
    }
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid credentials" })),
        )
    })?;

    // Verify password
    if !verify_password(&payload.password, &user.password_hash).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })? {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid credentials" })),
        ));
    }

    // Create token based on strategy
    let token = match strategy {
        AuthStrategy::Local(config) => {
            create_local_token(&user.id.to_string(), &user.email, user.role, config)
        }
        AuthStrategy::SecretJwt(config) => {
            create_secret_token(&user.id.to_string(), &user.email, user.role, config)
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Password login not supported for this auth strategy" })),
            ));
        }
    }
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
    })?;

    info!("User logged in successfully: {}", user.email);

    Ok(Json(AuthResponse {
        token,
        user: UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
        },
    }))
}

/// Initiate OAuth2 login flow
pub async fn oauth2_login(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, strategy_name)): Path<(String, String)>,
) -> Result<Redirect, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "OAuth2 login request for tenant '{}' strategy '{}'",
        tenant_id, strategy_name
    );

    // Get tenant and auth strategy
    let strategy = config
        .get_auth_strategy(&tenant_id, &strategy_name)
        .ok_or_else(|| {
            warn!(
                "Tenant or strategy not found: {}/{}",
                tenant_id, strategy_name
            );
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Tenant or auth strategy not found" })),
            )
        })?;

    // Only OAuth2 auth supports this endpoint
    let oauth2_config = match strategy {
        AuthStrategy::OAuth2(config) => config,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "This endpoint only supports OAuth2 auth strategy" })),
            ));
        }
    };

    // Generate authorization URL
    let (auth_url, _csrf_token) = generate_auth_url(oauth2_config, &tenant_id, &strategy_name)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
        })?;

    Ok(Redirect::temporary(&auth_url))
}

#[derive(Debug, Deserialize)]
pub struct OAuth2CallbackQuery {
    code: String,
    state: String,
}

/// Handle OAuth2 callback
pub async fn oauth2_callback(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, strategy_name)): Path<(String, String)>,
    Query(query): Query<OAuth2CallbackQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "OAuth2 callback for tenant '{}' strategy '{}'",
        tenant_id, strategy_name
    );

    // Get tenant and auth strategy
    let strategy = config
        .get_auth_strategy(&tenant_id, &strategy_name)
        .ok_or_else(|| {
            warn!(
                "Tenant or strategy not found: {}/{}",
                tenant_id, strategy_name
            );
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Tenant or auth strategy not found" })),
            )
        })?;

    // Only OAuth2 auth supports this endpoint
    let oauth2_config = match strategy {
        AuthStrategy::OAuth2(config) => config,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "This endpoint only supports OAuth2 auth strategy" })),
            ));
        }
    };

    // Handle the callback
    let result: OAuth2CallbackResult =
        handle_oauth2_callback(oauth2_config, &query.code, &query.state)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e })),
                )
            })?;

    // In a real application, you would:
    // 1. Create or update user in your database
    // 2. Generate your own JWT token
    // 3. Return the token to the client

    info!(
        "OAuth2 authentication successful for tenant '{}'",
        tenant_id
    );

    Ok(Json(json!({
        "success": true,
        "access_token": result.access_token,
        "user_info": result.user_info,
        "message": "OAuth2 authentication successful. In production, this would return a JWT token."
    })))
}

/// List available auth strategies for a tenant
pub async fn list_strategies(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!("Listing auth strategies for tenant '{}'", tenant_id);

    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Tenant not found" })),
        )
    })?;

    let strategies: Vec<serde_json::Value> = tenant
        .auth_strategies
        .iter()
        .map(|(name, strategy)| {
            let strategy_type = match strategy {
                AuthStrategy::JwkJwt(_) => "jwkjwt",
                AuthStrategy::SecretJwt(_) => "secretjwt",
                AuthStrategy::OAuth2(_) => "oauth2",
                AuthStrategy::Local(_) => "local",
            };

            json!({
                "name": name,
                "type": strategy_type,
            })
        })
        .collect();

    Ok(Json(json!({
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "strategies": strategies
    })))
}
