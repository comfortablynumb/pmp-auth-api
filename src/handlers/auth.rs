use axum::{http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::auth::{create_token, hash_password, verify_password};
use crate::models::{
    AuthResponse, Claims, LoginRequest, RegisterRequest, User, UserInfo, UserRole,
};

// In-memory storage (in production, use a real database)
lazy_static::lazy_static! {
    static ref USERS: Arc<Mutex<HashMap<Uuid, User>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref EMAIL_INDEX: Arc<Mutex<HashMap<String, Uuid>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub async fn register(
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<Value>)> {
    // Validate input
    if payload.email.is_empty() || payload.username.is_empty() || payload.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Email, username, and password are required"
            })),
        ));
    }

    // Check if email already exists
    let email_index = EMAIL_INDEX.lock().unwrap();
    if email_index.contains_key(&payload.email) {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Email already registered"
            })),
        ));
    }
    drop(email_index);

    // Hash the password
    let password_hash = hash_password(&payload.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to hash password"
            })),
        )
    })?;

    // Create new user
    let user_id = Uuid::new_v4();
    let user = User {
        id: user_id,
        email: payload.email.clone(),
        username: payload.username,
        password_hash,
        role: UserRole::User,
        created_at: Utc::now(),
    };

    // Store user
    let mut users = USERS.lock().unwrap();
    let mut email_index = EMAIL_INDEX.lock().unwrap();

    users.insert(user_id, user.clone());
    email_index.insert(payload.email.clone(), user_id);

    drop(users);
    drop(email_index);

    // Create JWT token
    let claims = Claims {
        sub: user_id.to_string(),
        email: user.email.clone(),
        role: user.role,
        exp: (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };

    let token = create_token(&claims).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to create token"
            })),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            token,
            user: UserInfo::from(user),
        }),
    ))
}

pub async fn login(
    Json(payload): Json<LoginRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<Value>)> {
    // Find user by email
    let email_index = EMAIL_INDEX.lock().unwrap();
    let user_id = email_index.get(&payload.email).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid credentials"
            })),
        )
    })?;
    let user_id = *user_id;
    drop(email_index);

    let users = USERS.lock().unwrap();
    let user = users.get(&user_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid credentials"
            })),
        )
    })?;

    // Verify password
    let is_valid = verify_password(&payload.password, &user.password_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Password verification failed"
            })),
        )
    })?;

    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid credentials"
            })),
        ));
    }

    // Create JWT token
    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        role: user.role,
        exp: (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };

    let token = create_token(&claims).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to create token"
            })),
        )
    })?;

    let user_info = UserInfo::from(user.clone());

    Ok((
        StatusCode::OK,
        Json(AuthResponse {
            token,
            user: user_info,
        }),
    ))
}
