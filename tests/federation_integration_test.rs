// Integration tests for OAuth2 Federation
//
// These tests verify the complete federation flow including:
// - Provider creation and configuration
// - User creation from federated authentication
// - User linking across multiple providers
// - Storage operations for federated identities

use pmp_auth_api::auth::federation::{ProviderUserInfo, types::FederationProviderConfig};
use pmp_auth_api::storage::{StorageBackend, FederatedIdentityData, UserData, memory::MemoryStorage};
use chrono::Utc;

/// Helper to create a test user info from Google
fn create_google_user_info() -> ProviderUserInfo {
    ProviderUserInfo {
        provider_user_id: "google-123456".to_string(),
        email: "user@example.com".to_string(),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        given_name: Some("Test".to_string()),
        family_name: Some("User".to_string()),
        picture: Some("https://example.com/photo.jpg".to_string()),
        preferred_username: Some("user@example.com".to_string()),
        locale: Some("en-US".to_string()),
        raw_profile: serde_json::json!({
            "sub": "google-123456",
            "email": "user@example.com",
            "email_verified": true,
            "name": "Test User"
        }),
    }
}

/// Helper to create a test user info from GitHub
fn create_github_user_info() -> ProviderUserInfo {
    ProviderUserInfo {
        provider_user_id: "789012".to_string(),
        email: "user@example.com".to_string(),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        given_name: None,
        family_name: None,
        picture: Some("https://avatars.githubusercontent.com/u/789012".to_string()),
        preferred_username: Some("testuser".to_string()),
        locale: None,
        raw_profile: serde_json::json!({
            "id": 789012,
            "login": "testuser",
            "email": "user@example.com"
        }),
    }
}

#[tokio::test]
async fn test_create_user_from_google_federation() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";
    let provider_id = "google";

    let user_info = create_google_user_info();

    // First login should create a new user
    let user = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info)
        .await
        .expect("Failed to create federated user");

    // Verify user was created with correct details
    assert_eq!(user.email, "user@example.com");
    assert_eq!(user.tenant_id, tenant_id);
    assert_eq!(user.email_verified, true); // Email verified by Google
    assert_eq!(user.name, Some("Test User".to_string()));
    assert_eq!(user.password_hash, ""); // No password for federated users

    // Verify federated identity was created
    let fed_identity = storage
        .get_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to get federated identity")
        .expect("Federated identity not found");

    assert_eq!(fed_identity.user_id, user.id);
    assert_eq!(fed_identity.provider_id, provider_id);
    assert_eq!(fed_identity.provider_user_id, "google-123456");
    assert_eq!(fed_identity.provider_email, "user@example.com");
    assert_eq!(fed_identity.provider_email_verified, true);
}

#[tokio::test]
async fn test_link_multiple_providers_same_user() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";

    // First login with Google
    let google_user_info = create_google_user_info();
    let user_from_google = storage
        .get_or_create_federated_user(tenant_id, "google", &google_user_info)
        .await
        .expect("Failed to create user from Google");

    // Second login with GitHub (same email)
    let github_user_info = create_github_user_info();
    let user_from_github = storage
        .get_or_create_federated_user(tenant_id, "github", &github_user_info)
        .await
        .expect("Failed to create user from GitHub");

    // Should be the same user (linked by email)
    assert_eq!(user_from_google.id, user_from_github.id);
    assert_eq!(user_from_google.email, user_from_github.email);

    // Verify both federated identities exist
    let google_identity = storage
        .get_federated_identity(tenant_id, "google", &google_user_info.provider_user_id)
        .await
        .expect("Failed to get Google identity")
        .expect("Google identity not found");

    let github_identity = storage
        .get_federated_identity(tenant_id, "github", &github_user_info.provider_user_id)
        .await
        .expect("Failed to get GitHub identity")
        .expect("GitHub identity not found");

    assert_eq!(google_identity.user_id, github_identity.user_id);

    // Verify we can get all federated identities for the user
    let all_identities = storage
        .get_user_federated_identities(&user_from_google.id)
        .await
        .expect("Failed to get user federated identities");

    assert_eq!(all_identities.len(), 2);
    let provider_ids: Vec<_> = all_identities.iter().map(|i| i.provider_id.as_str()).collect();
    assert!(provider_ids.contains(&"google"));
    assert!(provider_ids.contains(&"github"));
}

#[tokio::test]
async fn test_update_last_login_on_subsequent_login() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";
    let provider_id = "google";

    let user_info = create_google_user_info();

    // First login
    let _ = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info)
        .await
        .expect("Failed to create federated user");

    let identity_after_first_login = storage
        .get_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to get identity")
        .expect("Identity not found");

    let first_login_time = identity_after_first_login.last_login_at;

    // Wait a moment
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Second login
    let _ = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info)
        .await
        .expect("Failed on second login");

    let identity_after_second_login = storage
        .get_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to get identity")
        .expect("Identity not found");

    let second_login_time = identity_after_second_login.last_login_at;

    // last_login_at should be updated
    assert!(second_login_time > first_login_time);
}

#[tokio::test]
async fn test_email_verification_from_trusted_provider() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";

    // Create user with unverified email first
    let unverified_user = UserData {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        email: "user@example.com".to_string(),
        password_hash: "hash123".to_string(),
        name: Some("Existing User".to_string()),
        picture: None,
        role: "user".to_string(),
        active: true,
        email_verified: false, // Not verified
        created_at: Utc::now(),
        updated_at: Utc::now(),
        attributes: std::collections::HashMap::new(),
    };

    storage
        .store_user(&unverified_user.id, unverified_user.clone())
        .await
        .expect("Failed to create user");

    // Login with Google (verified email)
    let mut google_user_info = create_google_user_info();
    google_user_info.email_verified = Some(true);

    let user_after_google_login = storage
        .get_or_create_federated_user(tenant_id, "google", &google_user_info)
        .await
        .expect("Failed on Google login");

    // Email should now be verified
    assert_eq!(user_after_google_login.id, unverified_user.id);
    assert_eq!(user_after_google_login.email_verified, true);
}

#[tokio::test]
async fn test_delete_federated_identity() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";
    let provider_id = "google";

    let user_info = create_google_user_info();

    // Create federated user
    let _ = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info)
        .await
        .expect("Failed to create federated user");

    // Verify it exists
    let identity = storage
        .get_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to get identity");
    assert!(identity.is_some());

    // Delete it
    storage
        .delete_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to delete identity");

    // Verify it's gone
    let identity_after_delete = storage
        .get_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to get identity");
    assert!(identity_after_delete.is_none());
}

#[tokio::test]
async fn test_profile_data_storage() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";
    let provider_id = "google";

    let user_info = create_google_user_info();

    let _ = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info)
        .await
        .expect("Failed to create federated user");

    let identity = storage
        .get_federated_identity(tenant_id, provider_id, &user_info.provider_user_id)
        .await
        .expect("Failed to get identity")
        .expect("Identity not found");

    // Verify profile data is stored
    assert_eq!(
        identity.provider_profile_data.get("sub").and_then(|v| v.as_str()),
        Some("google-123456")
    );
    assert_eq!(
        identity.provider_profile_data.get("email").and_then(|v| v.as_str()),
        Some("user@example.com")
    );
}

#[tokio::test]
async fn test_store_federated_identity_directly() {
    let storage = MemoryStorage::new();

    let federated_identity = FederatedIdentityData {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: "test-tenant".to_string(),
        user_id: "user-123".to_string(),
        provider_id: "google".to_string(),
        provider_user_id: "google-456".to_string(),
        provider_email: "test@example.com".to_string(),
        provider_email_verified: true,
        provider_profile_data: serde_json::json!({"sub": "google-456"}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: Some(Utc::now()),
    };

    storage
        .store_federated_identity(federated_identity.clone())
        .await
        .expect("Failed to store federated identity");

    let retrieved = storage
        .get_federated_identity("test-tenant", "google", "google-456")
        .await
        .expect("Failed to get identity")
        .expect("Identity not found");

    assert_eq!(retrieved.id, federated_identity.id);
    assert_eq!(retrieved.user_id, "user-123");
    assert_eq!(retrieved.provider_email, "test@example.com");
}

#[tokio::test]
async fn test_different_emails_create_different_users() {
    let storage = MemoryStorage::new();
    let tenant_id = "test-tenant";
    let provider_id = "google";

    // First user
    let user_info_1 = ProviderUserInfo {
        provider_user_id: "google-111".to_string(),
        email: "user1@example.com".to_string(),
        email_verified: Some(true),
        name: Some("User One".to_string()),
        given_name: None,
        family_name: None,
        picture: None,
        preferred_username: None,
        locale: None,
        raw_profile: serde_json::json!({}),
    };

    // Second user (different email)
    let user_info_2 = ProviderUserInfo {
        provider_user_id: "google-222".to_string(),
        email: "user2@example.com".to_string(),
        email_verified: Some(true),
        name: Some("User Two".to_string()),
        given_name: None,
        family_name: None,
        picture: None,
        preferred_username: None,
        locale: None,
        raw_profile: serde_json::json!({}),
    };

    let user_1 = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info_1)
        .await
        .expect("Failed to create user 1");

    let user_2 = storage
        .get_or_create_federated_user(tenant_id, provider_id, &user_info_2)
        .await
        .expect("Failed to create user 2");

    // Should be different users
    assert_ne!(user_1.id, user_2.id);
    assert_eq!(user_1.email, "user1@example.com");
    assert_eq!(user_2.email, "user2@example.com");
}

#[test]
fn test_google_provider_config() {
    let config = FederationProviderConfig {
        provider_type: "google".to_string(),
        provider_id: "google".to_string(),
        client_id: "test-client-id.apps.googleusercontent.com".to_string(),
        client_secret: "test-client-secret".to_string(),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        jwks_uri: None,
        scopes: Some(vec!["openid".to_string(), "profile".to_string(), "email".to_string()]),
        extra: serde_json::json!({}),
    };

    assert_eq!(config.provider_type, "google");
    assert_eq!(config.scopes.as_ref().unwrap().len(), 3);
}

#[test]
fn test_github_provider_config() {
    let config = FederationProviderConfig {
        provider_type: "github".to_string(),
        provider_id: "github".to_string(),
        client_id: "test-github-client-id".to_string(),
        client_secret: "test-github-client-secret".to_string(),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        jwks_uri: None,
        scopes: Some(vec!["read:user".to_string(), "user:email".to_string()]),
        extra: serde_json::json!({}),
    };

    assert_eq!(config.provider_type, "github");
    assert_eq!(config.scopes.as_ref().unwrap().len(), 2);
}
