pub mod jwt;
pub mod oauth2;
pub mod password;
pub mod strategies;

pub use jwt::create_token;
pub use oauth2::{generate_auth_url, handle_oauth2_callback, OAuth2CallbackResult};
pub use password::{hash_password, verify_password};
pub use strategies::{
    create_local_token, create_secret_token, validate_token as validate_strategy_token,
};
