pub mod jwt;
pub mod oauth2;
pub mod oauth2_server;
pub mod password;
pub mod strategies;

pub use jwt::create_token;
pub use oauth2::{OAuth2CallbackResult, generate_auth_url, handle_oauth2_callback};
pub use oauth2_server::{jwks, oauth2_authorize, oauth2_token};
pub use password::{hash_password, verify_password};
pub use strategies::{
    create_local_token, create_secret_token, validate_token as validate_strategy_token,
};
