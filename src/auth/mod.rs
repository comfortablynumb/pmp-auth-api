pub mod api_keys;
pub mod device_flow;
pub mod identity_backend;
pub mod jwt;
pub mod oauth2;
pub mod oauth2_server;
pub mod oidc;
pub mod password;
pub mod saml;
pub mod strategies;
pub mod token_introspection;

pub use api_keys::{create_api_key, list_api_keys, revoke_api_key};
pub use device_flow::{device_authorize, device_confirm, device_token, device_verify};
#[allow(unused_imports)]
pub use identity_backend::{create_identity_backend, BackendUser, IdentityBackendTrait};
pub use jwt::create_token;
pub use oauth2_server::{jwks, oauth2_authorize, oauth2_token};
pub use oidc::{oidc_discovery, oidc_userinfo};
pub use password::{hash_password, verify_password};
pub use saml::{saml_metadata, saml_slo, saml_sso_post, saml_sso_redirect};
pub use token_introspection::{token_introspect, token_revoke};
