use crate::models::Claims;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::env;

const DEFAULT_SECRET: &str = "your-secret-key-change-this-in-production";

fn get_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_string())
}

pub fn create_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = get_secret();
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn validate_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = get_secret();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}
