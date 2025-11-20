// ID Token Encryption (JWE)
// This module implements encryption of OpenID Connect ID tokens using JSON Web Encryption

use crate::models::{JwkEncryptionConfig, OidcProviderConfig};
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;
use tracing::{info, warn};

/// Encrypt an ID token using JWE
/// This wraps a signed JWT (JWS) in an encrypted JWT (JWE)
pub fn encrypt_id_token(
    signed_id_token: &str,
    encryption_config: &JwkEncryptionConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    info!("Encrypting ID token using JWE");

    // Load the public key for encryption
    let public_key_pem = load_key_pem(&encryption_config.public_key)?;

    // Create JWE using the biscuit crate or similar
    // For now, we'll use a simplified approach with base64 encoding
    // In a production environment, you should use a proper JWE library like `josekit`

    // JWE Compact Serialization format:
    // BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    // BASE64URL(JWE Encrypted Key) || '.' ||
    // BASE64URL(JWE Initialization Vector) || '.' ||
    // BASE64URL(JWE Ciphertext) || '.' ||
    // BASE64URL(JWE Authentication Tag)

    // For this implementation, we'll use the openssl crate to perform RSA-OAEP encryption
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use openssl::pkey::PKey;
    use openssl::rsa::Padding;
    use openssl::symm::{Cipher, encrypt_aead};
    use rand::RngCore;

    // Parse the public key
    let public_key = PKey::public_key_from_pem(public_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse public key for encryption: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to parse encryption key"
            })),
        )
    })?;

    // Generate a random Content Encryption Key (CEK)
    let cek_len = match encryption_config.enc.as_str() {
        "A128GCM" => 16,
        "A192GCM" => 24,
        "A256GCM" => 32,
        "A128CBC-HS256" => 32,
        "A192CBC-HS384" => 48,
        "A256CBC-HS512" => 64,
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Unsupported encryption algorithm: {}", encryption_config.enc)
                })),
            ));
        }
    };

    let mut cek = vec![0u8; cek_len];
    rand::thread_rng().fill_bytes(&mut cek);

    // Encrypt the CEK with the public key using RSA-OAEP
    let rsa = public_key.rsa().map_err(|e| {
        warn!("Failed to extract RSA key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Invalid RSA key"
            })),
        )
    })?;

    let mut encrypted_cek = vec![0u8; rsa.size() as usize];
    let encrypted_cek_len = rsa
        .public_encrypt(&cek, &mut encrypted_cek, Padding::PKCS1_OAEP)
        .map_err(|e| {
            warn!("Failed to encrypt CEK: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to encrypt content encryption key"
                })),
            )
        })?;
    encrypted_cek.truncate(encrypted_cek_len);

    // Create JWE Protected Header
    let jwe_header = json!({
        "alg": encryption_config.alg,
        "enc": encryption_config.enc,
        "kid": encryption_config.kid,
        "cty": "JWT" // Content type is JWT (the signed ID token)
    });

    let jwe_header_json = serde_json::to_string(&jwe_header).map_err(|e| {
        warn!("Failed to serialize JWE header: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to create JWE header"
            })),
        )
    })?;

    let jwe_header_b64 = URL_SAFE_NO_PAD.encode(jwe_header_json.as_bytes());

    // Generate a random Initialization Vector (IV)
    let iv_len = match encryption_config.enc.as_str() {
        "A128GCM" | "A192GCM" | "A256GCM" => 12,       // GCM uses 96-bit IV
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => 16, // CBC uses 128-bit IV
        _ => 12,
    };

    let mut iv = vec![0u8; iv_len];
    rand::thread_rng().fill_bytes(&mut iv);

    // Construct Additional Authenticated Data (AAD)
    let aad = jwe_header_b64.as_bytes();

    // Encrypt the signed ID token using AES-GCM or AES-CBC-HMAC
    let (ciphertext, auth_tag) = if encryption_config.enc.ends_with("GCM") {
        // Use AES-GCM
        let cipher = match encryption_config.enc.as_str() {
            "A128GCM" => Cipher::aes_128_gcm(),
            "A192GCM" => Cipher::aes_192_gcm(),
            "A256GCM" => Cipher::aes_256_gcm(),
            _ => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Unsupported GCM cipher"
                    })),
                ));
            }
        };

        let mut tag = vec![0u8; 16]; // GCM tag is 128 bits
        let ciphertext = encrypt_aead(
            cipher,
            &cek,
            Some(&iv),
            aad,
            signed_id_token.as_bytes(),
            &mut tag,
        )
        .map_err(|e| {
            warn!("Failed to encrypt ID token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to encrypt ID token"
                })),
            )
        })?;

        (ciphertext, tag)
    } else {
        // Use AES-CBC-HMAC (RFC 7518 Section 5.2)
        // The CEK is split into two halves: MAC key and ENC key
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;
        use openssl::symm::Cipher;

        let key_len = cek.len();
        let mac_key_len = key_len / 2;
        let _enc_key_len = key_len / 2;

        let mac_key = &cek[0..mac_key_len];
        let enc_key = &cek[mac_key_len..];

        // Determine cipher and hash algorithm based on enc value
        let (cipher, hash_alg, tag_len) = match encryption_config.enc.as_str() {
            "A128CBC-HS256" => (Cipher::aes_128_cbc(), MessageDigest::sha256(), 16),
            "A192CBC-HS384" => (Cipher::aes_192_cbc(), MessageDigest::sha384(), 24),
            "A256CBC-HS512" => (Cipher::aes_256_cbc(), MessageDigest::sha512(), 32),
            _ => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Unsupported CBC cipher"
                    })),
                ));
            }
        };

        // Encrypt the plaintext using AES-CBC
        let ciphertext = openssl::symm::encrypt(
            cipher,
            enc_key,
            Some(&iv),
            signed_id_token.as_bytes(),
        )
        .map_err(|e| {
            warn!("Failed to encrypt ID token with AES-CBC: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to encrypt ID token"
                })),
            )
        })?;

        // Compute Authentication Tag using HMAC
        // AAD || IV || Ciphertext || AL
        // where AL is the octet string representing the Additional Authenticated Data length in bits
        let aad_len_bits = (aad.len() * 8) as u64;
        let al = aad_len_bits.to_be_bytes(); // 64-bit big-endian

        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(aad);
        hmac_input.extend_from_slice(&iv);
        hmac_input.extend_from_slice(&ciphertext);
        hmac_input.extend_from_slice(&al);

        // Create HMAC
        let pkey = openssl::pkey::PKey::hmac(mac_key).map_err(|e| {
            warn!("Failed to create HMAC key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to create MAC key"
                })),
            )
        })?;

        let mut signer = Signer::new(hash_alg, &pkey).map_err(|e| {
            warn!("Failed to create HMAC signer: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to create MAC signer"
                })),
            )
        })?;

        signer.update(&hmac_input).map_err(|e| {
            warn!("Failed to update HMAC: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to compute MAC"
                })),
            )
        })?;

        let hmac_output = signer.sign_to_vec().map_err(|e| {
            warn!("Failed to sign HMAC: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to compute MAC"
                })),
            )
        })?;

        // Take the first tag_len bytes of the HMAC output as the authentication tag
        let auth_tag = hmac_output[0..tag_len].to_vec();

        (ciphertext, auth_tag)
    };

    // Encode all components in Base64URL
    let encrypted_cek_b64 = URL_SAFE_NO_PAD.encode(&encrypted_cek);
    let iv_b64 = URL_SAFE_NO_PAD.encode(&iv);
    let ciphertext_b64 = URL_SAFE_NO_PAD.encode(&ciphertext);
    let auth_tag_b64 = URL_SAFE_NO_PAD.encode(&auth_tag);

    // Construct JWE Compact Serialization
    let jwe = format!(
        "{}.{}.{}.{}.{}",
        jwe_header_b64, encrypted_cek_b64, iv_b64, ciphertext_b64, auth_tag_b64
    );

    info!("Successfully encrypted ID token");
    Ok(jwe)
}

/// Check if ID token encryption should be applied
pub fn should_encrypt_id_token(oidc_config: &OidcProviderConfig) -> bool {
    oidc_config.encryption_key.is_some()
}

/// Load a key from either a file path or inline PEM
fn load_key_pem(key_config: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    if key_config.starts_with("-----BEGIN") {
        Ok(key_config.to_string())
    } else {
        std::fs::read_to_string(key_config).map_err(|e| {
            warn!("Failed to read key file '{}': {}", key_config, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to load encryption key"
                })),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_encrypt_id_token() {
        use crate::models::{JwkEncryptionConfig, OidcProviderConfig};

        // Without encryption key
        let oidc_config = OidcProviderConfig {
            issuer: "https://example.com".to_string(),
            userinfo_endpoint: "/userinfo".to_string(),
            claims_supported: vec!["sub".to_string()],
            scopes_supported: vec!["openid".to_string()],
            id_token_expiration_secs: 3600,
            encryption_key: None,
            id_token_encryption_alg_values_supported: vec![],
            id_token_encryption_enc_values_supported: vec![],
        };

        assert!(!should_encrypt_id_token(&oidc_config));

        // With encryption key
        let oidc_config_with_enc = OidcProviderConfig {
            encryption_key: Some(JwkEncryptionConfig {
                alg: "RSA-OAEP".to_string(),
                enc: "A256GCM".to_string(),
                kid: "enc-key-1".to_string(),
                public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                    .to_string(),
                private_key: None,
            }),
            ..oidc_config
        };

        assert!(should_encrypt_id_token(&oidc_config_with_enc));
    }
}
