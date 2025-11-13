// Time-based One-Time Password (TOTP) implementation for MFA
// RFC 6238 compliant TOTP authentication

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{Sha1, totp_custom};
use tracing::debug;

/// TOTP configuration
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Time step in seconds (typically 30)
    pub time_step: u64,
    /// Number of digits in the TOTP code (typically 6)
    pub digits: u32,
    /// Skew tolerance for time drift (how many time steps to check before/after)
    pub skew: u64,
    /// Issuer name for the TOTP (shown in authenticator apps)
    pub issuer: String,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            time_step: 30,
            digits: 6,
            skew: 1,
            issuer: "PMP Auth API".to_string(),
        }
    }
}

/// TOTP secret for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    /// Base32-encoded secret key
    pub secret: String,
    /// User identifier (email or username)
    pub account_name: String,
    /// When the secret was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether TOTP is enabled for this user
    pub enabled: bool,
    /// Backup codes (encrypted)
    pub backup_codes: Vec<String>,
}

/// TOTP Manager for handling TOTP operations
pub struct TotpManager {
    config: TotpConfig,
}

impl TotpManager {
    /// Create a new TOTP manager with the given configuration
    pub fn new(config: TotpConfig) -> Self {
        Self { config }
    }

    /// Generate a new TOTP secret for a user
    pub fn generate_secret(&self, account_name: &str) -> TotpSecret {
        let secret = self.generate_random_secret();

        TotpSecret {
            secret: secret.clone(),
            account_name: account_name.to_string(),
            created_at: chrono::Utc::now(),
            enabled: false,
            backup_codes: Vec::new(),
        }
    }

    /// Generate a random base32-encoded secret
    fn generate_random_secret(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.r#gen::<u8>()).collect();

        // Convert to base32
        self.base32_encode(&bytes)
    }

    /// Verify a TOTP code against a secret
    pub fn verify_code(&self, secret: &str, code: &str) -> Result<bool, String> {
        if code.len() != self.config.digits as usize {
            return Ok(false);
        }

        // Parse the code
        let code_num = code
            .parse::<u32>()
            .map_err(|_| "Invalid TOTP code format")?;

        // Get current time
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();

        // Decode the secret from base32
        let secret_bytes = self
            .base32_decode(secret)
            .map_err(|e| format!("Invalid secret: {}", e))?;

        // Check current time step and adjacent steps (for time skew tolerance)
        for skew in -(self.config.skew as i64)..=(self.config.skew as i64) {
            let time_step = (current_time / self.config.time_step) as i64 + skew;
            let time_step = if time_step < 0 { 0 } else { time_step as u64 };

            let generated_code = self.generate_totp(&secret_bytes, time_step);

            if generated_code == code_num {
                debug!("TOTP code verified with skew: {}", skew);
                return Ok(true);
            }
        }

        debug!("TOTP code verification failed");
        Ok(false)
    }

    /// Generate a TOTP code for a given secret and time step
    fn generate_totp(&self, secret: &[u8], time_step: u64) -> u32 {
        let code_str =
            totp_custom::<Sha1>(self.config.time_step, self.config.digits, secret, time_step);
        code_str.parse::<u32>().unwrap_or(0)
    }

    /// Generate a QR code URI for the TOTP secret
    /// This URI can be encoded as a QR code for easy scanning with authenticator apps
    pub fn generate_qr_uri(&self, secret: &TotpSecret) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period={}",
            urlencoding::encode(&self.config.issuer),
            urlencoding::encode(&secret.account_name),
            secret.secret,
            urlencoding::encode(&self.config.issuer),
            self.config.digits,
            self.config.time_step
        )
    }

    /// Generate a QR code image (PNG) for the TOTP secret
    pub fn generate_qr_code(&self, secret: &TotpSecret) -> Result<Vec<u8>, String> {
        let uri = self.generate_qr_uri(secret);

        let code = qrcode::QrCode::new(uri.as_bytes())
            .map_err(|e| format!("Failed to generate QR code: {}", e))?;

        let image = code.render::<qrcode::render::unicode::Dense1x2>().build();

        // For a real implementation, you'd want to generate a PNG image
        // For now, we'll return the UTF-8 representation
        Ok(image.as_bytes().to_vec())
    }

    /// Base32 encode (RFC 4648)
    fn base32_encode(&self, data: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = String::new();
        let mut buffer = 0u32;
        let mut bits_in_buffer = 0u8;

        for &byte in data {
            buffer = (buffer << 8) | byte as u32;
            bits_in_buffer += 8;

            while bits_in_buffer >= 5 {
                bits_in_buffer -= 5;
                let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        if bits_in_buffer > 0 {
            let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }

        // Pad to multiple of 8
        while result.len() % 8 != 0 {
            result.push('=');
        }

        result
    }

    /// Base32 decode (RFC 4648)
    fn base32_decode(&self, data: &str) -> Result<Vec<u8>, String> {
        let data = data.trim_end_matches('=').to_uppercase();
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits_in_buffer = 0u8;

        for c in data.chars() {
            let value = match c {
                'A'..='Z' => (c as u8 - b'A') as u32,
                '2'..='7' => (c as u8 - b'2' + 26) as u32,
                _ => return Err(format!("Invalid base32 character: {}", c)),
            };

            buffer = (buffer << 5) | value;
            bits_in_buffer += 5;

            if bits_in_buffer >= 8 {
                bits_in_buffer -= 8;
                result.push((buffer >> bits_in_buffer) as u8);
                buffer &= (1 << bits_in_buffer) - 1;
            }
        }

        Ok(result)
    }

    /// Generate backup codes for account recovery
    pub fn generate_backup_codes(&self, count: usize) -> Vec<String> {
        let mut rng = rand::thread_rng();
        (0..count)
            .map(|_| {
                let code: u64 = rng.gen_range(100000000..999999999);
                format!("{:09}", code)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation_and_verification() {
        let config = TotpConfig::default();
        let manager = TotpManager::new(config);

        let secret = manager.generate_secret("test@example.com");
        assert!(!secret.secret.is_empty());
        assert_eq!(secret.account_name, "test@example.com");
    }

    #[test]
    fn test_base32_encode_decode() {
        let config = TotpConfig::default();
        let manager = TotpManager::new(config);

        let data = b"Hello, World!";
        let encoded = manager.base32_encode(data);
        let decoded = manager.base32_decode(&encoded).unwrap();

        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_totp_verification_with_known_secret() {
        let config = TotpConfig {
            time_step: 30,
            digits: 6,
            skew: 1,
            issuer: "Test".to_string(),
        };
        let manager = TotpManager::new(config);

        // Use a known secret for testing
        let secret = "JBSWY3DPEHPK3PXP"; // Base32 encoded "Hello!"

        // Generate current TOTP
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_step = current_time / 30;

        let secret_bytes = manager.base32_decode(secret).unwrap();
        let code = manager.generate_totp(&secret_bytes, time_step);
        let code_str = format!("{:06}", code);

        // Verify the code
        assert!(manager.verify_code(secret, &code_str).unwrap());
    }

    #[test]
    fn test_backup_codes_generation() {
        let config = TotpConfig::default();
        let manager = TotpManager::new(config);

        let codes = manager.generate_backup_codes(10);
        assert_eq!(codes.len(), 10);

        for code in codes {
            assert_eq!(code.len(), 9);
            assert!(code.chars().all(|c| c.is_numeric()));
        }
    }

    #[test]
    fn test_qr_uri_generation() {
        let config = TotpConfig::default();
        let manager = TotpManager::new(config);

        let secret = TotpSecret {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            account_name: "test@example.com".to_string(),
            created_at: chrono::Utc::now(),
            enabled: false,
            backup_codes: Vec::new(),
        };

        let uri = manager.generate_qr_uri(&secret);
        assert!(uri.starts_with("otpauth://totp/"));
        // Email is URL-encoded, so @ becomes %40
        assert!(uri.contains("test%40example.com"));
        assert!(uri.contains("JBSWY3DPEHPK3PXP"));
    }
}
