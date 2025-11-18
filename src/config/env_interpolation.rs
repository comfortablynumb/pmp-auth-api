use regex::Regex;
use std::env;

/// Interpolates environment variables in a string.
///
/// Supports the following syntax:
/// - `${env:VAR_NAME}` - Required environment variable (fails if not set)
/// - `${env:VAR_NAME:default_value}` - Optional with default value
///
/// # Examples
///
/// ```
/// std::env::set_var("MY_VAR", "hello");
/// let result = interpolate_env_vars("Value is ${env:MY_VAR}").unwrap();
/// assert_eq!(result, "Value is hello");
///
/// let result = interpolate_env_vars("Value is ${env:MISSING:default}").unwrap();
/// assert_eq!(result, "Value is default");
/// ```
pub fn interpolate_env_vars(input: &str) -> Result<String, String> {
    // Regex to match ${env:VAR_NAME} or ${env:VAR_NAME:default}
    let re = Regex::new(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*?)(?::([^}]*))?\}").unwrap();

    let mut result = input.to_string();
    let mut errors = Vec::new();

    // Find all matches and replace them
    for cap in re.captures_iter(input) {
        let full_match = cap.get(0).unwrap().as_str();
        let var_name = cap.get(1).unwrap().as_str();
        let default_value = cap.get(2).map(|m| m.as_str());

        match env::var(var_name) {
            Ok(value) => {
                result = result.replace(full_match, &value);
            }
            Err(_) => {
                if let Some(default) = default_value {
                    result = result.replace(full_match, default);
                } else {
                    errors.push(format!(
                        "Environment variable '{}' is not set and no default value provided",
                        var_name
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_with_set_env_var() {
        env::set_var("TEST_VAR_1", "test_value");
        let result = interpolate_env_vars("host: ${env:TEST_VAR_1}").unwrap();
        assert_eq!(result, "host: test_value");
        env::remove_var("TEST_VAR_1");
    }

    #[test]
    fn test_interpolate_with_default() {
        env::remove_var("TEST_VAR_MISSING");
        let result = interpolate_env_vars("host: ${env:TEST_VAR_MISSING:localhost}").unwrap();
        assert_eq!(result, "host: localhost");
    }

    #[test]
    fn test_interpolate_missing_without_default() {
        env::remove_var("TEST_VAR_REQUIRED");
        let result = interpolate_env_vars("host: ${env:TEST_VAR_REQUIRED}");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TEST_VAR_REQUIRED"));
    }

    #[test]
    fn test_interpolate_multiple_vars() {
        env::set_var("HOST", "example.com");
        env::set_var("PORT", "8080");
        let result = interpolate_env_vars("url: ${env:HOST}:${env:PORT}").unwrap();
        assert_eq!(result, "url: example.com:8080");
        env::remove_var("HOST");
        env::remove_var("PORT");
    }

    #[test]
    fn test_interpolate_with_complex_default() {
        env::remove_var("DATABASE_URL");
        let result = interpolate_env_vars(
            "url: ${env:DATABASE_URL:postgresql://user:pass@localhost:5432/db}",
        )
        .unwrap();
        assert_eq!(result, "url: postgresql://user:pass@localhost:5432/db");
    }

    #[test]
    fn test_no_interpolation_needed() {
        let result = interpolate_env_vars("plain text without variables").unwrap();
        assert_eq!(result, "plain text without variables");
    }

    #[test]
    fn test_empty_default_value() {
        env::remove_var("EMPTY_VAR");
        let result = interpolate_env_vars("value: ${env:EMPTY_VAR:}").unwrap();
        assert_eq!(result, "value: ");
    }
}
