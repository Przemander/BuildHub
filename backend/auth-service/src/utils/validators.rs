//! Input validation utilities.
//!
//! Clean, secure, and thorough validation without over-engineering.

use once_cell::sync::Lazy;
use regex::Regex;
use tracing::warn;

use crate::utils::errors::AuthServiceError;

// =============================================================================
// CONSTANTS
// =============================================================================

const MAX_INPUT_LENGTH: usize = 256;
const MAX_PASSWORD_LENGTH: usize = 128;
const MIN_PASSWORD_LENGTH: usize = 8;
const SPECIAL_CHARS: &str = "@#$%^&+=!*_-";
const MAX_EMAIL_LENGTH: usize = 254;
const MIN_TLD_LENGTH: usize = 2;
const MAX_TLD_LENGTH: usize = 63;

// =============================================================================
// REGEX PATTERNS
// =============================================================================

static USERNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_-]{3,30}$").unwrap());

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap()
});

// =============================================================================
// VALIDATION FUNCTIONS
// =============================================================================

/// Validates username format.
pub fn validate_username(username: &str) -> Result<(), AuthServiceError> {
    if username.is_empty() {
        return Err(AuthServiceError::validation("username", "Username is required"));
    }

    if username.len() > MAX_INPUT_LENGTH {
        warn!("Username too long: {} chars", username.len());
        return Err(AuthServiceError::validation(
            "username",
            format!("Username must be at most {} characters", MAX_INPUT_LENGTH),
        ));
    }

    if !USERNAME_REGEX.is_match(username) {
        return Err(AuthServiceError::validation(
            "username",
            "Username must be 3-30 characters (letters, numbers, underscore, dash)",
        ));
    }

    Ok(())
}

/// Validates email address.
pub fn validate_email(email: &str) -> Result<(), AuthServiceError> {
    if email.is_empty() {
        return Err(AuthServiceError::validation("email", "Email is required"));
    }

    if email.len() > MAX_EMAIL_LENGTH {
        warn!("Email too long: {} chars", email.len());
        return Err(AuthServiceError::validation(
            "email",
            format!("Email must be at most {} characters", MAX_EMAIL_LENGTH),
        ));
    }

    if !EMAIL_REGEX.is_match(email) {
        return Err(AuthServiceError::validation(
            "email",
            "Please provide a valid email address",
        ));
    }

    // Check domain structure
    if let Some(domain) = email.split('@').nth(1) {
        if !domain.contains('.') {
            return Err(AuthServiceError::validation(
                "email",
                "Email domain must contain a dot",
            ));
        }

        if let Some(tld) = domain.split('.').last() {
            if tld.len() < MIN_TLD_LENGTH || tld.len() > MAX_TLD_LENGTH {
                return Err(AuthServiceError::validation(
                    "email",
                    format!(
                        "Domain extension must be {}-{} characters",
                        MIN_TLD_LENGTH, MAX_TLD_LENGTH
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Validates password strength.
pub fn validate_password(password: &str) -> Result<(), AuthServiceError> {
    if password.is_empty() {
        return Err(AuthServiceError::validation(
            "password",
            "Password is required",
        ));
    }

    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(AuthServiceError::validation(
            "password",
            format!("Password must be at least {} characters", MIN_PASSWORD_LENGTH),
        ));
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        warn!("Password too long: {} chars", password.len());
        return Err(AuthServiceError::validation(
            "password",
            format!("Password must be at most {} characters", MAX_PASSWORD_LENGTH),
        ));
    }

    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

    if !has_letter || !has_number || !has_special {
        return Err(AuthServiceError::validation(
            "password",
            format!(
                "Password must contain letters, numbers, and special characters ({})",
                SPECIAL_CHARS
            ),
        ));
    }

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        // Valid
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("abc").is_ok());
        assert!(validate_username(&"a".repeat(30)).is_ok());

        // Invalid
        assert!(validate_username("").is_err());
        assert!(validate_username("ab").is_err());
        assert!(validate_username(&"a".repeat(31)).is_err());
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username(&"a".repeat(257)).is_err());
    }

    #[test]
    fn test_email_validation() {
        // Valid
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@example.co.uk").is_ok());
        assert!(validate_email("user+tag@sub.domain.com").is_ok());

        // Invalid
        assert!(validate_email("").is_err());
        assert!(validate_email("user").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@domain").is_err());
        assert!(validate_email("user@domain.x").is_err());
        assert!(validate_email(&format!("{}@example.com", "a".repeat(250))).is_err());
    }

    #[test]
    fn test_password_validation() {
        // Valid
        assert!(validate_password("Pass123!").is_ok());
        assert!(validate_password("SecureP@ss1").is_ok());
        assert!(validate_password("Test#123456").is_ok());

        // Invalid
        assert!(validate_password("").is_err());
        assert!(validate_password("short1!").is_err());
        assert!(validate_password("NoNumbers!").is_err());
        assert!(validate_password("NoSpecial123").is_err());
        assert!(validate_password("12345678!").is_err());
        assert!(validate_password(&"a".repeat(129)).is_err());
    }

    #[test]
    fn test_error_messages() {
        // Check that error messages are user-friendly
        let err = validate_username("ab").unwrap_err();
        assert!(err.to_string().contains("3-30 characters"));

        let err = validate_email("invalid").unwrap_err();
        assert!(err.to_string().contains("valid email"));

        let err = validate_password("weak").unwrap_err();
        assert!(err.to_string().contains("at least 8"));
    }
}