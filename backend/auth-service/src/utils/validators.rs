//! Input validation utilities.
//!
//! Clean, secure, and thorough validation without over-engineering.

use regex::Regex;
use std::sync::LazyLock;
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

static USERNAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]{3,30}$").unwrap());

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap()
});

// =============================================================================
// INITIALIZATION
// =============================================================================

/// Initializes all lazy static validators.
///
/// Call this once at application startup to eagerly compile all regex patterns,
/// avoiding a performance penalty on the first validation request.
pub fn init() {
    LazyLock::force(&USERNAME_REGEX);
    LazyLock::force(&EMAIL_REGEX);
}

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

    // =========================================================================
    // USERNAME VALIDATION TESTS
    // =========================================================================

    #[test]
    fn test_username_valid_cases() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("abc").is_ok());
        assert!(validate_username(&"a".repeat(30)).is_ok());
        assert!(validate_username("User123").is_ok());
        assert!(validate_username("ABC").is_ok());
        assert!(validate_username("a_b-c").is_ok());
    }

    #[test]
    fn test_username_empty() {
        let result = validate_username("");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "username");
                assert!(message.contains("required"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_username_too_short() {
        let result = validate_username("ab");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "username");
                assert!(message.contains("3-30"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_username_too_long() {
        let result = validate_username(&"a".repeat(31));
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, .. }) => {
                assert_eq!(field, "username");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_username_exceeds_max_input_length() {
        let result = validate_username(&"a".repeat(257));
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "username");
                assert!(message.contains("256"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_username_invalid_characters() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user.name").is_err());
        assert!(validate_username("user#name").is_err());
        assert!(validate_username("user!name").is_err());
        assert!(validate_username("user$name").is_err());
    }

    #[test]
    fn test_username_boundary_cases() {
        // Exactly 3 chars (minimum)
        assert!(validate_username("abc").is_ok());
        // Exactly 30 chars (maximum)
        assert!(validate_username(&"a".repeat(30)).is_ok());
        // 2 chars (below minimum)
        assert!(validate_username("ab").is_err());
    }

    // =========================================================================
    // EMAIL VALIDATION TESTS
    // =========================================================================

    #[test]
    fn test_email_valid_cases() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@example.co.uk").is_ok());
        assert!(validate_email("user+tag@sub.domain.com").is_ok());
        assert!(validate_email("user_name@example.com").is_ok());
        assert!(validate_email("123@example.com").is_ok());
        assert!(validate_email("user@sub1.sub2.example.com").is_ok());
    }

    #[test]
    fn test_email_empty() {
        let result = validate_email("");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "email");
                assert!(message.contains("required"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_email_too_long() {
        let result = validate_email(&format!("{}@example.com", "a".repeat(250)));
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "email");
                assert!(message.contains("254"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_email_invalid_format() {
        assert!(validate_email("user").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@@example.com").is_err());
        assert!(validate_email("user@example").is_err());
    }

    #[test]
    fn test_email_missing_dot_in_domain() {
        let result = validate_email("user@example");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "email");
                assert!(message.contains("dot") || message.contains("valid"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_email_tld_too_short() {
        let result = validate_email("user@domain.x");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "email");
                assert!(message.contains("2-63"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_email_tld_too_long() {
        let tld = "a".repeat(64);
        let result = validate_email(&format!("user@domain.{}", tld));
        assert!(result.is_err());
        // The error could be either about TLD length or invalid format from regex
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "email");
                // Accept either error message since regex might reject it first
                assert!(
                    message.contains("2-63") || message.contains("valid email"),
                    "Expected TLD length or format error, got: {}",
                    message
                );
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_email_boundary_cases() {
        // Valid TLD lengths
        assert!(validate_email("user@domain.co").is_ok()); // 2 chars
        assert!(validate_email("user@domain.com").is_ok()); // 3 chars
        assert!(validate_email(&format!("user@domain.{}", "a".repeat(63))).is_ok()); // 63 chars
        
        // Invalid TLD lengths
        assert!(validate_email("user@domain.a").is_err()); // 1 char
        assert!(validate_email(&format!("user@domain.{}", "a".repeat(64))).is_err()); // 64 chars
    }

    // =========================================================================
    // PASSWORD VALIDATION TESTS
    // =========================================================================

    #[test]
    fn test_password_valid_cases() {
        assert!(validate_password("Pass123!").is_ok());
        assert!(validate_password("SecureP@ss1").is_ok());
        assert!(validate_password("Test#123456").is_ok());
        assert!(validate_password("Abc123@def").is_ok());
        assert!(validate_password(&format!("{}1a@", "A".repeat(125))).is_ok());
    }

    #[test]
    fn test_password_empty() {
        let result = validate_password("");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "password");
                assert!(message.contains("required"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_password_too_short() {
        let result = validate_password("short1!");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "password");
                assert!(message.contains("at least 8"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_password_too_long() {
        let result = validate_password(&format!("{}1a@", "A".repeat(126)));
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "password");
                assert!(message.contains("at most 128"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_password_missing_letter() {
        let result = validate_password("12345678!");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "password");
                assert!(message.contains("letters"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_password_missing_number() {
        let result = validate_password("NoNumbers!");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "password");
                assert!(message.contains("numbers"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_password_missing_special() {
        let result = validate_password("NoSpecial123");
        assert!(result.is_err());
        match result {
            Err(AuthServiceError::Validation { field, message }) => {
                assert_eq!(field, "password");
                assert!(message.contains("special"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_password_all_special_chars() {
        // Test all allowed special characters
        for special in SPECIAL_CHARS.chars() {
            let password = format!("Pass123{}", special);
            assert!(
                validate_password(&password).is_ok(),
                "Password with '{}' should be valid",
                special
            );
        }
    }

    #[test]
    fn test_password_boundary_cases() {
        // Exactly 8 chars (minimum)
        assert!(validate_password("Pass123!").is_ok());
        // Exactly 128 chars (maximum)
        assert!(validate_password(&format!("{}1a@", "A".repeat(125))).is_ok());
        // 7 chars (below minimum)
        assert!(validate_password("Pas123!").is_err());
        // 129 chars (above maximum)
        assert!(validate_password(&format!("{}1a@", "A".repeat(126))).is_err());
    }

    // =========================================================================
    // ERROR MESSAGE TESTS
    // =========================================================================

    #[test]
    fn test_error_messages_are_user_friendly() {
        let err = validate_username("ab").unwrap_err();
        assert!(err.to_string().contains("3-30 characters"));

        let err = validate_email("invalid").unwrap_err();
        assert!(err.to_string().contains("valid email"));

        let err = validate_password("weak").unwrap_err();
        assert!(err.to_string().contains("at least 8"));
    }

    #[test]
    fn test_validation_error_structure() {
        let err = validate_username("a").unwrap_err();
        match err {
            AuthServiceError::Validation { field, message } => {
                assert_eq!(field, "username");
                assert!(!message.is_empty());
            }
            _ => panic!("Expected Validation error"),
        }
    }

    // =========================================================================
    // INITIALIZATION TEST
    // =========================================================================

    #[test]
    fn test_init_compiles_regex() {
        // This test ensures init() doesn't panic
        init();
        // Verify regex patterns work after init
        assert!(USERNAME_REGEX.is_match("user123"));
        assert!(EMAIL_REGEX.is_match("user@example.com"));
    }

    // =========================================================================
    // REGEX PATTERN TESTS
    // =========================================================================

    #[test]
    fn test_username_regex_edge_cases() {
        assert!(USERNAME_REGEX.is_match("abc"));
        assert!(USERNAME_REGEX.is_match(&"a".repeat(30)));
        assert!(!USERNAME_REGEX.is_match("ab"));
        assert!(!USERNAME_REGEX.is_match(&"a".repeat(31)));
        assert!(!USERNAME_REGEX.is_match("user@name"));
    }

    #[test]
    fn test_email_regex_edge_cases() {
        assert!(EMAIL_REGEX.is_match("a@b.co"));
        assert!(EMAIL_REGEX.is_match("test+tag@domain.com"));
        assert!(!EMAIL_REGEX.is_match("@domain.com"));
        assert!(!EMAIL_REGEX.is_match("user@"));
        assert!(!EMAIL_REGEX.is_match("user"));
    }
}