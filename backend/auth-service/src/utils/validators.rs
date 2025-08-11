//! # Input Validation Utilities for BuildHub Auth Service
//!
//! Enterprise-grade validation with comprehensive observability.
//! Implements defense-in-depth security patterns with performance optimization.
//!
//! ## Features
//! - RFC-compliant email validation
//! - Configurable password strength requirements
//! - Username format validation with security considerations
//! - Generic field validation for extensibility
//! - Full OpenTelemetry tracing integration
//! - Prometheus metrics for monitoring
//! - Structured error handling with context

use crate::metricss::validation_metrics::{field_types, instrument_validation};
use crate::utils::error_new::{AuthServiceError, ValidationError};
use crate::utils::log_new::Log;
use crate::utils::telemetry::business_operation_span;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing_error::SpanTrace;

// =============================================================================
// VALIDATION CONSTANTS
// =============================================================================

/// Maximum allowed length for general input fields
const MAX_INPUT_LENGTH: usize = 256;

/// Maximum allowed password length (prevents DoS attacks)
const MAX_PASSWORD_LENGTH: usize = 128;

/// Minimum required password length for security
const MIN_PASSWORD_LENGTH: usize = 8;

/// Special characters required in passwords
const SPECIAL_CHARS: &str = "@#$%^&+=!*_-";

/// Maximum email length per RFC 5321
const MAX_EMAIL_LENGTH: usize = 254;

/// Minimum TLD length (e.g., .uk)
const MIN_TLD_LENGTH: usize = 2;

/// Maximum TLD length per DNS specifications
const MAX_TLD_LENGTH: usize = 63;

// =============================================================================
// COMPILED REGEX PATTERNS
// =============================================================================

/// Username validation regex: 3-30 chars, alphanumeric + underscore/dash
static USERNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_-]{3,30}$").expect("USERNAME regex compilation failed"));

/// RFC-compliant email validation regex
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).expect("EMAIL regex compilation failed")
});

// =============================================================================
// USER-FRIENDLY ERROR MESSAGES
// =============================================================================

/// Clear error message for username validation failures
const USERNAME_ERROR: &str = "Username must be 3-30 characters long and contain only letters, numbers, underscores, and dashes";

/// Clear error message for password validation failures
const PASSWORD_ERROR: &str = "Password must be at least 8 characters long and include at least one letter, one number, and one special character (@#$%^&+=!*_-)";

/// Clear error message for email validation failures
const EMAIL_ERROR: &str = "Please provide a valid email address";

// =============================================================================
// CORE VALIDATION FUNCTIONS
// =============================================================================

/// Validates username format with comprehensive security checks.
///
/// ## Validation Rules:
/// - Must not be empty
/// - Length: 3-30 characters
/// - Allowed characters: letters, numbers, underscore, dash
/// - Maximum length enforced to prevent DoS
///
/// ## Example:
/// ```rust
/// assert!(validate_username("john_doe").is_ok());
/// assert!(validate_username("user-123").is_ok());
/// assert!(validate_username("a").is_err()); // Too short
/// ```
#[inline]
pub fn validate_username(username: &str) -> Result<(), AuthServiceError> {
    let span = business_operation_span("validate_username");
    span.record("field", &field_types::USERNAME);
    span.record("input_length", &username.len());

    span.in_scope(|| {
        instrument_validation(field_types::USERNAME, || {
            // Check if empty
            if username.is_empty() {
                span.record("result", &"failure");
                span.record("failure_reason", &"missing");

                return Err(ValidationError::MissingField {
                    field: field_types::USERNAME.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Check length constraints
            if username.len() > MAX_INPUT_LENGTH {
                // Log potential abuse attempt
                Log::event(
                    "WARN",
                    "Validation",
                    &format!(
                        "Username length {} exceeds maximum {}",
                        username.len(),
                        MAX_INPUT_LENGTH
                    ),
                    "username_too_long",
                    "validate_username",
                );

                span.record("result", &"failure");
                span.record("failure_reason", &"too_long");
                span.record("max_allowed_length", &MAX_INPUT_LENGTH);

                return Err(ValidationError::TooLong {
                    field: field_types::USERNAME.to_string(),
                    max_length: MAX_INPUT_LENGTH,
                    span: SpanTrace::capture(),
                });
            }

            // Validate format
            if USERNAME_REGEX.is_match(username) {
                span.record("result", &"success");
                Ok(())
            } else {
                span.record("result", &"failure");
                span.record("failure_reason", &"invalid_format");

                Err(ValidationError::InvalidValue {
                    field: field_types::USERNAME.to_string(),
                    message: USERNAME_ERROR.to_string(),
                    span: SpanTrace::capture(),
                })
            }
        })
    })
}

/// Validates email address with RFC compliance and security checks.
///
/// ## Validation Rules:
/// - Must not be empty
/// - Maximum length: 254 characters (RFC 5321)
/// - Must match RFC-compliant regex pattern
/// - Domain must contain at least one dot
/// - TLD must be 2-63 characters
///
/// ## Example:
/// ```rust
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("test.user+tag@sub.domain.com").is_ok());
/// assert!(validate_email("invalid@").is_err());
/// ```
#[inline]
pub fn validate_email(email: &str) -> Result<(), AuthServiceError> {
    let span = business_operation_span("validate_email");
    span.record("field", &field_types::EMAIL);
    span.record("input_length", &email.len());

    // Extract and record domain for observability (privacy-safe)
    if let Some(at_pos) = email.find('@') {
        if let Some(domain) = email.get(at_pos + 1..) {
            span.record("email_domain", &domain);
        }
    }

    span.in_scope(|| {
        instrument_validation(field_types::EMAIL, || {
            // Check if empty
            if email.is_empty() {
                span.record("result", &"failure");
                span.record("failure_reason", &"missing");

                return Err(ValidationError::MissingField {
                    field: field_types::EMAIL.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Check length constraints
            if email.len() > MAX_EMAIL_LENGTH {
                Log::event(
                    "WARN",
                    "Validation",
                    &format!(
                        "Email length {} exceeds RFC limit {}",
                        email.len(),
                        MAX_EMAIL_LENGTH
                    ),
                    "email_too_long",
                    "validate_email",
                );

                span.record("result", &"failure");
                span.record("failure_reason", &"too_long");
                span.record("max_allowed_length", &MAX_EMAIL_LENGTH);

                return Err(ValidationError::TooLong {
                    field: field_types::EMAIL.to_string(),
                    max_length: MAX_EMAIL_LENGTH,
                    span: SpanTrace::capture(),
                });
            }

            // Validate basic format
            if !EMAIL_REGEX.is_match(email) {
                span.record("result", &"failure");
                span.record("failure_reason", &"invalid_format");

                return Err(ValidationError::InvalidValue {
                    field: field_types::EMAIL.to_string(),
                    message: EMAIL_ERROR.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Advanced domain validation
            let parts: Vec<&str> = email.split('@').collect();
            if parts.len() != 2 {
                // This should never happen if regex passed, log as internal error
                Log::event(
                    "ERROR",
                    "Validation",
                    "Email regex inconsistency detected",
                    "internal_validation_error",
                    "validate_email",
                );

                span.record("result", &"failure");
                span.record("failure_reason", &"internal_error");

                return Err(ValidationError::InvalidValue {
                    field: field_types::EMAIL.to_string(),
                    message: EMAIL_ERROR.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            let domain = parts[1];

            // Check for dot in domain
            if !domain.contains('.') {
                span.record("result", &"failure");
                span.record("failure_reason", &"missing_domain_dot");

                return Err(ValidationError::InvalidValue {
                    field: field_types::EMAIL.to_string(),
                    message: "Email domain must contain at least one dot".to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Validate TLD length
            if let Some(tld) = domain.split('.').last() {
                span.record("tld_length", &tld.len());

                if tld.len() < MIN_TLD_LENGTH || tld.len() > MAX_TLD_LENGTH {
                    span.record("result", &"failure");
                    span.record("failure_reason", &"invalid_tld_length");

                    return Err(ValidationError::InvalidValue {
                        field: field_types::EMAIL.to_string(),
                        message: format!(
                            "Email domain extension must be {}-{} characters",
                            MIN_TLD_LENGTH, MAX_TLD_LENGTH
                        ),
                        span: SpanTrace::capture(),
                    });
                }
            }

            span.record("result", &"success");
            Ok(())
        })
    })
}

/// Validates password strength with configurable requirements.
///
/// ## Validation Rules:
/// - Must not be empty
/// - Minimum length: 8 characters
/// - Maximum length: 128 characters
/// - Must contain at least one letter
/// - Must contain at least one number
/// - Must contain at least one special character
///
/// ## Security Note:
/// Password content is never logged or recorded in spans for security.
///
/// ## Example:
/// ```rust
/// assert!(validate_password("SecureP@ss123").is_ok());
/// assert!(validate_password("weak").is_err()); // Too short
/// assert!(validate_password("NoNumbers!").is_err()); // Missing number
/// ```
#[inline]
pub fn validate_password(password: &str) -> Result<(), AuthServiceError> {
    let span = business_operation_span("validate_password");
    span.record("field", &field_types::PASSWORD);
    // Security: Only record length, never the actual password
    span.record("input_length", &password.len());

    span.in_scope(|| {
        instrument_validation(field_types::PASSWORD, || {
            // Check if empty
            if password.is_empty() {
                span.record("result", &"failure");
                span.record("failure_reason", &"missing");

                return Err(ValidationError::MissingField {
                    field: field_types::PASSWORD.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Check minimum length
            if password.len() < MIN_PASSWORD_LENGTH {
                span.record("result", &"failure");
                span.record("failure_reason", &"too_short");
                span.record("min_required_length", &MIN_PASSWORD_LENGTH);

                return Err(ValidationError::InvalidValue {
                    field: field_types::PASSWORD.to_string(),
                    message: PASSWORD_ERROR.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Check maximum length
            if password.len() > MAX_PASSWORD_LENGTH {
                Log::event(
                    "WARN",
                    "Validation",
                    &format!(
                        "Password length {} exceeds maximum {}",
                        password.len(),
                        MAX_PASSWORD_LENGTH
                    ),
                    "password_too_long",
                    "validate_password",
                );

                span.record("result", &"failure");
                span.record("failure_reason", &"too_long");
                span.record("max_allowed_length", &MAX_PASSWORD_LENGTH);

                return Err(ValidationError::TooLong {
                    field: field_types::PASSWORD.to_string(),
                    max_length: MAX_PASSWORD_LENGTH,
                    span: SpanTrace::capture(),
                });
            }

            // Check complexity requirements
            let has_letter = password.chars().any(|c| c.is_alphabetic());
            let has_number = password.chars().any(|c| c.is_numeric());
            let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

            // Record complexity analysis (privacy-safe)
            span.record("has_letter", &has_letter);
            span.record("has_number", &has_number);
            span.record("has_special", &has_special);

            if !has_letter || !has_number || !has_special {
                span.record("result", &"failure");
                span.record("failure_reason", &"insufficient_complexity");

                return Err(ValidationError::InvalidValue {
                    field: field_types::PASSWORD.to_string(),
                    message: PASSWORD_ERROR.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            span.record("result", &"success");
            Ok(())
        })
    })
}

/// Validates a generic field with customizable constraints.
///
/// This function provides a flexible validation framework for custom fields.
///
/// ## Parameters:
/// - `field_name`: Name of the field being validated
/// - `value`: The value to validate
/// - `min_length`: Minimum allowed length
/// - `max_length`: Maximum allowed length
/// - `regex`: Optional regex pattern for format validation
/// - `custom_error`: Error message to display on validation failure
///
/// ## Example:
/// ```rust
/// let phone_regex = Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap();
/// validate_generic_field(
///     "phone",
///     "+1234567890",
///     10,
///     15,
///     Some(&phone_regex),
///     "Invalid phone number format"
/// ).unwrap();
/// ```
#[allow(dead_code)]
pub fn validate_generic_field(
    field_name: &str,
    value: &str,
    min_length: usize,
    max_length: usize,
    regex: Option<&Regex>,
    custom_error: &str,
) -> Result<(), AuthServiceError> {
    let span = business_operation_span("validate_generic_field");
    span.record("field", &field_name);
    span.record("input_length", &value.len());
    span.record("min_length", &min_length);
    span.record("max_length", &max_length);
    span.record("has_regex", &regex.is_some());

    span.in_scope(|| {
        instrument_validation(field_name, || {
            // Check if empty when required
            if value.is_empty() && min_length > 0 {
                span.record("result", &"failure");
                span.record("failure_reason", &"missing");

                return Err(ValidationError::MissingField {
                    field: field_name.to_string(),
                    span: SpanTrace::capture(),
                });
            }

            // Check minimum length
            if value.len() < min_length {
                span.record("result", &"failure");
                span.record("failure_reason", &"too_short");

                return Err(ValidationError::InvalidValue {
                    field: field_name.to_string(),
                    message: format!(
                        "{} must be at least {} characters long",
                        field_name, min_length
                    ),
                    span: SpanTrace::capture(),
                });
            }

            // Check maximum length
            if value.len() > max_length {
                span.record("result", &"failure");
                span.record("failure_reason", &"too_long");

                return Err(ValidationError::TooLong {
                    field: field_name.to_string(),
                    max_length,
                    span: SpanTrace::capture(),
                });
            }

            // Check regex pattern if provided
            if let Some(pattern) = regex {
                if !pattern.is_match(value) {
                    span.record("result", &"failure");
                    span.record("failure_reason", &"invalid_format");

                    return Err(ValidationError::InvalidValue {
                        field: field_name.to_string(),
                        message: custom_error.to_string(),
                        span: SpanTrace::capture(),
                    });
                }
            }

            span.record("result", &"success");
            Ok(())
        })
    })
}

// =============================================================================
// COMPREHENSIVE TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    mod username_validation {
        use super::*;

        #[test]
        fn valid_usernames() {
            let valid_cases = vec![
                "user",
                "user_123",
                "test-user",
                "User2024",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 30 'a's
            ];

            for username in valid_cases {
                assert!(
                    validate_username(username).is_ok(),
                    "Username '{}' should be valid",
                    username
                );
            }
        }

        #[test]
        fn invalid_usernames() {
            let invalid_cases = vec![
                ("", "empty"),
                ("ab", "too short"),
                ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "too long"), // 31 'a's
                ("user name", "contains space"),
                ("user@domain", "contains @"),
                ("user!test", "contains !"),
            ];

            for (username, reason) in invalid_cases {
                assert!(
                    validate_username(username).is_err(),
                    "Username '{}' should be invalid: {}",
                    username,
                    reason
                );
            }
        }

        #[test]
        fn username_length_boundaries() {
            assert!(validate_username("abc").is_ok()); // Minimum valid

            // Create strings for testing that don't create temporary values
            let max_valid = "a".repeat(30);
            let over_limit = "a".repeat(31);

            assert!(validate_username(&max_valid).is_ok()); // Maximum valid
            assert!(validate_username(&over_limit).is_err()); // Over limit
        }
    }

    mod email_validation {
        use super::*;

        #[test]
        fn valid_emails() {
            let valid_cases = vec![
                "user@example.com",
                "test.user@example.com",
                "user+tag@example.co.uk",
                "123@test.org",
                "user@sub.domain.example.com",
            ];

            for email in valid_cases {
                assert!(
                    validate_email(email).is_ok(),
                    "Email '{}' should be valid",
                    email
                );
            }
        }

        #[test]
        fn invalid_emails() {
            let invalid_cases = vec![
                ("", "empty"),
                ("user", "no @"),
                ("@example.com", "no local part"),
                ("user@", "no domain"),
                ("user@domain", "no TLD"),
                ("user@@example.com", "double @"),
                ("user@domain.x", "TLD too short"),
            ];

            for (email, reason) in invalid_cases {
                assert!(
                    validate_email(email).is_err(),
                    "Email '{}' should be invalid: {}",
                    email,
                    reason
                );
            }
        }

        #[test]
        fn email_edge_cases() {
            // Create persistent strings for testing
            let long_local_part = "a".repeat(241);
            let long_email = format!("{}@example.com", long_local_part);

            let too_long_local_part = "a".repeat(242);
            let too_long_email = format!("{}@example.com", too_long_local_part);

            assert!(validate_email(&long_email).is_ok()); // Maximum valid
            assert!(validate_email(&too_long_email).is_err()); // Over maximum length
        }
    }

    mod password_validation {
        use super::*;

        #[test]
        fn valid_passwords() {
            let valid_cases = vec![
                "SecureP@ss123",
                "Test123!",
                "MyStr0ng#Pass",
                "p@ssW0rd",
                "Complex1ty!",
            ];

            for password in valid_cases {
                assert!(
                    validate_password(password).is_ok(),
                    "Password should be valid"
                );
            }
        }

        #[test]
        fn invalid_passwords() {
            let invalid_cases = vec![
                ("", "empty"),
                ("short1!", "too short"),
                ("NoNumbers!", "no numbers"),
                ("NoSpecial123", "no special chars"),
                ("12345678!", "no letters"),
            ];

            for (password, reason) in invalid_cases {
                assert!(
                    validate_password(password).is_err(),
                    "Password should be invalid: {}",
                    reason
                );
            }

            // Test too long password separately to avoid temporary value issues
            let too_long = "a".repeat(129);
            assert!(
                validate_password(&too_long).is_err(),
                "Password should be invalid: too long"
            );
        }

        #[test]
        fn password_complexity_requirements() {
            // Test each requirement individually
            assert!(validate_password("Abcdefgh!").is_err()); // No number
            assert!(validate_password("12345678!").is_err()); // No letter
            assert!(validate_password("Abcd1234").is_err()); // No special
            assert!(validate_password("Ab1!").is_err()); // Too short
        }
    }

    mod generic_field_validation {
        use super::*;

        #[test]
        fn generic_field_basic_validation() {
            // Valid case
            assert!(validate_generic_field(
                "test_field",
                "valid_value",
                5,
                20,
                None,
                "Invalid field"
            )
            .is_ok());

            // Too short
            assert!(
                validate_generic_field("test_field", "abc", 5, 20, None, "Invalid field").is_err()
            );

            // Too long - use a persistent string
            let too_long = "a".repeat(21);
            assert!(
                validate_generic_field("test_field", &too_long, 5, 20, None, "Invalid field")
                    .is_err()
            );
        }

        #[test]
        fn generic_field_with_regex() {
            let phone_regex = Regex::new(r"^\+?[1-9]\d{9,14}$").unwrap();

            // Valid phone numbers
            assert!(validate_generic_field(
                "phone",
                "+1234567890",
                10,
                16,
                Some(&phone_regex),
                "Invalid phone number"
            )
            .is_ok());

            // Invalid format
            assert!(validate_generic_field(
                "phone",
                "123-456-7890",
                10,
                16,
                Some(&phone_regex),
                "Invalid phone number"
            )
            .is_err());
        }
    }
}
