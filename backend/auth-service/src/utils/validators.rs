//! # Input Validation Utilities for BuildHub Auth Service
//!
//! Enterprise-grade validation with minimal, actionable logging.
//! Only logs abnormal conditions (abuse patterns, internal errors).
//! Normal validation failures are handled via errors + metrics.

use crate::utils::error_new::{AuthServiceError, ValidationError};
use crate::utils::log_new::Log;
use crate::metricss::validation_metrics::{
    instrument_validation, time_validation, record_username_success,
    record_username_failure, field_types, error_types,
};
use once_cell::sync::Lazy;
use regex::Regex;
use tracing_error::SpanTrace;

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

static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_-]{3,30}$")
        .expect("USERNAME regex failed to compile")
});

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("EMAIL regex failed to compile")
});

const USERNAME_ERROR: &str = "Username must be 3-30 characters long and can contain letters, numbers, underscores, and dashes";
const PASSWORD_ERROR: &str = "Password must be at least 8 characters long and include at least one letter, one number, and one special character (@#$%^&+=!*_-)";

// =============================================================================
// CORE VALIDATION FUNCTIONS
// =============================================================================

/// Validates username format with security checks.
#[inline]
pub fn validate_username(username: &str) -> Result<(), AuthServiceError> {
    instrument_validation(field_types::USERNAME, || {
        if username.is_empty() {
            return Err(ValidationError::MissingField {
                field: field_types::USERNAME.to_string(),
                span: SpanTrace::capture(),
            });
        }

        if username.len() > MAX_INPUT_LENGTH {
            // Potential abuse - log oversized input
            Log::event(
                "WARN",
                "validation",
                "Username too long - potential abuse",
                "failure",
                "validate_username",
            );
            return Err(ValidationError::TooLong {
                field: field_types::USERNAME.to_string(),
                max_length: MAX_INPUT_LENGTH,
                span: SpanTrace::capture(),
            });
        }

        if USERNAME_REGEX.is_match(username) {
            Ok(())
        } else {
            // Normal validation error - no log, just return error
            Err(ValidationError::InvalidValue {
                field: field_types::USERNAME.to_string(),
                message: USERNAME_ERROR.to_string(),
                span: SpanTrace::capture(),
            })
        }
    })
}

/// Validates email address with RFC compliance.
#[inline]
pub fn validate_email(email: &str) -> Result<(), AuthServiceError> {
    instrument_validation(field_types::EMAIL, || {
        if email.is_empty() {
            return Err(ValidationError::MissingField {
                field: field_types::EMAIL.to_string(),
                span: SpanTrace::capture(),
            });
        }

        if email.len() > MAX_EMAIL_LENGTH {
            // Potential abuse - log oversized input
            Log::event(
                "WARN",
                "validation",
                "Email too long - potential abuse",
                "failure",
                "validate_email",
            );
            return Err(ValidationError::TooLong {
                field: field_types::EMAIL.to_string(),
                max_length: MAX_EMAIL_LENGTH,
                span: SpanTrace::capture(),
            });
        }

        if !EMAIL_REGEX.is_match(email) {
            // Normal validation error - no log
            return Err(ValidationError::InvalidValue {
                field: field_types::EMAIL.to_string(),
                message: "Please provide a valid email address".to_string(),
                span: SpanTrace::capture(),
            });
        }

        // Additional domain validation
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            // Internal inconsistency - regex passed but split failed
            Log::event(
                "ERROR",
                "validation",
                "Email regex passed but @ split failed - internal error",
                "failure",
                "validate_email",
            );
            return Err(ValidationError::InvalidValue {
                field: field_types::EMAIL.to_string(),
                message: "Email must contain exactly one @ symbol".to_string(),
                span: SpanTrace::capture(),
            });
        }

        let domain = parts[1];
        if !domain.contains('.') {
            // Normal validation error - no log
            return Err(ValidationError::InvalidValue {
                field: field_types::EMAIL.to_string(),
                message: "Email domain must contain at least one dot".to_string(),
                span: SpanTrace::capture(),
            });
        }

        let tld = domain.split('.').last().unwrap_or("");
        if tld.len() < MIN_TLD_LENGTH || tld.len() > MAX_TLD_LENGTH {
            // Normal validation error - no log
            return Err(ValidationError::InvalidValue {
                field: field_types::EMAIL.to_string(),
                message: format!("Email TLD must be {}-{} characters long", MIN_TLD_LENGTH, MAX_TLD_LENGTH),
                span: SpanTrace::capture(),
            });
        }

        Ok(())
    })
}

/// Validates password strength requirements.
#[inline]
pub fn validate_password(password: &str) -> Result<(), AuthServiceError> {
    instrument_validation(field_types::PASSWORD, || {
        if password.is_empty() {
            return Err(ValidationError::MissingField {
                field: field_types::PASSWORD.to_string(),
                span: SpanTrace::capture(),
            });
        }

        if password.len() < MIN_PASSWORD_LENGTH {
            // Normal validation error - no log
            return Err(ValidationError::InvalidValue {
                field: field_types::PASSWORD.to_string(),
                message: PASSWORD_ERROR.to_string(),
                span: SpanTrace::capture(),
            });
        }

        if password.len() > MAX_PASSWORD_LENGTH {
            // Potential abuse - log oversized input
            Log::event(
                "WARN",
                "validation",
                "Password too long - potential abuse",
                "failure",
                "validate_password",
            );
            return Err(ValidationError::TooLong {
                field: field_types::PASSWORD.to_string(),
                max_length: MAX_PASSWORD_LENGTH,
                span: SpanTrace::capture(),
            });
        }
        
        // Check password strength requirements
        let has_letter = password.chars().any(|c| c.is_alphabetic());
        let has_number = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

        if !has_letter || !has_number || !has_special {
            // Normal validation error - no log
            return Err(ValidationError::InvalidValue {
                field: field_types::PASSWORD.to_string(),
                message: PASSWORD_ERROR.to_string(),
                span: SpanTrace::capture(),
            });
        }

        Ok(())
    })
}

// =============================================================================
// LOW-LEVEL API EXAMPLE (manual control)
// =============================================================================

/// Alternative username validation using low-level API for manual control.
#[allow(dead_code)]
pub fn validate_username_manual(username: &str) -> Result<(), AuthServiceError> {
    let _timer = time_validation(field_types::USERNAME);
    
    let validation_result = || -> Result<(), ValidationError> {
        if username.is_empty() {
            return Err(ValidationError::MissingField {
                field: field_types::USERNAME.to_string(),
                span: SpanTrace::capture(),
            });
        }

        if username.len() > MAX_INPUT_LENGTH {
            return Err(ValidationError::TooLong {
                field: field_types::USERNAME.to_string(),
                max_length: MAX_INPUT_LENGTH,
                span: SpanTrace::capture(),
            });
        }

        if USERNAME_REGEX.is_match(username) {
            Ok(())
        } else {
            Err(ValidationError::InvalidValue {
                field: field_types::USERNAME.to_string(),
                message: USERNAME_ERROR.to_string(),
                span: SpanTrace::capture(),
            })
        }
    };

    match validation_result() {
        Ok(()) => {
            record_username_success();
            Ok(())
        }
        Err(validation_err) => {
            let error_type = match &validation_err {
                ValidationError::MissingField { .. } => error_types::MISSING,
                ValidationError::TooLong { .. } => error_types::TOO_LONG,
                ValidationError::InvalidValue { .. } => error_types::INVALID_FORMAT,
                ValidationError::PasswordHash { .. } => error_types::HASH_ERROR,
            };
            record_username_failure(error_type);
            
            Err(AuthServiceError::from(validation_err))
        }
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Validates a generic input field with customizable constraints.
#[allow(dead_code)]
pub fn validate_generic_field(
    field_name: &str,
    value: &str,
    min_length: usize,
    max_length: usize,
    regex: Option<&Regex>,
    custom_error: &str,
) -> Result<(), AuthServiceError> {
    instrument_validation(field_name, || {
        if value.is_empty() && min_length > 0 {
            return Err(ValidationError::MissingField {
                field: field_name.to_string(),
                span: SpanTrace::capture(),
            });
        }

        if value.len() < min_length {
            return Err(ValidationError::InvalidValue {
                field: field_name.to_string(),
                message: format!("Field must be at least {} characters long", min_length),
                span: SpanTrace::capture(),
            });
        }

        if value.len() > max_length {
            return Err(ValidationError::TooLong {
                field: field_name.to_string(),
                max_length,
                span: SpanTrace::capture(),
            });
        }

        if let Some(pattern) = regex {
            if !pattern.is_match(value) {
                return Err(ValidationError::InvalidValue {
                    field: field_name.to_string(),
                    message: custom_error.to_string(),
                    span: SpanTrace::capture(),
                });
            }
        }

        Ok(())
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metricss::validation_metrics::init_validation_metrics;

    fn setup() {
        init_validation_metrics();
    }

    mod username_validation {
        use super::*;

        #[test]
        fn valid_usernames_should_pass() {
            setup();
            assert!(validate_username("user_123").is_ok());
            assert!(validate_username("alice").is_ok());
            assert!(validate_username("bob-2023").is_ok());
            assert!(validate_username("test_user_name").is_ok());
        }

        #[test]
        fn empty_username_should_fail() {
            setup();
            let result = validate_username("");
            assert!(result.is_err());
        }

        #[test]
        fn too_long_username_should_fail() {
            setup();
            let long_username = "a".repeat(MAX_INPUT_LENGTH + 1);
            let result = validate_username(&long_username);
            assert!(result.is_err());
        }

        #[test]
        fn invalid_format_username_should_fail() {
            setup();
            assert!(validate_username("no spaces!").is_err());
            assert!(validate_username("user@domain").is_err());
            assert!(validate_username("ab").is_err());
        }
    }

    mod email_validation {
        use super::*;

        #[test]
        fn valid_emails_should_pass() {
            setup();
            assert!(validate_email("test@example.com").is_ok());
            assert!(validate_email("user.name+tag@example.co.uk").is_ok());
            assert!(validate_email("simple@test.org").is_ok());
        }

        #[test]
        fn empty_email_should_fail() {
            setup();
            let result = validate_email("");
            assert!(result.is_err());
        }

        #[test]
        fn invalid_format_emails_should_fail() {
            setup();
            assert!(validate_email("not-an-email").is_err());
            assert!(validate_email("@missing-local.com").is_err());
            assert!(validate_email("missing-at-sign.com").is_err());
        }
    }

    mod password_validation {
        use super::*;

        #[test]
        fn valid_passwords_should_pass() {
            setup();
            assert!(validate_password("SecureP@ss123").is_ok());
            assert!(validate_password("MyStr0ng!Pass").is_ok());
            assert!(validate_password("Test123#").is_ok());
        }

        #[test]
        fn empty_password_should_fail() {
            setup();
            let result = validate_password("");
            assert!(result.is_err());
        }

        #[test]
        fn missing_requirements_should_fail() {
            setup();
            assert!(validate_password("12345678!").is_err());   // No letters
            assert!(validate_password("Abcdefgh!").is_err());   // No numbers
            assert!(validate_password("Abcd1234").is_err());    // No special chars
            assert!(validate_password("Ab1!").is_err());        // Too short
        }
    }
}