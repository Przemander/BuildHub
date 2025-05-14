//! Input validation utilities for user data.
//!
//! This module validates user inputs such as usernames, emails, and passwords
//! using regex patterns and additional checks. It leverages structured logging
//! and metrics to track validation attempts, successes, and failures.
//!
//! Best practices:
//! - Use clear documentation and inline comments.
//! - Time validation operations and update corresponding metrics.
//! - Return early on error and use domain errors (ValidationError) for failures.

use crate::utils::errors::ValidationError;
use crate::utils::metrics::{VALIDATION_OPERATIONS, VALIDATION_TIMING};
use crate::{log_debug, log_info, log_warn};
use lazy_static::lazy_static;
use regex::Regex;

/// Regex pattern definitions for validation.
const USERNAME_PATTERN: &str = r"^[a-zA-Z0-9_-]{3,30}$"; // 3-30 alphanumeric characters, underscores, dashes.
const PASSWORD_PATTERN: &str = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=!*]).{8,128}$"; // 8-128 characters with letters, numbers, special character.
const EMAIL_PATTERN: &str = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"; // RFC 5322 compliant

/// Error messages for validation failures.
const USERNAME_ERROR: &str = "Username must be 3-30 characters long and can contain letters, numbers, underscores, and dashes.";
const EMAIL_ERROR: &str = "Please provide a valid email address.";
const PASSWORD_ERROR: &str = "Password must be at least 8 characters long and include at least one letter, one number, and one special character (@#$%^&+=!*).";

lazy_static! {
    /// Compiled regex for username validation.
    static ref USERNAME_REGEX: Regex = Regex::new(USERNAME_PATTERN)
        .expect("Invalid regex pattern for username");

    /// Compiled regex for email validation.
    static ref EMAIL_REGEX: Regex = Regex::new(EMAIL_PATTERN)
        .expect("Invalid regex pattern for email");

    /// Compiled regex for password validation.
    static ref PASSWORD_REGEX: Regex = Regex::new(PASSWORD_PATTERN)
        .expect("Invalid regex pattern for password");
}

/// Maximum input length to prevent potential abuse.
const MAX_INPUT_LENGTH: usize = 256;

/// Helper function for regex-based validation.
/// Times the operation and updates metrics for attempts, successes, and failures.
/// Log messages remain generic to avoid printing any sensitive input data.
///
/// # Arguments
/// * `value` - The input value to validate.
/// * `regex` - The compiled regex to check against.
/// * `field` - The name of the field being validated (e.g. "username").
/// * `error_message` - The error message to return if validation fails.
///
/// # Returns
/// * `Ok(())` if the input is valid.
/// * `Err(ValidationError)` if validation fails.
fn validate_with_regex(
    value: &str,
    regex: &Regex,
    field: &str,
    error_message: &str,
) -> Result<(), ValidationError> {
    let timer = VALIDATION_TIMING.with_label_values(&[field]).start_timer();
    VALIDATION_OPERATIONS
        .with_label_values(&[field, "attempt"])
        .inc();

    if value.is_empty() {
        log_warn!("Validation", "Empty input for field", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&[field, "empty"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            field.to_string(),
            format!("{} cannot be empty", field),
        ));
        timer.observe_duration();
        return res;
    }

    if value.len() > MAX_INPUT_LENGTH {
        log_warn!("Validation", "Input too long", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&[field, "too_long"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            field.to_string(),
            format!(
                "{} is too long (max {} characters)",
                field, MAX_INPUT_LENGTH
            ),
        ));
        timer.observe_duration();
        return res;
    }

    if regex.is_match(value) {
        log_debug!("Validation", "Input format valid", "success");
        VALIDATION_OPERATIONS
            .with_label_values(&[field, "success"])
            .inc();
        timer.observe_duration();
        Ok(())
    } else {
        log_warn!("Validation", "Input invalid format", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&[field, "invalid_format"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            field.to_string(),
            error_message.to_string(),
        ));
        timer.observe_duration();
        res
    }
}

/// Validates a username.
///
/// Requirements:
/// - 3 to 30 characters long.
/// - Contains only letters, numbers, underscores, and dashes.
///
/// # Arguments
/// * `username` - The username string to validate.
///
/// # Returns
/// * `Ok(())` if valid.
/// * `Err(ValidationError)` if invalid.
pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    log_debug!("Validation", "Starting username validation", "attempt");
    let result = validate_with_regex(username, &USERNAME_REGEX, "username", USERNAME_ERROR);
    if result.is_ok() {
        log_info!("Validation", "Username validation succeeded", "success");
    } else {
        log_warn!("Validation", "Username validation failed", "failure");
    }
    result
}

/// Validates an email address.
///
/// Checks:
/// - Non-empty input.
/// - Matches regex pattern.
/// - Domain contains at least one period and valid TLD length (2-63 characters).
///
/// # Arguments
/// * `email` - The email address to validate.
///
/// # Returns
/// * `Ok(())` if valid.
/// * `Err(ValidationError)` if invalid.
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    let timer = VALIDATION_TIMING
        .with_label_values(&["email"])
        .start_timer();
    VALIDATION_OPERATIONS
        .with_label_values(&["email", "attempt"])
        .inc();
    log_debug!("Validation", "Starting email validation", "attempt");

    if email.is_empty() {
        log_warn!("Validation", "Email is empty", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["email", "empty"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "email".to_string(),
            "Email cannot be empty".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    if email.len() > MAX_INPUT_LENGTH {
        log_warn!("Validation", "Email exceeds maximum length", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["email", "too_long"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "email".to_string(),
            format!("Email is too long (max {} characters)", MAX_INPUT_LENGTH),
        ));
        timer.observe_duration();
        return res;
    }

    if !EMAIL_REGEX.is_match(email) {
        log_warn!("Validation", "Email regex mismatch", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["email", "regex_mismatch"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "email".to_string(),
            EMAIL_ERROR.to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    if !email.split('@').nth(1).unwrap_or("").contains('.') {
        log_warn!("Validation", "Email domain invalid", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["email", "invalid_domain"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "email".to_string(),
            "Email domain appears invalid".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    let tld = email.split('.').last().unwrap_or("");
    if tld.len() < 2 || tld.len() > 63 {
        log_warn!("Validation", "Email TLD invalid", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["email", "invalid_tld"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "email".to_string(),
            "Email TLD appears invalid".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    log_info!("Validation", "Email validation succeeded", "success");
    VALIDATION_OPERATIONS
        .with_label_values(&["email", "success"])
        .inc();
    timer.observe_duration();
    Ok(())
}

/// Validates a password ensuring it meets complexity requirements.
///
/// Requirements:
/// - At least 8 characters and at most 128 characters.
/// - Contains at least one letter, one number, and one special character (@#$%^&+=!*).
///
/// # Arguments
/// * `password` - The password string to validate.
///
/// # Returns
/// * `Ok(())` if valid.
/// * `Err(ValidationError)` if invalid.
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    let timer = VALIDATION_TIMING
        .with_label_values(&["password"])
        .start_timer();
    VALIDATION_OPERATIONS
        .with_label_values(&["password", "attempt"])
        .inc();
    log_debug!("Validation", "Starting password validation", "attempt");

    if password.is_empty() {
        log_warn!("Validation", "Password is empty", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["password", "empty"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "password".to_string(),
            "Password cannot be empty".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    if password.len() < 8 {
        log_warn!("Validation", "Password too short", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["password", "too_short"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "password".to_string(),
            "Password must be at least 8 characters long".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    if password.len() > 128 {
        log_warn!("Validation", "Password too long", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["password", "too_long"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "password".to_string(),
            "Password is too long (max 128 characters)".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| "@#$%^&+=!*".contains(c));

    if !has_letter {
        log_warn!("Validation", "Password missing letter", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["password", "missing_letter"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "password".to_string(),
            "Password must include at least one letter".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    if !has_number {
        log_warn!("Validation", "Password missing number", "failure");
        VALIDATION_OPERATIONS
            .with_label_values(&["password", "missing_number"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "password".to_string(),
            "Password must include at least one number".to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    if !has_special {
        log_warn!(
            "Validation",
            "Password missing special character",
            "failure"
        );
        VALIDATION_OPERATIONS
            .with_label_values(&["password", "missing_special"])
            .inc();
        let res = Err(ValidationError::InvalidValue(
            "password".to_string(),
            PASSWORD_ERROR.to_string(),
        ));
        timer.observe_duration();
        return res;
    }

    log_info!("Validation", "Password validation succeeded", "success");
    VALIDATION_OPERATIONS
        .with_label_values(&["password", "success"])
        .inc();
    timer.observe_duration();
    Ok(())
}

// …existing code…

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::errors::ValidationError;

    #[test]
    fn validate_username_ok() {
        assert!(validate_username("user_123").is_ok());
    }

    #[test]
    fn validate_username_empty() {
        let err = validate_username("").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "username");
                assert!(msg.contains("cannot be empty"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_username_too_long() {
        let long = "a".repeat(MAX_INPUT_LENGTH + 1);
        let err = validate_username(&long).unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "username");
                assert!(msg.contains("too long"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_username_bad_format() {
        let err = validate_username("no spaces!").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, _) => {
                assert_eq!(field, "username");
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_email_ok() {
        assert!(validate_email("test@example.com").is_ok());
    }

    #[test]
    fn validate_email_empty() {
        let err = validate_email("").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "email");
                assert!(msg.contains("cannot be empty"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_email_too_long() {
        let long = "a".repeat(257) + "@x.com";
        let err = validate_email(&long).unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "email");
                assert!(msg.contains("too long"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_email_regex_mismatch() {
        let err = validate_email("not-an-email").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, _) => {
                assert_eq!(field, "email");
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_email_invalid_domain() {
        let err = validate_email("user@domain").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "email");
                assert!(msg.contains("invalid"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_email_invalid_tld() {
        let err = validate_email("user@domain.c").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "email");
                assert!(msg.contains("invalid"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_password_ok() {
        assert!(validate_password("Abcd1234!").is_ok());
    }

    #[test]
    fn validate_password_empty() {
        let err = validate_password("").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "password");
                assert!(msg.contains("cannot be empty"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_password_too_short() {
        let err = validate_password("Ab1!").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "password");
                assert!(msg.contains("at least 8 characters"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_password_missing_letter() {
        let err = validate_password("12345678!").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "password");
                assert!(msg.contains("include at least one letter"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_password_missing_number() {
        let err = validate_password("Abcdefgh!").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "password");
                assert!(msg.contains("include at least one number"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_password_missing_special() {
        let err = validate_password("Abcd1234").unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "password");
                // PASSWORD_ERROR is the generic message including special-char requirement
                assert!(msg.contains("special character"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn validate_password_too_long() {
        let too_long = "A1!".repeat(50); // length > 128
        let err = validate_password(&too_long).unwrap_err();
        match err {
            ValidationError::InvalidValue(field, msg) => {
                assert_eq!(field, "password");
                assert!(msg.contains("too long"));
            }
            _ => panic!("expected InvalidValue"),
        }
    }
}