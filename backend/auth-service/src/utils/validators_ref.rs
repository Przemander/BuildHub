//! Input validation utilities for user data.
//!
//! Validates usernames, emails, and passwords with regex patterns,
//! structured logging, and Prometheus metrics instrumentation.

use crate::utils::errors::ValidationError;
use crate::utils::metrics::{VALIDATION_OPERATIONS, VALIDATION_TIMING};
use crate::{log_debug, log_info, log_warn};
use once_cell::sync::Lazy;
use regex::Regex;

/// Maximum length for any input to prevent abuse.
const MAX_INPUT_LENGTH: usize = 256;

/// Regex patterns (compiled lazily).
static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_-]{3,30}$").expect("Invalid USERNAME regex")
});
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@" \
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" \
                r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("Invalid EMAIL regex")
});
static PASSWORD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=!*]).{8,128}$")
        .expect("Invalid PASSWORD regex")
});

/// Common messages for invalid formats.
const USERNAME_ERROR: &str = "Username must be 3–30 characters long and contain letters, numbers, '_' or '-'.";
const EMAIL_ERROR: &str = "Please provide a valid email address.";
const PASSWORD_ERROR: &str = "Password must be 8–128 characters long and include a letter, number, and special character.";

/// Instrumentation helper: logs start, measures timing, and records metrics.
fn instrument<F>(field: &str, validation: F) -> Result<(), ValidationError>
where
    F: FnOnce() -> Result<(), ValidationError>,
{
    log_debug!("Validation", &format!("Starting {} validation", field), "attempt");
    let timer = VALIDATION_TIMING.with_label_values(&[field]).start_timer();
    VALIDATION_OPERATIONS.with_label_values(&[field, "attempt"]).inc();

    let result = validation();
    timer.observe_duration();

    match &result {
        Ok(_) => log_info!("Validation", &format!("{} validation succeeded", field), "success"),
        Err(err) => log_warn!("Validation", &format!("{} validation failed: {:?}", field, err), "failure"),
    }

    result
}

/// Validates a username:
/// - Non-empty
/// - <= MAX_INPUT_LENGTH
/// - Matches USERNAME_REGEX
#[inline]
pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    instrument("username", || {
        if username.is_empty() {
            VALIDATION_OPERATIONS.with_label_values(&["username", "empty"]).inc();
            return Err(ValidationError::InvalidValue(
                "username".into(),
                "Username cannot be empty".into(),
            ));
        }
        if username.len() > MAX_INPUT_LENGTH {
            VALIDATION_OPERATIONS.with_label_values(&["username", "too_long"]).inc();
            return Err(ValidationError::InvalidValue(
                "username".into(),
                format!("Username is too long (max {} chars)", MAX_INPUT_LENGTH),
            ));
        }
        if USERNAME_REGEX.is_match(username) {
            VALIDATION_OPERATIONS.with_label_values(&["username", "success"]).inc();
            Ok(())
        } else {
            VALIDATION_OPERATIONS.with_label_values(&["username", "invalid_format"]).inc();
            Err(ValidationError::InvalidValue(
                "username".into(),
                USERNAME_ERROR.into(),
            ))
        }
    })
}

/// Validates an email address:
/// - Non-empty
/// - <= MAX_INPUT_LENGTH
/// - Matches EMAIL_REGEX
/// - Domain contains '.' and TLD length is 2–63
#[inline]
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    instrument("email", || {
        if email.is_empty() {
            VALIDATION_OPERATIONS.with_label_values(&["email", "empty"]).inc();
            return Err(ValidationError::InvalidValue(
                "email".into(),
                "Email cannot be empty".into(),
            ));
        }
        if email.len() > MAX_INPUT_LENGTH {
            VALIDATION_OPERATIONS.with_label_values(&["email", "too_long"]).inc();
            return Err(ValidationError::InvalidValue(
                "email".into(),
                format!("Email is too long (max {} chars)", MAX_INPUT_LENGTH),
            ));
        }
        if !EMAIL_REGEX.is_match(email) {
            VALIDATION_OPERATIONS.with_label_values(&["email", "regex_mismatch"]).inc();
            return Err(ValidationError::InvalidValue(
                "email".into(),
                EMAIL_ERROR.into(),
            ));
        }
        let domain = email.split('@').nth(1).unwrap_or("");
        if !domain.contains('.') {
            VALIDATION_OPERATIONS.with_label_values(&["email", "invalid_domain"]).inc();
            return Err(ValidationError::InvalidValue(
                "email".into(),
                "Email domain appears invalid".into(),
            ));
        }
        let tld = domain.rsplit('.').next().unwrap_or("");
        if tld.len() < 2 || tld.len() > 63 {
            VALIDATION_OPERATIONS.with_label_values(&["email", "invalid_tld"]).inc();
            return Err(ValidationError::InvalidValue(
                "email".into(),
                "Email TLD appears invalid".into(),
            ));
        }
        VALIDATION_OPERATIONS.with_label_values(&["email", "success"]).inc();
        Ok(())
    })
}

/// Validates a password:
/// - Non-empty
/// - 8–128 characters
/// - Matches PASSWORD_REGEX
#[inline]
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    instrument("password", || {
        if password.is_empty() {
            VALIDATION_OPERATIONS.with_label_values(&["password", "empty"]).inc();
            return Err(ValidationError::InvalidValue(
                "password".into(),
                "Password cannot be empty".into(),
            ));
        }
        if password.len() < 8 {
            VALIDATION_OPERATIONS.with_label_values(&["password", "too_short"]).inc();
            return Err(ValidationError::InvalidValue(
                "password".into(),
                "Password must be at least 8 characters long".into(),
            ));
        }
        if password.len() > 128 {
            VALIDATION_OPERATIONS.with_label_values(&["password", "too_long"]).inc();
            return Err(ValidationError::InvalidValue(
                "password".into(),
                "Password is too long (max 128 chars)".into(),
            ));
        }
        if PASSWORD_REGEX.is_match(password) {
            VALIDATION_OPERATIONS.with_label_values(&["password", "success"]).inc();
            Ok(())
        } else {
            VALIDATION_OPERATIONS.with_label_values(&["password", "invalid_format"]).inc();
            Err(ValidationError::InvalidValue(
                "password".into(),
                PASSWORD_ERROR.into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::errors::ValidationError;

    fn assert_invalid<F>(field: &str, input: &str, msg: &str, f: F)
    where
        F: Fn(&str) -> Result<(), ValidationError>,
    {
        match f(input).unwrap_err() {
            ValidationError::InvalidValue(fld, m) => {
                assert_eq!(fld, field);
                assert!(m.contains(msg));
            }
            _ => panic!("Expected InvalidValue for field {field}"),
        }
    }

    mod username {
        use super::*;

        #[test]
        fn valid_username_should_pass() {
            assert!(validate_username("user_123").is_ok());
        }

        #[test]
        fn empty_should_fail() {
            assert_invalid("username", "", "cannot be empty", validate_username);
        }

        #[test]
        fn too_long_should_fail() {
            let long = "a".repeat(MAX_INPUT_LENGTH + 1);
            assert_invalid("username", &long, "too long", validate_username);
        }

        #[test]
        fn bad_format_should_fail() {
            assert_invalid("username", "bad format!", "Username must", validate_username);
        }
    }

    mod email {
        use super::*;

        #[test]
        fn valid_should_pass() {
            assert!(validate_email("test@example.com").is_ok());
        }

        #[test]
        fn empty_should_fail() {
            assert_invalid("email", "", "cannot be empty", validate_email);
        }

        #[test]
        fn too_long_should_fail() {
            let long = "a".repeat(257) + "@x.com";
            assert_invalid("email", &long, "too long", validate_email);
        }

        #[test]
        fn regex_mismatch_should_fail() {
            assert_invalid("email", "not-an-email", "valid email", validate_email);
        }

        #[test]
        fn invalid_domain_should_fail() {
            assert_invalid("email", "user@domain", "domain appears invalid", validate_email);
        }

        #[test]
        fn invalid_tld_should_fail() {
            assert_invalid("email", "user@domain.c", "TLD appears invalid", validate_email);
        }
    }

    mod password {
        use super::*;

        #[test]
        fn valid_should_pass() {
            assert!(validate_password("Abcd1234!").is_ok());
        }

        #[test]
        fn empty_should_fail() {
            assert_invalid("password", "", "cannot be empty", validate_password);
        }

        #[test]
        fn too_short_should_fail() {
            assert_invalid("password", "Ab1!", "at least 8", validate_password);
        }

        #[test]
        fn too_long_should_fail() {
            let long = "A1!".repeat(50);
            assert_invalid("password", &long, "too long", validate_password);
        }

        #[test]
        fn missing_letter_should_fail() {
            assert_invalid("password", "12345678!", "one letter", validate_password);
        }

        #[test]
        fn missing_number_should_fail() {
            assert_invalid("password", "Abcdefgh!", "one number", validate_password);
        }

        #[test]
        fn missing_special_should_fail() {
            assert_invalid("password", "Abcd1234", "special character", validate_password);
        }
    }
}
