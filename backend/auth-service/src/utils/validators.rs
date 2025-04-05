//! Input validation utilities for user data.
//!
//! This module provides functions for validating user input data like
//! usernames, emails, and passwords against security and format requirements.
//! It uses regex patterns for consistent validation and provides
//! specific error messages for each validation failure.

use regex::Regex;
use lazy_static::lazy_static;
use log::debug;
use crate::utils::errors::ApiError;

/// Regex patterns for validation.
const USERNAME_PATTERN: &str = r"^[a-zA-Z0-9_-]{3,30}$"; // Allows 3-30 alphanumeric characters + underscore and dash
const PASSWORD_PATTERN: &str = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=!*]).{8,128}$"; // At least 8 chars with letter, number, special char
const EMAIL_PATTERN: &str = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"; // RFC 5322 compliant

/// Error messages for validation.
const USERNAME_ERROR: &str = "Username must be 3-30 characters long and can contain letters, numbers, underscores, and dashes.";
const EMAIL_ERROR: &str = "Please provide a valid email address.";
const PASSWORD_ERROR: &str = "Password must be at least 8 characters long and include at least one letter, one number, and one special character (@#$%^&+=!*).";

lazy_static! {
    /// Compiled regex for username validation.
    static ref USERNAME_REGEX: Regex = Regex::new(USERNAME_PATTERN).expect("Invalid regex for username");

    /// Compiled regex for email validation.
    static ref EMAIL_REGEX: Regex = Regex::new(EMAIL_PATTERN).expect("Invalid regex for email");

    /// Compiled regex for password validation.
    static ref PASSWORD_REGEX: Regex = Regex::new(PASSWORD_PATTERN).expect("Invalid regex for password");
}

/// Maximum allowed length for inputs to prevent DoS attacks.
const MAX_INPUT_LENGTH: usize = 256;

/// Helper function for regex-based validation.
/// 
/// # Arguments
/// * `value` - The string value to validate
/// * `regex` - The compiled regex to match against
/// * `field` - The name of the field being validated
/// * `error_message` - The error message to return if validation fails
///
/// # Returns
/// * `Ok(())` - If the value matches the regex
/// * `Err(ApiError)` - If the validation fails
fn validate_with_regex(value: &str, regex: &Regex, field: &str, error_message: &str) -> Result<(), ApiError> {
    // Check for empty values
    if value.is_empty() {
        debug!("Validation failed: {} is empty", field);
        return Err(ApiError::validation_error(field, &format!("{} cannot be empty", field)));
    }
    
    // Check for excessive length to prevent DoS attacks
    if value.len() > MAX_INPUT_LENGTH {
        debug!("Validation failed: {} exceeds maximum length", field);
        return Err(ApiError::validation_error(
            field,
            &format!("{} is too long (maximum {} characters)", field, MAX_INPUT_LENGTH)
        ));
    }
    
    // Check if the value matches the regex pattern
    if regex.is_match(value) {
        debug!("Validation passed for {}", field);
        Ok(())
    } else {
        debug!("Validation failed: {} does not match pattern", field);
        Err(ApiError::validation_error(field, error_message))
    }
}

/// Validates a username.
///
/// # Requirements
/// - 3-30 characters long
/// - Letters, numbers, underscores, and dashes only
/// - No spaces or special characters
///
/// # Arguments
/// * `username` - The username to validate
///
/// # Returns
/// * `Ok(())` - If the username is valid
/// * `Err(ApiError)` - If the username is invalid
pub fn validate_username(username: &str) -> Result<(), ApiError> {
    validate_with_regex(username, &USERNAME_REGEX, "username", USERNAME_ERROR)
}

/// Validates an email address.
///
/// Uses a comprehensive regex pattern compliant with RFC 5322.
///
/// # Arguments
/// * `email` - The email address to validate
///
/// # Returns
/// * `Ok(())` - If the email is valid
/// * `Err(ApiError)` - If the email is invalid
pub fn validate_email(email: &str) -> Result<(), ApiError> {
    // Basic length check before regex
    if email.is_empty() {
        return Err(ApiError::validation_error("email", "Email cannot be empty"));
    }
    
    if email.len() > MAX_INPUT_LENGTH {
        return Err(ApiError::validation_error(
            "email",
            &format!("Email is too long (maximum {} characters)", MAX_INPUT_LENGTH)
        ));
    }
    
    if !EMAIL_REGEX.is_match(email) {
        debug!("Email validation failed for: {}", email);
        return Err(ApiError::validation_error("email", EMAIL_ERROR));
    }
    
    // Additional validations beyond regex:
    
    // Check for minimum domain parts (must have at least one period in domain)
    if !email.split('@').nth(1).unwrap_or("").contains('.') {
        return Err(ApiError::validation_error("email", "Email domain appears invalid"));
    }
    
    // Check for valid TLD length (2-63 characters per RFC)
    let tld = email.split('.').last().unwrap_or("");
    if tld.len() < 2 || tld.len() > 63 {
        return Err(ApiError::validation_error("email", "Email TLD appears invalid"));
    }
    
    debug!("Email validation passed for: {}", email);
    Ok(())
}

/// Validates a password.
///
/// # Requirements
/// - At least 8 characters long
/// - At most 128 characters long
/// - Contains at least one letter
/// - Contains at least one number
/// - Contains at least one special character (@#$%^&+=!*)
///
/// # Arguments
/// * `password` - The password to validate
///
/// # Returns
/// * `Ok(())` - If the password is valid
/// * `Err(ApiError)` - If the password is invalid
pub fn validate_password(password: &str) -> Result<(), ApiError> {
    // Check for empty password
    if password.is_empty() {
        return Err(ApiError::validation_error("password", "Password cannot be empty"));
    }
    
    // Check for password length
    if password.len() < 8 {
        return Err(ApiError::validation_error(
            "password",
            "Password must be at least 8 characters long"
        ));
    }
    
    if password.len() > 128 {
        return Err(ApiError::validation_error(
            "password",
            "Password is too long (maximum 128 characters)"
        ));
    }
    
    // Detailed validation to ensure all requirements are met
    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| "@#$%^&+=!*".contains(c));
    
    if !has_letter || !has_number || !has_special {
        debug!("Password validation failed: missing required character types");
        return Err(ApiError::validation_error("password", PASSWORD_ERROR));
    }
    
    debug!("Password validation passed");
    Ok(())
}