use regex::Regex;
use lazy_static::lazy_static;
use crate::utils::errors::ApiError;

/// Regex patterns for validation.
const USERNAME_PATTERN: &str = r"^[a-zA-Z0-9]{3,20}$"; // Allows 3-20 alphanumeric characters.
const PASSWORD_PATTERN: &str = r"^[A-Za-z\d@#$%^&+=!*]{8,}$"; // At least 8 characters, including letters, numbers, special chars
const EMAIL_PATTERN: &str = r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$";  // Allows plus in local part

/// Error messages for validation.
const USERNAME_ERROR: &str = "Username must be 3-20 characters long and contain only letters and numbers.";
const EMAIL_ERROR: &str = "Invalid email format.";
const PASSWORD_ERROR: &str = "Password must be at least 8 characters long, contain a letter, a number, and a special character.";

lazy_static! {
    /// Compiled regex for username validation.
    static ref USERNAME_REGEX: Regex = Regex::new(USERNAME_PATTERN).expect("Invalid regex for username");

    /// Compiled regex for email validation.
    static ref EMAIL_REGEX: Regex = Regex::new(EMAIL_PATTERN).expect("Invalid regex for email");

    /// Compiled regex for password validation.
    static ref PASSWORD_REGEX: Regex = Regex::new(PASSWORD_PATTERN).expect("Invalid regex for password");
}

/// Helper function for regex-based validation.
/// 
/// # Parameters
/// - `value`: The string value to validate.
/// - `regex`: The compiled regex to match against.
/// - `field`: The name of the field being validated.
/// - `error_message`: The error message to return if validation fails.
///
/// # Returns
/// - `Ok(())` if the value matches the regex.
/// - `Err(ApiError)` if the validation fails.
fn validate_with_regex(value: &str, regex: &Regex, field: &str, error_message: &str) -> Result<(), ApiError> {
    if regex.is_match(value) {
        Ok(())
    } else {
        Err(ApiError::validation_error(field, error_message))
    }
}

/// Validates a username.
pub fn validate_username(username: &str) -> Result<(), ApiError> {
    validate_with_regex(username, &USERNAME_REGEX, "username", USERNAME_ERROR)
}

/// Validates an email address.
pub fn validate_email(email: &str) -> Result<(), ApiError> {
    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err(ApiError::validation_error("email", EMAIL_ERROR))
    }
}

/// Validates a password.
pub fn validate_password(password: &str) -> Result<(), ApiError> {
    if PASSWORD_REGEX.is_match(password)
        && password.chars().any(|c| c.is_alphabetic())
        && password.chars().any(|c| c.is_numeric())
        // Dodajemy '*' do sprawdzanych znaków specjalnych.
        && password.chars().any(|c| "@#$%^&+=!*".contains(c))
    {
        Ok(())
    } else {
        Err(ApiError::validation_error("password", PASSWORD_ERROR))
    }
}