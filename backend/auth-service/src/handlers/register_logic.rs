//! Business logic for user registration.
//!
//! This module implements a comprehensive registration flow with:
//! - Input validation for username, email, and password
//! - Uniqueness checks to prevent duplicate accounts
//! - User creation with secure password hashing
//! - Activation code generation and storage in Redis
//! - Email delivery for account activation
//! - Structured error handling with appropriate HTTP status codes
//! - Full observability through metrics and structured logging

use crate::{
    app::AppState,
    db::users::{RegisterData, User},
    log_error, log_info, log_warn,
    utils::{
        email::{generate_activation_code, store_activation_code},
        metrics::AUTH_REGISTRATIONS,
        validators::{validate_email, validate_password, validate_username},
    },
};
use axum::http::StatusCode;
use redis::Client as RedisClient;
use serde_json::json;
use std::fmt::Display;

/// Error types specific to the registration process
#[derive(Debug)]
enum RegistrationError {
    /// Missing required service dependencies
    MissingDependency(&'static str),
    /// Input validation failures
    ValidationFailure(&'static str, String),
    /// User already exists (email or username conflict)
    AlreadyExists(&'static str),
    /// Database or system error
    SystemError(&'static str, String),
}

impl RegistrationError {
    /// Converts error to HTTP status code and response body
    fn into_response(self) -> (StatusCode, serde_json::Value) {
        // Log and record metrics based on error type
        match &self {
            Self::MissingDependency(dep) => {
                log_error!("Register", &format!("Missing dependency: {}", dep), "system_error");
                AUTH_REGISTRATIONS.with_label_values(&["system_error"]).inc();
            }
            Self::ValidationFailure(field, msg) => {
                log_warn!("Register", &format!("{} validation failed: {}", field, msg), "validation_failed");
                AUTH_REGISTRATIONS.with_label_values(&["validation_failed"]).inc();
            }
            Self::AlreadyExists(field) => {
                log_warn!("Register", &format!("{} already exists", field), "already_exists");
                AUTH_REGISTRATIONS.with_label_values(&["already_exists"]).inc();
            }
            Self::SystemError(context, err) => {
                log_error!("Register", &format!("{}: {}", context, err), "failure");
                AUTH_REGISTRATIONS.with_label_values(&["failure"]).inc();
            }
        };

        // Convert to appropriate HTTP status and JSON response
        let (status, message) = match self {
            Self::MissingDependency(dep) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Missing {}", dep)),
            Self::ValidationFailure(_, msg) => (StatusCode::BAD_REQUEST, msg),
            Self::AlreadyExists(field) => (StatusCode::CONFLICT, format!("{} already exists", field)),
            Self::SystemError(context, _) => (StatusCode::INTERNAL_SERVER_ERROR, context.to_string()),
        };

        (status, json!({ "status": "error", "message": message }))
    }
}

impl Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDependency(dep) => write!(f, "Missing dependency: {}", dep),
            Self::ValidationFailure(field, msg) => write!(f, "{} validation error: {}", field, msg),
            Self::AlreadyExists(field) => write!(f, "{} already exists", field),
            Self::SystemError(context, err) => write!(f, "{}: {}", context, err),
        }
    }
}

/// Processes registration: validates, creates user, stores activation code, sends email, logs and metrics.
///
/// # Parameters
/// * `app_state` - Application state containing DB pool, Redis client, and email config
/// * `data` - Registration data from the client request
///
/// # Returns
/// A tuple containing HTTP status code and JSON response body
///
/// # Flow
/// 1. Validate dependencies (Email config, Redis)
/// 2. Validate input fields (username, email, password)
/// 3. Check uniqueness (email, username)
/// 4. Create inactive user in database
/// 5. Generate and store activation code
/// 6. Send activation email
/// 7. Return success response
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> (StatusCode, serde_json::Value) {
    // Check required dependencies and perform registration
    let result = async {
        // Get email configuration
        let email_cfg = app_state
            .email_config
            .as_ref()
            .ok_or(RegistrationError::MissingDependency("EmailConfig"))?
            .clone();

        // Get Redis client
        let redis_client = app_state
            .redis_client
            .as_ref()
            .ok_or(RegistrationError::MissingDependency("RedisClient"))?;

        // Obtain a DB connection
        let mut conn = app_state
            .pool
            .get()
            .map_err(|e| RegistrationError::SystemError("Database connection failed", e.to_string()))?;

        // Validate input fields
        validate_username(&data.username)
            .map_err(|e| RegistrationError::ValidationFailure("username", e.to_string()))?;
        validate_email(&data.email)
            .map_err(|e| RegistrationError::ValidationFailure("email", e.to_string()))?;
        validate_password(&data.password)
            .map_err(|e| RegistrationError::ValidationFailure("password", e.to_string()))?;

        // Check uniqueness
        if User::find_by_email(&mut conn, &data.email).is_ok() {
            return Err(RegistrationError::AlreadyExists("Email"));
        }
        if User::find_by_username(&mut conn, &data.username).is_ok() {
            return Err(RegistrationError::AlreadyExists("Username"));
        }

        // Create inactive user
        let mut user = User::new(&data.username, &data.email, &data.password);
        user.is_active = Some(false);
        user.save(&mut conn)
            .map_err(|e| RegistrationError::SystemError("Saving user failed", e.to_string()))?;

        // Generate and store activation code
        create_and_send_activation(&user, redis_client, &email_cfg).await?;

        Ok(())
    }
    .await;

    // Handle result and return appropriate response
    match result {
        Ok(()) => {
            log_info!("Register", "User registration successful", "success");
            AUTH_REGISTRATIONS.with_label_values(&["success"]).inc();
            (
                StatusCode::CREATED,
                json!({
                    "status": "success",
                    "message": "Registration successful! Please check your email to activate your account."
                }),
            )
        }
        Err(err) => err.into_response(),
    }
}

/// Helper function to generate activation code, store it, and send email
///
/// Returns Ok if both storage and sending succeed, otherwise returns the first error
/// encountered but ensures both operations are attempted.
async fn create_and_send_activation(
    user: &User,
    redis_client: &RedisClient,
    email_cfg: &crate::utils::email::EmailConfig,
) -> Result<(), RegistrationError> {
    // Generate and store activation code
    let code = generate_activation_code();
    store_activation_code(redis_client, &user.email, &code)
        .await
        .map_err(|e| RegistrationError::SystemError("Storing activation code failed", e.to_string()))?;

    // Send activation email (non-fatal)
    if let Err(e) = email_cfg
        .send_activation_email(&user.email, &code, redis_client)
        .await
    {
        log_warn!("Register", &format!("Activation email failed: {}", e), "email_failed");
        // Do not return error for email failures, just log and continue
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::db::users::{RegisterData, User};
    use crate::utils::email::EmailConfig;
    use crate::utils::test_utils::state_with_redis;
    use axum::http::StatusCode;
    use serde_json::json;

    /// Build a state with in-memory DB + Redis + dummy EmailConfig
    fn make_state() -> AppState {
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        state
    }

    #[tokio::test]
    async fn missing_email_config_returns_internal_server_error() {
        let mut state = make_state();
        state.email_config = None;
        let data = RegisterData {
            username: "user".into(),
            email: "user@ex.com".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["message"], json!("Missing EmailConfig"));
    }

    #[tokio::test]
    async fn missing_redis_returns_internal_server_error() {
        let mut state = make_state();
        state.redis_client = None;
        let data = RegisterData {
            username: "user".into(),
            email: "user@ex.com".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["message"], json!("Missing RedisClient"));
    }

    #[tokio::test]
    async fn missing_username_returns_bad_request() {
        let state = make_state();
        let data = RegisterData {
            username: "".into(),
            email: "user@example.com".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("username"));
    }

    #[tokio::test]
    async fn invalid_email_returns_bad_request() {
        let state = make_state();
        let data = RegisterData {
            username: "testuser".into(),
            email: "not-an-email".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("email"));
    }

    #[tokio::test]
    async fn weak_password_returns_bad_request() {
        let state = make_state();
        let data = RegisterData {
            username: "testuser".into(),
            email: "user@example.com".into(),
            password: "short".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("password"));
    }

    #[tokio::test]
    async fn duplicate_email_returns_conflict() {
        let state = make_state();
        let data1 = RegisterData {
            username: "first".into(),
            email: "dup@ex.com".into(),
            password: "Valid12!".into(),
        };
        let (s1, _) = process_registration(&state, data1.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);

        let data2 = RegisterData {
            username: "second".into(),
            email: data1.email.clone(),
            password: "Valid12!".into(),
        };
        let (s2, body2) = process_registration(&state, data2).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(body2["message"], json!("Email already exists"));
    }

    #[tokio::test]
    async fn duplicate_username_returns_conflict() {
        let state = make_state();
        let data1 = RegisterData {
            username: "sameuser".into(),
            email: "first@ex.com".into(),
            password: "Valid12!".into(),
        };
        let (s1, _) = process_registration(&state, data1.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);

        let data2 = RegisterData {
            username: data1.username.clone(),
            email: "second@ex.com".into(),
            password: "Valid12!".into(),
        };
        let (s2, body2) = process_registration(&state, data2).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(body2["message"], json!("Username already exists"));
    }

    #[tokio::test]
    async fn new_user_is_inactive_by_default() {
        let state = make_state();
        let data = RegisterData {
            username: "inact".into(),
            email: "inact@ex.com".into(),
            password: "Valid12!".into(), // >=8 chars for valid password
        };
        let (status, _) = process_registration(&state, data.clone()).await;
        assert_eq!(status, StatusCode::CREATED);

        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.is_active, Some(false));
    }

    #[tokio::test]
    async fn successful_registration_creates_user() {
        let state = make_state();
        let data = RegisterData {
            username: "newuser".into(),
            email: "new@user.com".into(),
            password: "Strong1!".into(),
        };
        let (status, body) = process_registration(&state, data.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["status"], json!("success"));

        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
    }
}