//! # User Registration Business Logic
//!
//! This module implements a secure and robust user registration flow. It is designed
//! to be resilient, observable, and follows security best practices.
//!
//! ## Flow
//! 1.  **Configuration & Input Validation**: Checks for required service configurations
//!     (Email, Redis) and validates user-provided data (username, email, password).
//! 2.  **Database Operations**: In a single, atomic, non-blocking transaction:
//!     - A new user record is created.
//!     - The database's unique constraints are used to prevent duplicate emails/usernames,
//!       eliminating race conditions.
//! 3.  **Activation Code**: A cryptographically secure activation code is generated and
//!     stored in Redis with a TTL.
//! 4.  **Email Dispatch**: A background "fire-and-forget" task is spawned to send the
//!     activation email, ensuring the user gets a fast API response. This task has its
//!     own timeout to protect against external service failures.
//! 5.  **Success Response**: A `201 Created` response is returned with a unique request ID
//!     for traceability.
//!
//! ## Security & Resilience
//! - **Password Hashing**: Handled by the `User` model, using Argon2id.
//! - **Race Condition Prevention**: Relies on the database's atomic constraint checks
//!   instead of a separate "check-then-insert" pattern.
//! - **Resilience**: The email sending process is isolated and time-limited, preventing
//!   failures in the email service from impacting the core registration flow.
//! - **Observability**: The entire flow is wrapped in a `tracing` span with a unique
//!   request ID. All operations, including background tasks, are instrumented.

use crate::{
    app::AppState,
    config::{database::get_connection, redis::store_activation_code},
    db::users::User,
    handlers::register::RegisterData,
    utils::metrics,
    utils::{
        email::generate_activation_code,
        errors::AuthServiceError,
        validators::{validate_email, validate_password, validate_username},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tokio::task::spawn_blocking;
use tokio::time::{timeout, Duration};
use tracing::{error, info, span, warn, Instrument, Level};
use uuid::Uuid;

/// Timeout for sending activation emails.
const EMAIL_SEND_TIMEOUT_SECS: u64 = 8;

/// Processes a user registration request.
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> Result<impl IntoResponse, AuthServiceError> {
    let request_id = Uuid::new_v4().to_string();

    let span = span!(Level::INFO, "registration",
        request_id = %request_id,
        username = %data.username,
        email_domain = data.email.split('@').nth(1).unwrap_or("unknown")
    );

    let request_id_for_response = request_id.clone();

    async move {
        info!("Starting registration process");

        let email_cfg = app_state.email_config.as_ref().ok_or_else(|| {
            error!("Email configuration missing - service misconfigured");
            metrics::auth::register_failure();
            AuthServiceError::configuration("Email service not configured")
        })?;

        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client missing - service misconfigured");
            metrics::auth::register_failure();
            AuthServiceError::configuration("Redis service not configured")
        })?;

        validate_inputs(&data).map_err(|e| {
            warn!("Input validation failed: {}", e);
            metrics::auth::register_failure();
            e
        })?;
        info!("Input validation passed");

        let db_span = span!(Level::INFO, "db_operations");
        let pool = app_state.pool.clone();
        let user = spawn_blocking(move || {
            let mut conn = get_connection(&pool)?;
            let new_user = User::new_for_insert(&data.username, &data.email, &data.password);
            User::save_new(new_user, &mut conn)
        })
        .instrument(db_span)
        .await
        .map_err(|e| {
            error!("Database task panicked: {}", e);
            AuthServiceError::internal("Database task failed")
        })??;

        info!(user_id = %user.id, "User created successfully in database");

        let activation_span = span!(Level::INFO, "activation_setup");
        let code = async {
            let code = generate_activation_code();
            info!("Generated activation code");

            store_activation_code(redis_client, &user.email, &code)
                .await
                .map_err(|e| {
                    error!("Failed to store activation code in Redis: {}", e);
                    metrics::auth::register_failure();
                    AuthServiceError::from(e)
                })?;

            info!("Activation code stored in Redis");
            Ok::<_, AuthServiceError>(code)
        }
        .instrument(activation_span)
        .await?;

        spawn_activation_email(email_cfg.clone(), user.email.clone(), code);

        metrics::auth::register_success();
        info!(
            user_id = %user.id,
            request_id = %request_id_for_response,
            "Registration completed successfully"
        );

        Ok((
            StatusCode::CREATED,
            Json(json!({
                "status": "success",
                "message": "Registration successful! Please check your email to activate your account.",
                "request_id": request_id_for_response
            })),
        ))
    }
    .instrument(span)
    .await
}

/// A helper function to validate all registration input fields.
#[inline]
fn validate_inputs(data: &RegisterData) -> Result<(), AuthServiceError> {
    validate_username(&data.username)?;
    validate_email(&data.email)?;
    validate_password(&data.password)?;
    Ok(())
}

/// Spawns a "fire-and-forget" background task to send the activation email.
///
/// This function is designed for resilience. It detaches the email sending process
/// from the main request-response cycle and wraps it in a timeout to prevent a slow
/// or failing email server from consuming system resources indefinitely.
fn spawn_activation_email(
    email_cfg: crate::utils::email::EmailConfig,
    email: String,
    code: String,
) {
    tokio::spawn(async move {
        let span = span!(Level::INFO, "send_activation_email",
            email_domain = email.split('@').nth(1).unwrap_or("unknown")
        );
        let _enter = span.enter();

        info!("Attempting to send activation email");

        let send_fut = email_cfg.send_activation_email(&email, &code);

        match timeout(Duration::from_secs(EMAIL_SEND_TIMEOUT_SECS), send_fut).await {
            Ok(Ok(())) => {
                info!("Activation email sent successfully");
            }
            Ok(Err(e)) => {
                error!("Failed to send activation email: {}", e);
            }
            Err(_) => {
                error!("Activation email timed out after {}s", EMAIL_SEND_TIMEOUT_SECS);
                metrics::external::email_failure("timeout");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::email::EmailConfig;
    use crate::utils::test_utils::state_with_redis;

    /// Creates a test-ready AppState with mocked Redis and Email configuration.
    fn make_state() -> AppState {
        metrics::init();
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        state
    }

    #[tokio::test]
    async fn test_missing_email_config() {
        let mut state = make_state();
        state.email_config = None;

        let data = RegisterData {
            username: "testuser".into(),
            email: "test@example.com".into(),
            password: "Valid123!".into(),
        };

        let result = process_registration(&state, data).await;
        assert!(matches!(result, Err(AuthServiceError::Configuration(_))));
    }

    #[tokio::test]
    async fn test_invalid_username() {
        let state = make_state();

        let data = RegisterData {
            username: "ab".into(), // Too short
            email: "test@example.com".into(),
            password: "Valid123!".into(),
        };

        let result = process_registration(&state, data).await;
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_duplicate_email() {
        let state = make_state();

        let first = RegisterData {
            username: "user1".into(),
            email: "duplicate@example.com".into(),
            password: "Valid123!".into(),
        };

        assert!(process_registration(&state, first.clone()).await.is_ok());

        let second = RegisterData {
            username: "user2".into(),
            email: first.email.clone(),
            password: "Valid123!".into(),
        };

        let result = process_registration(&state, second).await;
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_successful_registration() {
        let state = make_state();

        std::env::set_var("TEST_MODE", "true");

        let uuid = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let data = RegisterData {
            username: format!("user_{}", uuid),
            email: format!("new_{}@example.com", uuid),
            password: "StrongPassword123!".into(),
        };

        let result = process_registration(&state, data.clone()).await;
        assert!(result.is_ok(), "Registration failed: {:?}", result.err());

        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
        assert!(!user.is_active);

        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_validate_inputs_valid_data() {
        let data = RegisterData {
            username: "validuser".to_string(),
            email: "valid@email.com".to_string(),
            password: "ValidPassword123!".to_string(),
        };
        assert!(validate_inputs(&data).is_ok());
    }

    #[test]
    fn test_validate_inputs_invalid_username() {
        let data = RegisterData {
            username: "a".to_string(), // too short
            email: "valid@email.com".to_string(),
            password: "ValidPassword123!".to_string(),
        };
        let result = validate_inputs(&data);
        assert!(matches!(
            result,
            Err(AuthServiceError::Validation { ref field, .. }) if field == "username"
        ));
    }

    #[test]
    fn test_validate_inputs_invalid_email() {
        let data = RegisterData {
            username: "validuser".to_string(),
            email: "invalid-email".to_string(),
            password: "ValidPassword123!".to_string(),
        };
        let result = validate_inputs(&data);
        assert!(matches!(
            result,
            Err(AuthServiceError::Validation { ref field, .. }) if field == "email"
        ));
    }

    #[test]
    fn test_validate_inputs_invalid_password() {
        let data = RegisterData {
            username: "validuser".to_string(),
            email: "valid@email.com".to_string(),
            password: "weak".to_string(),
        };
        let result = validate_inputs(&data);
        assert!(matches!(
            result,
            Err(AuthServiceError::Validation { ref field, .. }) if field == "password"
        ));
    }

    #[test]
    fn test_validate_inputs_multiple_errors_fails_on_first() {
        // `validate_username` is first, so this error should be returned
        let data = RegisterData {
            username: "a".to_string(),         // invalid
            email: "invalid-email".to_string(), // also invalid
            password: "weak".to_string(),       // also invalid
        };
        let result = validate_inputs(&data);
        assert!(matches!(
            result,
            Err(AuthServiceError::Validation { ref field, .. }) if field == "username"
        ));
    }
}