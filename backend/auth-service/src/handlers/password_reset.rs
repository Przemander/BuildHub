//! Password reset endpoints for BuildHub Auth Service.
//!
//! This module implements a secure, two-step password reset flow:
//!
//! 1. **Request Phase**: User requests a reset link sent to their email
//!    - POST /auth/password-reset/request: Initiates the reset process
//!    - Generates a secure, time-limited token stored in Redis
//!    - Sends an email containing the reset link to the user
//!
//! 2. **Reset Phase**: User confirms the reset with token and new password
//!    - POST /auth/password-reset/confirm: Completes the reset process
//!    - Validates the token and password requirements
//!    - Updates the password and invalidates the token
//!
//! Security features include:
//! - Time-limited tokens with secure generation
//! - Single-use tokens (invalidated after use)
//! - Rate limiting protection
//! - Secure password requirements enforcement
//! - Same response timing regardless of whether email exists (prevents user enumeration)
//! - Unified error handling with automatic HTTP response conversion

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::password_reset_logic::{
    process_password_reset_confirm, process_password_reset_request,
};
use crate::utils::error_new::AuthServiceError; // ← Add unified error system

/// Request payload for initiating a password reset.
///
/// The user provides their email address, and if it exists in the system,
/// they will receive a password reset link via email.
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    /// The email address associated with the user account
    pub email: String,
}

/// Request payload for confirming a password reset.
///
/// The user provides the reset token (from the email link) along with
/// their desired new password.
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    /// The reset token received via email
    pub token: String,
    
    /// The new password to set for the account
    pub new_password: String,
}

/// Handles password reset link requests.
///
/// # Endpoint: POST /auth/password-reset/request
///
/// Takes an email address and, if it corresponds to a registered user,
/// generates a password reset token and sends an email with instructions.
///
/// ## Request Body
/// ```json
/// {
///   "email": "user@example.com"
/// }
/// ```
///
/// ## Responses
///
/// * `200 OK` - Request processed (sent only if email exists)
/// * `400 Bad Request` - Invalid email format
/// * `500 Internal Server Error` - Server-side error
///
/// ## Security Note
///
/// Always returns 200 OK even if the email doesn't exist, to prevent
/// user enumeration attacks. The actual email is only sent if the account exists.
///
/// ## Example success response
/// ```json
/// {
///   "status": "success",
///   "message": "If the email exists, a password reset link has been sent."
/// }
/// ```
///
/// ## Example error response
/// ```json
/// {
///   "status": "configuration_error",
///   "message": "Redis client not available for password reset operations"
/// }
/// ```
#[instrument(
    name = "password_reset_request",
    level = "info",
    skip(app_state, req),
    fields(
        path = "/auth/password-reset/request", 
        method = "POST",
        email_domain = tracing::field::Empty
    )
)]
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<impl IntoResponse, AuthServiceError> { // ← Changed return type
    // Log email domain for debugging without exposing full PII
    if let Some(domain) = req.email.split('@').nth(1) {
        tracing::Span::current().record("email_domain", &tracing::field::display(domain));
    }
    
    // Process the password reset request using unified error system
    // The ? operator will automatically convert AuthServiceError to HTTP response
    process_password_reset_request(&app_state, &req.email).await
}

/// Handles password reset confirmations.
///
/// # Endpoint: POST /auth/password-reset/confirm
///
/// Validates the reset token and updates the user's password if valid.
///
/// ## Request Body
/// ```json
/// {
///   "token": "reset-token-from-email",
///   "new_password": "NewSecureP@ssw0rd"
/// }
/// ```
///
/// ## Responses
///
/// * `200 OK` - Password successfully reset
/// * `400 Bad Request` - Invalid password format or requirements not met
/// * `401 Unauthorized` - Invalid or expired token
/// * `500 Internal Server Error` - Server-side error
///
/// ## Security Note
///
/// The token is single-use and will be invalidated after a successful reset.
/// The new password must meet the system's password strength requirements.
///
/// ## Example success response
/// ```json
/// {
///   "status": "success",
///   "message": "Password has been reset successfully."
/// }
/// ```
///
/// ## Example error responses
/// ```json
/// {
///   "status": "validation_error",
///   "message": "token: Invalid or expired reset token"
/// }
/// ```
/// ```json
/// {
///   "status": "validation_error", 
///   "message": "password: Password must be at least 8 characters long"
/// }
/// ```
#[instrument(
    name = "password_reset_confirm",
    level = "info",
    skip(app_state, req),
    fields(
        path = "/auth/password-reset/confirm", 
        method = "POST",
        token_length = tracing::field::Empty,
        password_length = tracing::field::Empty
    )
)]
pub async fn password_reset_confirm_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetConfirm>,
) -> Result<impl IntoResponse, AuthServiceError> { // ← Changed return type
    // Log metadata without exposing sensitive information
    tracing::Span::current()
        .record("token_length", &tracing::field::display(req.token.len()))
        .record("password_length", &tracing::field::display(req.new_password.len()));
    
    // Process the password reset confirmation using unified error system
    // The ? operator will automatically convert AuthServiceError to HTTP response
    process_password_reset_confirm(&app_state, &req.token, &req.new_password).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::json;
    use tower::ServiceExt;

    use crate::utils::email::EmailConfig;
    use crate::utils::test_utils::state_with_redis;

    /// Creates a test router with both password reset handlers
    fn app() -> Router {
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        
        Router::new()
            .route("/auth/password-reset/request", post(password_reset_request_handler))
            .route("/auth/password-reset/confirm", post(password_reset_confirm_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn reset_request_with_valid_email_returns_success() {
        // Arrange
        let app = app();
        let request_body = json!({
            "email": "test@example.com"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - We should get 200 OK regardless of whether the email exists
        assert_eq!(response.status(), StatusCode::OK);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "success");
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("If the email exists"));
    }

    #[tokio::test]
    async fn reset_request_with_invalid_email_returns_success() {
        // Arrange
        let app = app();
        let request_body = json!({
            "email": "not-an-email-address"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - Should return success regardless of email validity (security feature)
        assert_eq!(response.status(), StatusCode::OK);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "success", 
            "Status should be 'success' regardless of email validity (security feature)");
        assert!(body["message"].as_str().unwrap().contains("If the email exists"), 
            "Message should be generic to prevent email enumeration");
    }

    #[tokio::test]
    async fn reset_confirm_with_invalid_token_returns_validation_error() {
        // Arrange
        let app = app();
        let request_body = json!({
            "token": "invalid-token",
            "new_password": "ValidNewP@ss123"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        // With unified error system, invalid token is a validation error
        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("token"));
    }

    #[tokio::test]
    async fn reset_confirm_with_weak_password_returns_validation_error() {
        // Arrange
        let app = app();
        let request_body = json!({
            "token": "some-valid-token",  // Token validation will fail first
            "new_password": "weak"        // Too short, doesn't meet requirements
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - Token validation happens first, so we get validation error
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        // With unified error system, both token and password issues are validation errors
        assert_eq!(body["status"], "validation_error");
    }

    #[tokio::test]
    async fn missing_fields_returns_bad_request() {
        // Arrange
        let app = app();
        let request_body = json!({
            // Missing required "email" field
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - accept either 400 or 422 as both are used for validation errors by Axum JSON extractor
        assert!(
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Response status should be 400 Bad Request or 422 Unprocessable Entity"
        );
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        // Arrange - Create state without Redis
        let mut state = state_with_redis();
        state.redis_client = None; // Remove Redis client
        state.email_config = Some(EmailConfig::dummy());
        
        let app = Router::new()
            .route("/auth/password-reset/request", post(password_reset_request_handler))
            .with_state(Arc::new(state));

        let request_body = json!({
            "email": "test@example.com"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "configuration_error");
        assert!(body["message"].as_str().unwrap().contains("Redis"));
    }

    #[tokio::test]
    async fn missing_redis_confirm_returns_configuration_error() {
        // Arrange - Create state without Redis
        let mut state = state_with_redis();
        state.redis_client = None; // Remove Redis client
        state.email_config = Some(EmailConfig::dummy());
        
        let app = Router::new()
            .route("/auth/password-reset/confirm", post(password_reset_confirm_handler))
            .with_state(Arc::new(state));

        let request_body = json!({
            "token": "any-token",
            "new_password": "ValidPass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "configuration_error");
        assert!(body["message"].as_str().unwrap().contains("Redis"));
    }
}