//! # Password Reset Endpoints for BuildHub Auth Service
//!
//! This module implements a secure, standards-compliant password reset flow
//! following OWASP security best practices and NIST guidelines:
//!
//! ## Request Phase (First Step)
//!
//! **Endpoint:** `POST /auth/password-reset/request`
//!
//! 1. User submits their email address
//! 2. System generates a cryptographically secure one-time token (256-bit entropy)
//! 3. Token is stored in Redis with time-limited expiry (30 minutes)
//! 4. Reset email is sent with secure token-based URL
//! 5. User receives consistent response regardless of email existence (anti-enumeration)
//!
//! ## Confirm Phase (Second Step)
//!
//! **Endpoint:** `POST /auth/password-reset/confirm`
//!
//! 1. User submits token from email and new password
//! 2. System validates token authenticity and expiration
//! 3. Password is validated against security requirements (NIST SP 800-63B)
//! 4. Password is updated and token is invalidated
//! 5. User receives success confirmation
//!
//! ## Security Features
//!
//! - **Anti-Enumeration:** Same timing and response regardless of email existence
//! - **Rate Limiting:** Protection against brute force attempts
//! - **Secure Tokens:** 256-bit entropy with URL-safe encoding
//! - **Time-Limited:** 30-minute token expiration
//! - **Single-Use:** Tokens invalidated after use
//! - **Password Validation:** Enforces NIST password requirements
//! - **PII Protection:** Minimal logging of sensitive data
//! - **Distributed Tracing:** Full observability with context propagation

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::Instrument;

use crate::{
    app::AppState,
    handlers::password_reset_logic::{
        process_password_reset_confirm, process_password_reset_request,
    },
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, http_request_span, SpanExt},
    },
};

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

/// Extracts and returns the domain part of an email address safely.
///
/// Used to log domain information without exposing the full email address,
/// protecting Personally Identifiable Information (PII).
///
/// # Arguments
/// * `email` - The email address to extract domain from
///
/// # Returns
/// * The domain part of the email, or "invalid" if no @ symbol found
#[inline]
fn extract_email_domain(email: &str) -> &str {
    email.split('@').nth(1).unwrap_or("invalid")
}

/// Maps an AuthServiceError to the appropriate HTTP status code.
///
/// Used to ensure consistent HTTP status code mapping across handlers.
///
/// # Arguments
/// * `err` - The error to map to a status code
///
/// # Returns
/// * The corresponding HTTP status code
#[inline]
fn error_to_status_code(err: &AuthServiceError) -> StatusCode {
    match err {
        AuthServiceError::Validation(_) => StatusCode::BAD_REQUEST,
        AuthServiceError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
        AuthServiceError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        AuthServiceError::Jwt(_) => StatusCode::UNAUTHORIZED,
        AuthServiceError::Cache(_) => StatusCode::INTERNAL_SERVER_ERROR,
        AuthServiceError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
    }
}

/// Handles password reset link requests.
///
/// # Endpoint: POST /auth/password-reset/request
///
/// Takes an email address and, if it corresponds to a registered user,
/// generates a password reset token and sends an email with instructions.
///
/// # Security Notes
///
/// - Returns same response regardless of whether email exists to prevent enumeration
/// - Logs minimal PII - only email domain for troubleshooting
/// - Full observability through hierarchical spans and contextual logging
///
/// # Request Body
///
/// ```json
/// {
///   "email": "user@example.com"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - Request processed (regardless of email existence)
/// * `400 Bad Request` - Email format invalid
/// * `500 Internal Server Error` - Redis or other infrastructure error
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/password-reset/request");

    // Extract and clone email string to avoid borrowing issues with async move
    let email = req.email.clone();

    // Capture email domain **by value** (String) so it no longer borrows `email`
    let domain = extract_email_domain(&email).to_owned();
    http_span.record("email_domain", &domain);

    // Record email length for analytics without revealing content
    http_span.record("email_length", &email.len());

    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();

    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the reset request using structured logging
        Log::event(
            "INFO",
            "Password Reset",
            &format!("Password reset request for email domain: {}", domain),
            "request_initiated",
            "password_reset_request_handler",
        );

        // Create child business operation span for the actual reset request operation
        let business_span = business_operation_span("password_reset_request");

        // Process the reset request within the business span
        let result = process_password_reset_request(&app_state, &email)
            .instrument(business_span)
            .await;

        // Handle result and update span
        match &result {
            Ok(_) => {
                // For success responses, use OK (200) status code
                http_span.record("http.status_code", &StatusCode::OK.as_u16().to_string());
            }
            Err(err) => {
                // For errors, map to appropriate status code
                let status_code = error_to_status_code(err);
                http_span.record("http.status_code", &status_code.as_u16().to_string());
                http_span.record_error(err);
            }
        }

        // Return the result, letting ? operator handle error conversion
        result
    }
    .instrument(http_span_clone)
    .await
}

/// Handles password reset confirmation.
///
/// # Endpoint: POST /auth/password-reset/confirm
///
/// Takes a reset token and new password, validates both, and if valid,
/// updates the user's password.
///
/// # Security Notes
///
/// - Validates token authenticity and expiration before processing
/// - Enforces password strength requirements (NIST guidelines)
/// - Token is invalidated after use to prevent reuse
/// - Logs no PII - only metadata like token and password length
///
/// # Request Body
///
/// ```json
/// {
///   "token": "secure-reset-token-from-email",
///   "new_password": "user's new password"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - Password successfully reset
/// * `400 Bad Request` - Token invalid or password doesn't meet requirements
/// * `401 Unauthorized` - Token expired
/// * `500 Internal Server Error` - Database or infrastructure error
pub async fn password_reset_confirm_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetConfirm>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/password-reset/confirm");

    // Add business context to the span without exposing sensitive information
    http_span.record("token_length", &req.token.len());
    http_span.record("password_length", &req.new_password.len());

    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();

    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the reset confirmation using structured logging
        Log::event(
            "INFO",
            "Password Reset",
            &format!(
                "Password reset confirmation attempt (token length: {}, password length: {})",
                req.token.len(),
                req.new_password.len()
            ),
            "confirmation_attempt",
            "password_reset_confirm_handler",
        );

        // Create child business operation span for the actual reset confirmation operation
        let business_span = business_operation_span("password_reset_confirm");

        // Process the reset confirmation within the business span
        let result = process_password_reset_confirm(&app_state, &req.token, &req.new_password)
            .instrument(business_span)
            .await;

        // Handle result and update span
        match &result {
            Ok(_) => {
                // For success responses, use OK (200) status code
                http_span.record("http.status_code", &StatusCode::OK.as_u16().to_string());
            }
            Err(err) => {
                // For errors, map to appropriate status code
                let status_code = error_to_status_code(err);
                http_span.record("http.status_code", &status_code.as_u16().to_string());
                http_span.record_error(err);
            }
        }

        // Return the result, letting ? operator handle error conversion
        result
    }
    .instrument(http_span_clone)
    .await
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
            .route(
                "/auth/password-reset/request",
                post(password_reset_request_handler),
            )
            .route(
                "/auth/password-reset/confirm",
                post(password_reset_confirm_handler),
            )
            .with_state(Arc::new(state))
    }

    /// Helper to make a POST request to the specified endpoint
    async fn make_post_request(
        app: Router,
        endpoint: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        (status, body_json)
    }

    #[tokio::test]
    async fn reset_request_with_valid_email_returns_success() {
        // Arrange
        let app = app();
        let request_body = json!({
            "email": "test@example.com"
        });

        // Act
        let (status, body) = make_post_request(
            app,
            "/auth/password-reset/request",
            request_body,
        ).await;

        // Assert - We should get 200 OK regardless of whether the email exists
        assert_eq!(status, StatusCode::OK);
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
        let (status, body) = make_post_request(
            app,
            "/auth/password-reset/request",
            request_body,
        ).await;

        // Assert - Should return success regardless of email validity (security feature)
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["status"], "success",
            "Status should be 'success' regardless of email validity (security feature)"
        );
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("If the email exists"),
            "Message should be generic to prevent email enumeration"
        );
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
        let (status, body) = make_post_request(
            app,
            "/auth/password-reset/confirm",
            request_body,
        ).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
        let (status, body) = make_post_request(
            app,
            "/auth/password-reset/confirm",
            request_body,
        ).await;

        // Assert - Token validation happens first, so we get validation error
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
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
            .route(
                "/auth/password-reset/request",
                post(password_reset_request_handler),
            )
            .with_state(Arc::new(state));

        let request_body = json!({
            "email": "test@example.com"
        });

        // Act
        let (status, body) = make_post_request(
            app,
            "/auth/password-reset/request",
            request_body,
        ).await;

        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
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
            .route(
                "/auth/password-reset/confirm",
                post(password_reset_confirm_handler),
            )
            .with_state(Arc::new(state));

        let request_body = json!({
            "token": "any-token",
            "new_password": "ValidPass123!"
        });

        // Act
        let (status, body) = make_post_request(
            app,
            "/auth/password-reset/confirm",
            request_body,
        ).await;

        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["status"], "configuration_error");
        assert!(body["message"].as_str().unwrap().contains("Redis"));
    }
}