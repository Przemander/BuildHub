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
//! - Complete OpenTelemetry observability with hierarchical spans

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    http::StatusCode,  // Add this import
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::Instrument;

use crate::{
    app::AppState,
    handlers::password_reset_logic::{
        process_password_reset_confirm, process_password_reset_request,
    },
    utils::{
        error_new::AuthServiceError,
        telemetry::{http_request_span, business_operation_span, SpanExt},
        log_new::Log,
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

/// Handles password reset link requests.
///
/// # Endpoint: POST /auth/password-reset/request
///
/// Takes an email address and, if it corresponds to a registered user,
/// generates a password reset token and sends an email with instructions.
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/password-reset/request");
    
    // Log email domain for debugging without exposing full PII
    if let Some(domain) = req.email.split('@').nth(1) {
        http_span.record("email_domain", &domain);
    }
    
    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();
    
    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the reset request using structured logging
        Log::event(
            "INFO",
            "Password Reset",
            &format!("Password reset request for email domain: {}", 
                req.email.split('@').nth(1).unwrap_or("invalid")),
            "request_initiated",
            "password_reset_request_handler"
        );

        // Create child business operation span for the actual reset request operation
        let business_span = business_operation_span("password_reset_request");
        
        // Process the reset request within the business span
        let result = process_password_reset_request(&app_state, &req.email)
            .instrument(business_span)
            .await;
        
        // Handle result and update span
        match &result {
            Ok(_) => {
                // For success responses, use OK (200) status code
                http_span.record("http.status_code", &StatusCode::OK.as_u16().to_string());
            }
            Err(err) => {
                // For errors, we can get the status code from the error type
                let status_code = match err {
                    AuthServiceError::Validation(_) => StatusCode::BAD_REQUEST,
                    AuthServiceError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    AuthServiceError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    AuthServiceError::Jwt(_) => StatusCode::UNAUTHORIZED,
                    AuthServiceError::Cache(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    AuthServiceError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
                };
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
            &format!("Password reset confirmation attempt (token length: {}, password length: {})",
                req.token.len(), req.new_password.len()),
            "confirmation_attempt",
            "password_reset_confirm_handler"
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
                // For errors, we can get the status code from the error type
                let status_code = match err {
                    AuthServiceError::Validation(_) => StatusCode::BAD_REQUEST,
                    AuthServiceError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    AuthServiceError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    AuthServiceError::Jwt(_) => StatusCode::UNAUTHORIZED,
                    AuthServiceError::Cache(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    AuthServiceError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
                };
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