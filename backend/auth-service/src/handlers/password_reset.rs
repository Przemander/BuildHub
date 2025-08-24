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

//! Password reset HTTP handlers.
//!
//! Implements secure password reset flow with anti-enumeration protection,
//! rate limiting, and comprehensive observability.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, warn, Instrument, Level};

use crate::{
    app::AppState,
    handlers::password_reset_logic::{
        process_password_reset_confirm, process_password_reset_request,
    },
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

/// Request payload for initiating a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// Request payload for confirming a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    pub token: String,
    pub new_password: String,
}

/// Handles POST /auth/password-reset/request requests.
///
/// # Security
/// Always returns 200 OK to prevent user enumeration attacks.
/// 
/// # Request Format
/// ```json
/// {
///   "email": "user@example.com"
/// }
/// ```
///
/// # Response Format
/// Always returns 200 OK with generic message:
/// ```json
/// {
///   "status": "success",
///   "message": "If the email exists, a password reset link has been sent."
/// }
/// ```
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "POST",
        path = "/auth/password-reset/request",
        email_domain = req.email.split('@').nth(1).unwrap_or("unknown")
    );
    
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/password-reset/request");

    async move {
        info!("Received password reset request");

        // Process request
        let result = process_password_reset_request(&app_state, &req.email).await;

        // Always return 200 OK for security (prevent enumeration)
        // Even if there was an error internally
        metrics::http::request("/auth/password-reset/request", "POST", 200);
        drop(timer);
        
        // Always return success to prevent enumeration
        match result {
            Ok(response) => {
                info!("Password reset request processed successfully");
                Ok(response.into_response())  // Fixed: add .into_response() here
            }
            Err(e) => {
                // Log error internally but still return 200 to client
                error!("Password reset request failed internally: {}", e);
                Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "success",
                        "message": "If the email exists, a password reset link has been sent."
                    })),
                ).into_response())
            }
        }
    }
    .instrument(span)
    .await
}

/// Handles POST /auth/password-reset/confirm requests.
///
/// # Request Format
/// ```json
/// {
///   "token": "secure_token_from_email",
///   "new_password": "NewSecurePassword123!"
/// }
/// ```
///
/// # Response Format
/// - 200 OK: Password successfully reset
/// - 400 Bad Request: Invalid token or password validation failed
/// - 500 Internal Server Error: Server configuration issues
pub async fn password_reset_confirm_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetConfirm>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "POST",
        path = "/auth/password-reset/confirm",
        token_length = req.token.len()
    );
    
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/password-reset/confirm");

    async move {
        info!("Received password reset confirmation");

        // Early validation
        if req.token.is_empty() {
            warn!("Password reset confirmation failed - empty token");
            metrics::http::request("/auth/password-reset/confirm", "POST", 400);
            return Err(AuthServiceError::validation("token", "Token is required"));
        }
        
        if req.new_password.is_empty() {
            warn!("Password reset confirmation failed - empty password");
            metrics::http::request("/auth/password-reset/confirm", "POST", 400);
            return Err(AuthServiceError::validation("new_password", "New password is required"));
        }

        // Process confirmation
        let result = process_password_reset_confirm(
            &app_state,
            &req.token,
            &req.new_password,
        )
        .await;

        // Map result to HTTP status code
        let status = match &result {
            Ok(_) => {
                info!("Password reset confirmation successful");
                StatusCode::OK
            }
            Err(AuthServiceError::Validation { .. }) => {  // Fixed: use struct pattern
                info!("Password reset confirmation failed - validation error");
                StatusCode::BAD_REQUEST
            }
            // Fixed: Removed Jwt variant since it doesn't exist in our simplified error system
            // Token validation errors are now handled as Authentication or External errors
            Err(AuthServiceError::Authentication(_)) => {
                info!("Password reset confirmation failed - invalid token");
                StatusCode::BAD_REQUEST
            }
            Err(AuthServiceError::Configuration(_)) => {
                error!("Password reset confirmation failed - configuration error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Err(e) => {
                error!("Password reset confirmation failed - unexpected error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        
        // Record metrics
        metrics::http::request("/auth/password-reset/confirm", "POST", status.as_u16());
        drop(timer);
        
        result
    }
    .instrument(span)
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

    /// Create test app with mocked dependencies
    fn make_app() -> Router {
        metrics::init();
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        
        Router::new()
            .route("/auth/password-reset/request", post(password_reset_request_handler))
            .route("/auth/password-reset/confirm", post(password_reset_confirm_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn test_request_always_returns_200() {
        let app = make_app();

        // Test with any email
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"email": "any@example.com"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify response message
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["message"].as_str().unwrap().contains("If the email exists"));
    }

    #[tokio::test]
    async fn test_request_with_invalid_email_still_returns_200() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"email": "not-an-email"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should still return 200 for security
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_confirm_empty_token_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({
                        "token": "",
                        "new_password": "ValidPass123!"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        // Verify error message
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["message"].as_str().unwrap().contains("required"));
    }

    #[tokio::test]
    async fn test_confirm_empty_password_returns_400() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({
                        "token": "valid-token",
                        "new_password": ""
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_confirm_invalid_token_returns_400() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({
                        "token": "short",  // Too short to be valid
                        "new_password": "ValidPass123!"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_missing_fields_returns_422() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_malformed_json_returns_422() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{invalid-json}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Fix: Axum returns 400 Bad Request for malformed JSON, not 422
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_missing_redis_request_still_returns_200() {
        metrics::init();
        let mut state = state_with_redis();
        state.redis_client = None;
        state.email_config = Some(EmailConfig::dummy());

        let app = Router::new()
            .route("/auth/password-reset/request", post(password_reset_request_handler))
            .with_state(Arc::new(state));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/request")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"email": "test@example.com"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should still return 200 to prevent enumeration
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_missing_redis_confirm_returns_500() {
        metrics::init();
        let mut state = state_with_redis();
        state.redis_client = None;

        let app = Router::new()
            .route("/auth/password-reset/confirm", post(password_reset_confirm_handler))
            .with_state(Arc::new(state));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({
                        "token": "valid-token-1234567890123456",
                        "new_password": "ValidPass123!"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_weak_password_returns_400() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset/confirm")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({
                        "token": "valid-token-1234567890123456",
                        "new_password": "weak"
                    }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}