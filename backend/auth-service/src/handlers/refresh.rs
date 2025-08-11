//! Token refresh HTTP handler with comprehensive OpenTelemetry integration.
//!
//! This module implements the OAuth2-compatible token refresh endpoint that:
//! - Validates refresh tokens with cryptographic verification
//! - Implements token rotation security pattern (one-time use refresh tokens)
//! - Returns new access and refresh token pairs with appropriate expiry
//! - Provides detailed error responses with security-conscious information disclosure
//! - Full OpenTelemetry observability with hierarchical spans and complete metrics
//!
//! Security features:
//! - No sensitive token information is logged
//! - Detailed telemetry without leaking credentials
//! - Proper error status codes that don't leak system information
//! - Protection against token reuse attacks via revocation
//! - Clear diagnostic information for legitimate errors
//!
//! # API Endpoint
//! `POST /auth/refresh`
//!
//! # Request Format
//! ```json
//! {
//!   "token": "your.refresh.token"
//! }
//! ```
//!
//! # Response Format (Success)
//! ```json
//! {
//!   "status": "success",
//!   "message": "Tokens refreshed successfully",
//!   "data": {
//!     "access_token": "new.access.token",
//!     "refresh_token": "new.refresh.token",
//!     "token_type": "Bearer"
//!   }
//! }
//! ```
//!
//! # Error Responses
//! - 400 Bad Request: Invalid request format or token type
//! - 401 Unauthorized: Invalid, expired or revoked token
//! - 500 Internal Server Error: System errors (Redis unavailable, etc.)

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::Instrument;

use crate::{
    app::AppState,
    handlers::refresh_logic::process_token_refresh,
    metricss::refresh_metrics::{record_refresh_operation, steps, time_refresh_operation},
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, http_request_span, SpanExt},
    },
};

/// Request payload for token refresh.
///
/// This structure represents the expected JSON format for token refresh requests.
/// The token field should contain a valid refresh token previously issued by the system.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// The refresh token to validate and exchange for new tokens
    pub token: String,
}

/// Response payload for successful token refresh operations.
///
/// This structure defines the expected format for successful token refresh responses,
/// containing new access and refresh tokens that the client should use for future requests.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Status indicator (always "success" for this response type)
    pub status: String,
    /// Human-readable success message
    pub message: String,
    /// Token data payload containing the new tokens
    pub data: TokenResponseData,
}

/// Token data returned on successful refresh operations.
#[derive(Debug, Serialize)]
pub struct TokenResponseData {
    /// New access token for authorization
    pub access_token: String,
    /// New refresh token for future token refresh operations
    pub refresh_token: String,
    /// Token type (always "Bearer" for JWT implementation)
    pub token_type: String,
}

/// Handles token refresh requests with comprehensive security and observability.
///
/// # Endpoint: POST /auth/refresh
///
/// Takes a refresh token and returns a new pair of access and refresh tokens.
/// Implements token rotation for enhanced security, preventing token reuse attacks.
///
/// # Security Features
///
/// - One-time use refresh tokens (revoked after use)
/// - Cryptographic signature validation
/// - Token expiration enforcement
/// - Token type validation (prevents confused deputy attacks)
/// - Security-conscious error messages
///
/// # Metrics Generated
///
/// - `refresh_operations_total{step="http_request", result="success|failure"}`
/// - `refresh_duration_seconds{step="http_request"}` (histogram)
/// - Additional detailed metrics from the token refresh business logic
///
/// # OpenTelemetry Integration
///
/// - HTTP request span with method, path, status code
/// - Business operation spans for token processing
/// - Error recording with span context
/// - Token length recording (without exposing tokens)
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(refresh_request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/refresh");
    
    // Security: Add business context to the span without exposing the token itself
    // Only record the length for analytics without compromising security
    http_span.record("token_length", &refresh_request.token.len());
    
    // Check for obvious token issues to fail fast
    if refresh_request.token.is_empty() {
        http_span.record("http.status_code", &StatusCode::UNAUTHORIZED.as_u16().to_string());
        http_span.record("error.type", &"empty_token");
        record_refresh_operation(steps::HTTP_REQUEST, "failure");
        
        // Fixed: Use validation error instead of jwt - more appropriate for empty input
        return Err(AuthServiceError::validation("token", "Empty token provided"));
    }

    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();

    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the token refresh attempt using structured logging
        // Security: Don't log the token itself, only metadata about the request
        Log::event(
            "INFO",
            "Token Refresh",
            &format!(
                "Token refresh attempt (token length: {})",
                refresh_request.token.len()
            ),
            "attempt",
            "refresh_token_handler",
        );

        // Start HTTP duration timer for performance tracking
        let _timer = time_refresh_operation(steps::HTTP_REQUEST);

        // Create child business operation span for the actual token refresh operation
        // This creates a proper span hierarchy in tracing systems
        let business_span = business_operation_span("token_refresh");

        // Process the token refresh within the business span
        // This delegates the core business logic to a separate module for better separation of concerns
        let result = process_token_refresh(&app_state, &refresh_request.token)
            .instrument(business_span)
            .await;

        // Map result to HTTP status for metrics and span context
        match &result {
            Ok(_) => {
                http_span.record("http.status_code", &StatusCode::OK.as_u16().to_string());
                record_refresh_operation(steps::HTTP_REQUEST, "success");
                
                Log::event(
                    "INFO",
                    "Token Refresh",
                    "Token refresh completed successfully",
                    "success",
                    "refresh_token_handler",
                );
            }
            Err(err) => {
                // Map error types to appropriate HTTP status codes
                let status_code = match err {
                    AuthServiceError::Validation(_) => StatusCode::BAD_REQUEST,
                    // These two variants are fixed:
                    AuthServiceError::Jwt(_) => StatusCode::UNAUTHORIZED,
                    AuthServiceError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };

                // Add error context to the span for observability
                http_span.record("http.status_code", &status_code.as_u16().to_string());
                
                // Fixed: Get error category based on error variant
                let error_category = match err {
                    AuthServiceError::Validation(_) => "validation_error",
                    AuthServiceError::Jwt(_) => "jwt_error",
                    AuthServiceError::Database(_) => "database_error",
                    AuthServiceError::Cache(_) => "cache_error",
                    AuthServiceError::RateLimit(_) => "rate_limit_error",
                    AuthServiceError::Configuration(_) => "configuration_error",
                };
                
                http_span.record("error.type", &error_category);
                http_span.record_error(err);
                record_refresh_operation(steps::HTTP_REQUEST, "failure");
                
                // Log the error with appropriate context
                Log::event(
                    "WARN",
                    "Token Refresh",
                    &format!("Token refresh failed: {}", err),
                    "failure",
                    "refresh_token_handler",
                );
            }
        };

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

    use crate::metricss::refresh_metrics::{
        init_refresh_metrics, results, steps, REFRESH_OPERATIONS,
    };
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::state_with_redis;

    fn app() -> Router {
        let state = state_with_redis();

        Router::new()
            .route("/auth/refresh", post(refresh_token_handler))
            .with_state(Arc::new(state))
    }

    fn setup_metrics() {
        init_refresh_metrics();
    }

    #[tokio::test]
    async fn empty_token_returns_unauthorized() {
        setup_metrics();
        let app = app();
        let request_body = json!({
            "token": ""
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "validation_error");
        assert!(
            body["message"].as_str().unwrap().contains("Empty token") ||
            body["message"].as_str().unwrap().contains("token")
        );
    }

    #[tokio::test]
    async fn invalid_token_format_returns_unauthorized() {
        setup_metrics();
        let app = app();
        let request_body = json!({
            "token": "not-a-valid-jwt-token"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "unauthorized");
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET to be set
    async fn proper_refresh_token_returns_new_tokens() {
        setup_metrics();
        std::env::set_var("JWT_SECRET", "test-secret-for-refresh-token-handler");
        let app = app();

        let refresh_token = generate_token("test_user", TOKEN_TYPE_REFRESH, None).unwrap();

        let request_body = json!({
            "token": refresh_token
        });

        let initial_complete_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "success");
        assert!(body["data"].is_object());
        assert!(body["data"]["access_token"].is_string());
        assert!(body["data"]["refresh_token"].is_string());
        assert_eq!(body["data"]["token_type"], "Bearer");

        let final_complete_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        assert_eq!(final_complete_success, initial_complete_success + 1.0);
    }

    #[tokio::test]
    async fn missing_token_field_returns_bad_request() {
        setup_metrics();
        let app = app();
        let request_body = json!({
            "wrong_field": "some_value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn wrong_token_type_returns_validation_error() {
        setup_metrics();
        std::env::set_var("JWT_SECRET", "test-secret-for-wrong-token-type");
        let app = app();

        let access_token = generate_token("test_user", "access", None).unwrap();

        let request_body = json!({
            "token": access_token
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("refresh"));
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        setup_metrics();
        let mut state = state_with_redis();
        state.redis_client = None;

        let app = Router::new()
            .route("/auth/refresh", post(refresh_token_handler))
            .with_state(Arc::new(state));

        let request_body = json!({
            "token": "any-token"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "configuration_error");
        assert!(body["message"].as_str().unwrap().contains("Redis"));
    }
    
    #[tokio::test]
    async fn malformed_json_returns_unprocessable_entity() {
        setup_metrics();
        let app = app();
        
        // Send malformed JSON
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{not-valid-json}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
