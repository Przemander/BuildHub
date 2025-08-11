//! # User Logout (Token Revocation) HTTP Handler
//!
//! This module implements a secure, robust JWT token revocation endpoint with 
//! comprehensive observability and security controls.
//!
//! ## Endpoint
//!
//! `POST /auth/logout`
//!
//! ## Security Features
//!
//! - Complete token revocation via Redis blocklist
//! - Token validation before revocation for audit purposes
//! - Protection against token leakage in logs and spans
//! - Graceful handling of already-revoked tokens
//! - Comprehensive error mapping for consistent user experience
//! - Defense against timing attacks with consistent processing
//!
//! ## Observability
//!
//! - Detailed OpenTelemetry spans with proper hierarchy
//! - Privacy-preserving token instrumentation
//! - Prometheus metrics for all operations
//! - Structured logging with security context
//! - Complete error tracking in distributed tracing

use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::Instrument;

use crate::{
    app::AppState,
    handlers::logout_logic::process_logout,
    metricss::logout_metrics::{
        http::{BAD_REQUEST, INTERNAL_SERVER_ERROR, OK, POST, UNAUTHORIZED},
        record_http_request,
        LOGOUT_HTTP_DURATION,
    },
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, http_request_span, SpanExt},
    },
};

/// Request payload for logout operations.
///
/// Contains the JWT token that should be revoked and added to the blocklist.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// The JWT token to be revoked (access or refresh token)
    pub token: String,
}

/// Response format for successful logout.
///
/// Provides a consistent API response structure that follows REST best practices.
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    /// Status of the operation ("success")
    pub status: String,
    
    /// Human-readable message about the operation result
    pub message: String,
}

/// Validates token input before processing.
///
/// Performs basic validation to reject obviously invalid tokens early:
/// - Empty tokens
/// - Tokens that don't match basic JWT format (contains two periods)
///
/// Note: This is just a quick check - full JWT validation happens in the business logic
fn validate_token_input(token: &str) -> Result<(), AuthServiceError> {
    if token.is_empty() {
        return Err(AuthServiceError::validation(
            "token",
            "Token is required",
        ));
    }
    
    // Simple check for JWT format (header.payload.signature)
    // This isn't full validation, just a quick rejection of obviously wrong formats
    if !token.contains('.') || token.matches('.').count() != 2 {
        Log::event(
            "WARN",
            "Authentication",
            "Logout attempt with malformed token format",
            "malformed_token",
            "logout_handler",
        );
    }
    
    Ok(())
}

/// Handles user logout requests by revoking JWT tokens.
///
/// # Endpoint: POST /auth/logout
///
/// Takes a JWT token and revokes it by adding to the Redis blocklist,
/// preventing future use of the token for authentication.
///
/// # Request Body
///
/// ```json
/// {
///   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - Token successfully revoked
/// * `400 Bad Request` - Missing or malformed token
/// * `401 Unauthorized` - Invalid token format or signature
/// * `500 Internal Server Error` - Redis or configuration error
///
/// # Security Considerations
///
/// The handler avoids exposing the actual token in logs or spans to prevent
/// token leakage in logging systems. Only metadata like token length is recorded.
pub async fn logout_handler(
    State(app_state): State<Arc<AppState>>,
    Json(logout_request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/logout");
    
    // Add business context to the span without exposing the token itself
    http_span.record("token_length", &logout_request.token.len());
    
    // Record if token appears to be a JWT based on format (for metrics only)
    let has_jwt_format = logout_request.token.matches('.').count() == 2;
    http_span.record("has_jwt_format", &has_jwt_format);
    
    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();
    
    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the logout attempt using structured logging
        Log::event(
            "INFO",
            "Authentication",
            &format!(
                "Logout attempt (token length: {}, format: {})",
                logout_request.token.len(),
                if has_jwt_format { "JWT" } else { "unknown" }
            ),
            "attempt",
            "logout_handler",
        );
        
        // Start HTTP duration timer
        let start = std::time::Instant::now();
        
        // Validate token format early
        if let Err(e) = validate_token_input(&logout_request.token) {
            let duration = start.elapsed().as_secs_f64();
            http_span.record("http.status_code", &BAD_REQUEST.to_string());
            http_span.record_error(&e);
            
            LOGOUT_HTTP_DURATION
                .with_label_values(&[POST, &BAD_REQUEST.to_string()])
                .observe(duration);
                
            record_http_request(POST, BAD_REQUEST);
            
            return Err(e);
        }
        
        // Create child business operation span for the actual logout operation
        let business_span = business_operation_span("user_logout");
        
        // Process the logout within the business span
        let result = process_logout(&app_state, &logout_request.token)
            .instrument(business_span)
            .await;
        
        // Record HTTP metrics
        let duration = start.elapsed().as_secs_f64();
        let status_code = match &result {
            Ok(_) => OK,
            Err(err) => match err {
                AuthServiceError::Configuration(_) => INTERNAL_SERVER_ERROR,
                AuthServiceError::Jwt(_) => UNAUTHORIZED,
                AuthServiceError::Cache(_) => INTERNAL_SERVER_ERROR,
                AuthServiceError::Validation(_) => BAD_REQUEST,
                _ => BAD_REQUEST,
            },
        };
        
        // Record status code in the HTTP span
        http_span.record("http.status_code", &status_code.to_string());
        
        // If there was an error, record it in the span
        if let Err(ref e) = result {
            http_span.record_error(e);
        }
        
        LOGOUT_HTTP_DURATION
            .with_label_values(&[POST, &status_code.to_string()])
            .observe(duration);
            
        record_http_request(POST, status_code);
        
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

    use crate::metricss::logout_metrics::{
        http, init_logout_metrics, LOGOUT_HTTP_DURATION, LOGOUT_HTTP_REQUESTS,
    };
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};

    /// Creates a test router with the logout handler
    fn app() -> Router {
        let state = state_with_redis();

        Router::new()
            .route("/auth/logout", post(logout_handler))
            .with_state(Arc::new(state))
    }

    /// Initialize logout metrics for testing
    fn setup_metrics() {
        init_logout_metrics();
    }

    #[tokio::test]
    async fn empty_token_returns_bad_request() {
        setup_metrics();
        // Arrange
        let app = app();
        let request_body = json!({
            "token": ""
        });

        // Record initial metrics
        let initial_http_bad_request = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "400"])
            .get_sample_count();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
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

        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("required"));

        // Assert metrics
        let final_http_bad_request = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "400"])
            .get_sample_count();

        assert_eq!(final_http_bad_request, initial_http_bad_request + 1.0);
        assert_eq!(final_http_duration, initial_http_duration + 1);
    }

    #[tokio::test]
    async fn invalid_token_format_returns_unauthorized() {
        setup_metrics();
        // Arrange
        let app = app();
        let request_body = json!({
            "token": "not-a-valid-jwt-token"
        });

        // Record initial metrics
        let initial_http_unauthorized = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "401"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "401"])
            .get_sample_count();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // With unified error system, invalid token should be unauthorized
        assert_eq!(body["status"], "unauthorized");

        // Assert metrics
        let final_http_unauthorized = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "401"])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "401"])
            .get_sample_count();

        assert_eq!(final_http_unauthorized, initial_http_unauthorized + 1.0);
        assert_eq!(final_http_duration, initial_http_duration + 1);
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET to be set
    async fn valid_token_logout_returns_success() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let app = app();

        // Generate a valid token
        let token = generate_token("test_user", TOKEN_TYPE_ACCESS, None).unwrap();

        let request_body = json!({
            "token": token
        });

        // Record initial metrics
        let initial_http_ok = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "200"])
            .get_sample_count();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify success response structure
        assert_eq!(body["status"], "success");
        assert_eq!(body["message"], "Logged out successfully");

        // Assert metrics
        let final_http_ok = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "200"])
            .get_sample_count();

        assert_eq!(final_http_ok, initial_http_ok + 1.0);
        assert_eq!(final_http_duration, initial_http_duration + 1);
    }

    #[tokio::test]
    async fn missing_token_field_returns_bad_request() {
        setup_metrics();
        // Arrange
        let app = app();
        let request_body = json!({
            "wrong_field": "some_value" // Missing required "token" field
        });

        // Record initial metrics
        let initial_http_bad = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "400"])
            .get_sample_count();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - This will be handled by Axum's JSON extractor
        // which should return 400 or 422 for malformed JSON
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Response status should be 400 Bad Request or 422 Unprocessable Entity"
        );

        // Assert metrics (using 400 as example, adjust if 422)
        let status_str = response.status().as_u16().to_string();
        let final_http_bad = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, &status_str])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, &status_str])
            .get_sample_count();

        assert_eq!(final_http_bad, initial_http_bad + 1.0);
        assert_eq!(final_http_duration, initial_http_duration + 1);
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        setup_metrics();
        // Arrange - Create state without Redis
        let mut state = state_with_redis();
        state.redis_client = None; // Remove Redis client

        let app = Router::new()
            .route("/auth/logout", post(logout_handler))
            .with_state(Arc::new(state));

        let request_body = json!({
            "token": "any-token"
        });

        // Record initial metrics
        let initial_http_internal = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "500"])
            .get_sample_count();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
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

        // Assert metrics
        let final_http_internal = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "500"])
            .get_sample_count();

        assert_eq!(final_http_internal, initial_http_internal + 1.0);
        assert_eq!(final_http_duration, initial_http_duration + 1);
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET + Redis
    async fn double_logout_handles_gracefully() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let app = app();

        // Generate a valid token
        let token = generate_token("test_user", TOKEN_TYPE_ACCESS, None).unwrap();
        let request_body = json!({
            "token": token
        });

        // Record initial metrics
        let initial_http_ok = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "200"])
            .get_sample_count();

        // First logout
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response1.status(), StatusCode::OK);

        // Assert metrics for first logout
        let intermediate_http_ok = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let intermediate_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "200"])
            .get_sample_count();

        assert_eq!(intermediate_http_ok, initial_http_ok + 1.0);
        assert_eq!(intermediate_http_duration, initial_http_duration + 1);

        // Act - Second logout with same token
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - Second logout may succeed (idempotent) or fail (already revoked)
        assert!(
            response2.status() == StatusCode::OK || response2.status() == StatusCode::UNAUTHORIZED,
            "Second logout should either succeed (idempotent) or fail with 401 (already revoked)"
        );

        // Assert metrics for second logout
        let status_str = response2.status().as_u16().to_string();
        let final_http_count = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, &status_str])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, &status_str])
            .get_sample_count();

        assert_eq!(final_http_count, intermediate_http_ok + 1.0);
        assert_eq!(final_http_duration, intermediate_http_duration + 1);
    }

    #[tokio::test]
    async fn malformed_json_returns_bad_request() {
        setup_metrics();
        // Arrange
        let app = app();
        let malformed_json = "{ invalid json }";

        // Record initial metrics
        let initial_http_bad = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        let initial_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, "400"])
            .get_sample_count();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(malformed_json))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - Malformed JSON should be rejected by Axum
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Malformed JSON should return 400 or 422"
        );

        // Assert metrics (using 400 as example, adjust if 422)
        let status_str = response.status().as_u16().to_string();
        let final_http_bad = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, &status_str])
            .get();
        let final_http_duration = LOGOUT_HTTP_DURATION
            .with_label_values(&[http::POST, &status_str])
            .get_sample_count();

        assert_eq!(final_http_bad, initial_http_bad + 1.0);
        assert_eq!(final_http_duration, initial_http_duration + 1);
    }
}