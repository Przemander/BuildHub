//! User logout HTTP handler.
//!
//! This module provides the HTTP endpoint for user logout functionality:
//! - POST /auth/logout: Revokes JWT tokens by adding them to Redis blocklist
//!
//! Security features include:
//! - Token validation and revocation
//! - Comprehensive logging and metrics
//! - Graceful handling of invalid or expired tokens
//! - Unified error handling with automatic HTTP response conversion

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::logout_logic::process_logout;
use crate::utils::error_new::AuthServiceError; // ← Add unified error system

/// Request payload for logout operations.
///
/// Contains the JWT token that should be revoked and added to the blocklist.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// The JWT token to be revoked
    pub token: String,
}

/// Handles user logout requests.
///
/// # Endpoint: POST /auth/logout
///
/// Takes a JWT token and revokes it by adding to the Redis blocklist,
/// preventing future use of the token for authentication.
///
/// ## Request Body
/// ```json
/// {
///   "token": "<jwt-token-to-revoke>"
/// }
/// ```
///
/// ## Responses
///
/// * `200 OK` - Token successfully revoked
/// * `401 Unauthorized` - Invalid or malformed token
/// * `500 Internal Server Error` - Server-side error
/// * `503 Service Unavailable` - Redis unavailable
///
/// ## Example success response
/// ```json
/// {
///   "status": "success",
///   "message": "Logged out successfully"
/// }
/// ```
///
/// ## Example error responses
/// ```json
/// {
///   "status": "configuration_error",
///   "message": "Redis client not available for logout operation"
/// }
/// ```
/// ```json
/// {
///   "status": "unauthorized",
///   "message": "Invalid token"
/// }
/// ```
#[instrument(
    name = "logout_user",
    level = "info",
    skip(app_state, logout_request),
    fields(
        path = "/auth/logout", 
        method = "POST",
        token_length = tracing::field::Empty
    )
)]
pub async fn logout_handler(
    State(app_state): State<Arc<AppState>>,
    Json(logout_request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> { // ← Changed return type
    // Add useful trace information without exposing the token
    tracing::Span::current().record(
        "token_length",
        &tracing::field::display(logout_request.token.len()),
    );

    // Process the logout request using unified error system
    // The ? operator will automatically convert AuthServiceError to HTTP response
    process_logout(&app_state, &logout_request.token).await
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

    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};

    /// Creates a test router with the logout handler
    fn app() -> Router {
        let state = state_with_redis();
        
        Router::new()
            .route("/auth/logout", post(logout_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn empty_token_returns_unauthorized() {
        // Arrange
        let app = app();
        let request_body = json!({
            "token": ""
        });

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
        
        // With unified error system, empty token should be unauthorized
        assert_eq!(body["status"], "unauthorized");
    }

    #[tokio::test]
    async fn invalid_token_format_returns_unauthorized() {
        // Arrange
        let app = app();
        let request_body = json!({
            "token": "not-a-valid-jwt-token"
        });

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
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET to be set
    async fn valid_token_logout_returns_success() {
        // Arrange
        init_jwt_secret();
        let app = app();
        
        // Generate a valid token
        let token = generate_token("test_user", TOKEN_TYPE_ACCESS, None).unwrap();
        
        let request_body = json!({
            "token": token
        });

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
    }

    #[tokio::test]
    async fn missing_token_field_returns_bad_request() {
        // Arrange
        let app = app();
        let request_body = json!({
            "wrong_field": "some_value" // Missing required "token" field
        });

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
        
        let app = Router::new()
            .route("/auth/logout", post(logout_handler))
            .with_state(Arc::new(state));

        let request_body = json!({
            "token": "any-token"
        });

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
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET + Redis
    async fn double_logout_handles_gracefully() {
        // Arrange
        init_jwt_secret();
        let app = app();
        
        // Generate a valid token
        let token = generate_token("test_user", TOKEN_TYPE_ACCESS, None).unwrap();
        let request_body = json!({
            "token": token
        });

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
        // Both behaviors are acceptable depending on implementation
        assert!(
            response2.status() == StatusCode::OK || 
            response2.status() == StatusCode::UNAUTHORIZED,
            "Second logout should either succeed (idempotent) or fail with 401 (already revoked)"
        );
    }

    #[tokio::test]
    async fn malformed_json_returns_bad_request() {
        // Arrange
        let app = app();
        let malformed_json = "{ invalid json }";

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
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Malformed JSON should return 400 or 422"
        );
    }
}