//! Token refresh HTTP handler.
//!
//! This module implements the OAuth2-compatible token refresh endpoint that:
//! - Validates refresh tokens
//! - Implements token rotation security pattern
//! - Returns new access and refresh token pairs
//! - Provides detailed error responses for client debugging
//!
//! # API Endpoint
//! `POST /auth/refresh`

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::refresh_logic::process_token_refresh;

/// Request payload for token refresh operations.
///
/// Accepts a refresh token and validates it according to OAuth2 spec.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// The refresh token to validate and exchange for new tokens.
    pub token: String,
}

/// Response structure for token refresh operations.
///
/// Provides a consistent response format for both success and error cases.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Operation status ("success" or "error").
    pub status: String,
    
    /// Human-readable message about the operation result.
    pub message: String,
    
    /// Optional data field containing new tokens (present only on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<TokenData>,
}

/// Data structure for successful token refresh operations.
#[derive(Debug, Serialize)]
pub struct TokenData {
    /// The new JWT access token.
    pub access_token: String,
    
    /// The new JWT refresh token.
    pub refresh_token: String,
    
    /// Token type (always "Bearer" for JWT).
    pub token_type: String,
}

/// Handles token refresh requests.
///
/// # Endpoint: POST /auth/refresh
///
/// Takes a refresh token, validates it, revokes it (for security),
/// and returns a new token pair (access + refresh) if successful.
///
/// ## Request Body
/// ```json
/// {
///   "token": "<refresh-token-string>"
/// }
/// ```
///
/// ## Responses
///
/// * `200 OK` - Token refresh successful
/// * `400 Bad Request` - Wrong token type
/// * `401 Unauthorized` - Invalid, expired, or revoked token
/// * `500 Internal Server Error` - Server-side error
///
/// ## Example success response
/// ```json
/// {
///   "status": "success",
///   "message": "Tokens refreshed successfully",
///   "data": {
///     "access_token": "<new-access-token>",
///     "refresh_token": "<new-refresh-token>",
///     "token_type": "Bearer"
///   }
/// }
/// ```
#[instrument(
    name = "refresh_token",
    level = "info",
    skip(app_state, refresh_request),
    fields(
        path = "/auth/refresh", 
        method = "POST",
        token_length = tracing::field::Empty
    )
)]
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(refresh_request): Json<TokenRequest>,
) -> impl IntoResponse {
    // Add useful trace information without revealing the token
    tracing::Span::current().record(
        "token_length",
        &tracing::field::display(refresh_request.token.len()),
    );

    // Process the token refresh request
    let (status, body) = process_token_refresh(&app_state, &refresh_request.token).await;
    
    // Return the response with appropriate status code
    (status, AxumJson(body))
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

    use crate::utils::jwt::{generate_token, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::state_with_redis;

    /// Creates a test router with the refresh handler
    fn app() -> Router {
        let state = state_with_redis();
        
        Router::new()
            .route("/auth/refresh", post(refresh_token_handler))
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
                    .uri("/auth/refresh")
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
        
        assert_eq!(body["status"], "error");
        assert!(body.get("data").is_none(), "Error response should not contain data field");
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
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET to be set
    async fn proper_refresh_token_returns_new_tokens() {
        // Arrange - Set JWT secret and generate valid refresh token
        std::env::set_var("JWT_SECRET", "test-secret-for-refresh-token-handler");
        let app = app();
        
        // Generate a valid refresh token
        let refresh_token = generate_token("test_user", TOKEN_TYPE_REFRESH, None).unwrap();
        
        let request_body = json!({
            "token": refresh_token
        });

        // Act
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

        // Assert
        assert_eq!(response.status(), StatusCode::OK);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        // Verify success response structure
        assert_eq!(body["status"], "success");
        assert!(body["data"].is_object(), "Success response should contain data object");
        assert!(body["data"]["access_token"].is_string(), "Response should contain access_token string");
        assert!(body["data"]["refresh_token"].is_string(), "Response should contain refresh_token string");
        assert_eq!(body["data"]["token_type"], "Bearer");
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
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - accept either 400 or 422 as both are used for validation errors
        assert!(
            response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Response status should be 400 Bad Request or 422 Unprocessable Entity"
        );
    }
}