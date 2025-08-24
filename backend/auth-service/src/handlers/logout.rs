//! HTTP handler for user logout endpoint.
//!
//! Provides the REST API interface for token-based logout with
//! proper request validation, error handling, and observability.

use axum::{extract::State, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, span, error, Instrument, Level};

use crate::{
    app::AppState,
    handlers::logout_logic::process_logout,
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

/// Request payload for logout operations.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handles POST /auth/logout requests.
///
/// # Request Format
/// ```json
/// {
///   "token": "eyJhbGciOiJIUzI1NiIs..."
/// }
/// ```
///
/// # Response Format
/// - 200 OK: Logout successful (even for invalid tokens)
/// - 400 Bad Request: Empty token provided
/// - 500 Internal Server Error: Server configuration issues
///
/// # Security
/// - Idempotent operation (safe to call multiple times)
/// - Revokes even invalid tokens (defense in depth)
pub async fn logout_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "POST",
        path = "/auth/logout",
        token_length = req.token.len(),
        has_jwt_format = req.token.matches('.').count() == 2
    );
    let span_for_instrument = span.clone();
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/logout");

    async move {
        info!("Received logout request");
        
        // Early validation
        if req.token.is_empty() {
            info!("Logout failed - empty token");
            metrics::http::request("/auth/logout", "POST", 400);
            return Err(AuthServiceError::validation("token", "Token is required"));
        }

        // Process logout
        let result = process_logout(&app_state, &req.token).await;

        // Map result to HTTP status code
        let status = match &result {
            Ok(_) => {
                info!("Logout successful");
                200
            }
            Err(AuthServiceError::Configuration(_)) => {
                error!("Logout failed - configuration error");
                500
            }
            // Fixed: Removed Jwt variant - we don't have this in our simplified error system
            // JWT errors are now handled as Authentication or External errors
            Err(AuthServiceError::Authentication(_)) => {
                // Still return 200 for invalid tokens (they get revoked anyway)
                info!("Logout successful (invalid token revoked)");
                200
            }
            Err(AuthServiceError::Cache(_)) => {
                error!("Logout failed - cache error");
                500
            }
            Err(AuthServiceError::Validation { .. }) => {  // Fixed: use struct pattern
                info!("Logout failed - validation error");
                400
            }
            Err(e) => {
                error!("Logout failed - unexpected error: {}", e);
                500
            }
        };
        
        // Record metrics
        span.record("http.status_code", &status);
        metrics::http::request("/auth/logout", "POST", status);
        drop(timer); // Timer records duration when dropped
        
        // For authentication errors (invalid tokens), still return success (token was revoked)
        match result {
            Err(AuthServiceError::Authentication(_)) => Ok((
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "status": "success",
                    "message": "Logged out successfully"
                })),
            ).into_response()),
            other => other.map(|r| r.into_response()),
        }
    }
    .instrument(span_for_instrument)
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

    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::{init_test_env, state_with_redis};  // Fixed: correct function name

    /// Create test app with mocked dependencies
    fn make_app() -> Router {
        metrics::init();
        let state = state_with_redis();
        
        Router::new()
            .route("/auth/logout", post(logout_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn test_empty_token_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": ""}).to_string()))
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
    async fn test_invalid_token_returns_200() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": "invalid.jwt.token"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Invalid tokens still get "revoked" (added to blocklist)
        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify success message
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "success");
    }

    #[tokio::test]
    async fn test_valid_token_returns_200() {
        init_test_env();  // Fixed: correct function name
        let app = make_app();
        let token = generate_token("testuser", TOKEN_TYPE_ACCESS, None).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify response
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "success");
        assert_eq!(body["message"], "Logged out successfully");
    }

    #[tokio::test]
    async fn test_missing_token_field_returns_422() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"wrong": "field"}).to_string()))
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
                    .uri("/auth/logout")
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
    async fn test_missing_redis_returns_500() {
        metrics::init();
        let mut state = state_with_redis();
        state.redis_client = None; // Remove Redis

        let app = Router::new()
            .route("/auth/logout", post(logout_handler))
            .with_state(Arc::new(state));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": "any-token"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_double_logout_is_idempotent() {
        init_test_env();  // Fixed: correct function name
        let app = make_app();
        let token = generate_token("testuser", TOKEN_TYPE_ACCESS, None).unwrap();

        // First logout
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": &token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response1.status(), StatusCode::OK);

        // Second logout should also succeed (idempotent)
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": &token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_with_wrong_format_returns_200() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": "not.jwt.format.at.all.extra"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should still "revoke" the malformed token
        assert_eq!(response.status(), StatusCode::OK);
    }
}