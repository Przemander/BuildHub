//! HTTP handler for JWT token refresh endpoint.
//!
//! Provides the REST API interface for token refresh with
//! proper request validation, error handling, and observability.

use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

use crate::{
    app::AppState,
    handlers::refresh_logic::process_token_refresh,
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

/// Request payload for token refresh.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Response data for successful refresh.
#[derive(Debug, Serialize)]
pub struct TokenResponseData {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
}

/// Handles POST /auth/refresh requests.
///
/// # Request Format
/// ```json
/// {
///   "token": "eyJhbGciOiJIUzI1NiIs..."
/// }
/// ```
///
/// # Response Format
/// - 200 OK: New token pair returned
/// - 400 Bad Request: Invalid token type or validation error
/// - 401 Unauthorized: Token expired, invalid signature, or revoked
/// - 500 Internal Server Error: Server configuration issues
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "POST",
        path = "/auth/refresh",
        token_length = req.token.len()
    );
    let span_for_instrument = span.clone();
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/refresh");

    async move {
        info!("Received token refresh request");
        
        // Early validation
        if req.token.is_empty() {
            info!("Token refresh failed - empty token");
            metrics::http::request("/auth/refresh", "POST", 400);
            return Err(AuthServiceError::validation("token", "Token is required"));
        }

        // Process token refresh
        let result = process_token_refresh(&app_state, &req.token).await;

        // Map result to HTTP status code
        let status = match &result {
            Ok(_) => {
                info!("Token refresh successful");
                200
            }
            Err(AuthServiceError::Validation { .. }) => {  // Fixed: use struct pattern
                info!("Token refresh failed - validation error");
                400
            }
            // Fixed: Removed Jwt and RateLimit variants since they don't exist in our simplified error system
            // JWT errors are now handled as Authentication errors
            Err(AuthServiceError::Authentication(_)) => {
                info!("Token refresh failed - authentication error");
                401
            }
            Err(AuthServiceError::Configuration(_)) => {
                error!("Token refresh failed - configuration error");
                500
            }
            Err(e) => {
                error!("Token refresh failed - unexpected error: {}", e);
                500
            }
        };
        
        // Record metrics
        span.record("http.status_code", &status);
        metrics::http::request("/auth/refresh", "POST", status);
        drop(timer); // Timer records duration when dropped
        
        result
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

    use crate::utils::jwt::{generate_token, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::{init_test_env, state_with_redis};  // Fixed: correct function name

    /// Create test app with mocked dependencies
    fn make_app() -> Router {
        metrics::init();
        init_test_env();  // Fixed: correct function name
        let state = state_with_redis();
        
        Router::new()
            .route("/auth/refresh", post(refresh_token_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn test_empty_token_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
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
    async fn test_invalid_token_returns_401() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": "invalid.jwt.token"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_valid_refresh_token_returns_200() {
        let app = make_app();
        let token = generate_token("testuser", TOKEN_TYPE_REFRESH, None).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify response structure
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "success");
        assert!(body["data"]["access_token"].is_string());
        assert!(body["data"]["refresh_token"].is_string());
        assert_eq!(body["data"]["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn test_access_token_returns_400() {
        let app = make_app();
        let access_token = generate_token("testuser", "access", None).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": access_token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        // Verify error mentions refresh token
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["message"].as_str().unwrap().contains("refresh"));
    }

    #[tokio::test]
    async fn test_missing_token_field_returns_422() {
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
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
                    .uri("/auth/refresh")
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
        init_test_env();  // Fixed: correct function name
        let mut state = state_with_redis();
        state.redis_client = None; // Remove Redis

        let app = Router::new()
            .route("/auth/refresh", post(refresh_token_handler))
            .with_state(Arc::new(state));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": "any-token"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_expired_token_returns_401() {
        let app = make_app();
        let expired_token = generate_token(
            "testuser",
            TOKEN_TYPE_REFRESH,
            Some(chrono::Duration::seconds(-1))
        ).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"token": expired_token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
