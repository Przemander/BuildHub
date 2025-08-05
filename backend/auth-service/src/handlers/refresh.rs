//! Token refresh HTTP handler with OpenTelemetry integration.
//!
//! This module implements the OAuth2-compatible token refresh endpoint that:
//! - Validates refresh tokens
//! - Implements token rotation security pattern
//! - Returns new access and refresh token pairs
//! - Provides detailed error responses for client debugging
//! - Full OpenTelemetry observability with hierarchical spans
//!
//! # API Endpoint
//! `POST /auth/refresh`

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::Instrument;

use crate::{
    app::AppState,
    handlers::refresh_logic::process_token_refresh,
    utils::{
        error_new::AuthServiceError,
        telemetry::{http_request_span, business_operation_span, SpanExt},
        log_new::Log,
    },
    // Fix: Corrected imports by using what's available in the refresh_metrics module
    metricss::refresh_metrics::{
        record_refresh_operation, time_refresh_operation, steps
    },
};

/// Request payload for token refresh.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handles token refresh requests.
///
/// # Endpoint: POST /auth/refresh
///
/// Takes a refresh token and returns a new pair of access and refresh tokens.
/// Implements token rotation for enhanced security.
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(refresh_request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/refresh");
    
    // Add business context to the span without exposing the token itself
    http_span.record("token_length", &refresh_request.token.len());
    
    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();
    
    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the token refresh attempt using structured logging
        Log::event(
            "INFO",
            "Token Refresh",
            &format!("Token refresh attempt (token length: {})", refresh_request.token.len()),
            "attempt",
            "refresh_token_handler"
        );

        // Start HTTP duration timer
        let _timer = time_refresh_operation(steps::HTTP_REQUEST);

        // Create child business operation span for the actual token refresh operation
        let business_span = business_operation_span("token_refresh");
        
        // Process the token refresh within the business span
        let result = process_token_refresh(&app_state, &refresh_request.token)
            .instrument(business_span)
            .await;
        
        // Map result to HTTP status for metrics and span context
        match &result {
            Ok(_) => {
                http_span.record("http.status_code", &StatusCode::OK.as_u16().to_string());
                record_refresh_operation(steps::HTTP_REQUEST, "success");
            }
            Err(err) => {
                let status_code = match err {
                    AuthServiceError::Validation(_) => StatusCode::BAD_REQUEST,
                    AuthServiceError::Jwt(_) => StatusCode::UNAUTHORIZED,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                
                http_span.record("http.status_code", &status_code.as_u16().to_string());
                http_span.record_error(err);
                record_refresh_operation(steps::HTTP_REQUEST, "failure");
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

    use crate::utils::jwt::{generate_token, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::state_with_redis;
    use crate::metricss::refresh_metrics::{
        init_refresh_metrics, REFRESH_OPERATIONS,
        steps, results
    };

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
        
        assert_eq!(body["status"], "unauthorized");
        assert!(body["message"].as_str().unwrap().contains("Invalid") || 
                body["message"].as_str().unwrap().contains("token"));
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
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY
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
}