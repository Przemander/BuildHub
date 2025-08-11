//! User registration HTTP handler with email activation.
//!
//! This module provides the API endpoint for user registration with:
//! - Input validation
//! - User creation in the database
//! - Account activation flow via email
//! - Unified error handling with automatic HTTP response conversion
//! - Complete HTTP-level metrics integration
//! - Comprehensive request tracing with OpenTelemetry

use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::Instrument;

use crate::{
    app::AppState,
    db::users::RegisterData,
    handlers::register_logic::process_registration,
    metricss::register_metrics::{http, record_http_request},
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, http_request_span, SpanExt},
    },
};

/// Handles user registration requests with complete HTTP metrics tracking.
///
/// # Endpoint: POST /auth/register
///
/// Takes JSON user data, validates it, creates an inactive account,
/// and initiates the email verification flow.
pub async fn register_handler(
    State(app_state): State<Arc<AppState>>,
    Json(register_data): Json<RegisterData>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with method and path
    let http_span = http_request_span("POST", "/auth/register");

    // Add business context to the span without exposing full PII
    http_span.record("username", &register_data.username);
    http_span.record(
        "email_domain",
        &register_data.email.split('@').nth(1).unwrap_or("invalid"),
    );

    // Clone span before moving it into the async block
    let http_span_clone = http_span.clone();

    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log the registration attempt using structured logging
        Log::event(
            "INFO",
            "Registration",
            &format!(
                "Registration attempt for username: {}, email domain: {}",
                register_data.username,
                register_data.email.split('@').nth(1).unwrap_or("invalid")
            ),
            "attempt",
            "register_handler",
        );

        // Create child business operation span for the actual registration operation
        let business_span = business_operation_span("user_registration");

        // Process the registration within the business span
        let result = process_registration(&app_state, register_data)
            .instrument(business_span)
            .await;

        // Map result to HTTP status for metrics and span context
        let status_code = match &result {
            Ok(_) => {
                http_span.record("http.status_code", &http::CREATED.to_string());
                http::CREATED
            }
            Err(AuthServiceError::Validation(_)) => {
                http_span.record("http.status_code", &http::BAD_REQUEST.to_string());
                http::BAD_REQUEST
            }
            Err(_) => {
                http_span.record("http.status_code", &http::INTERNAL_SERVER_ERROR.to_string());
                http::INTERNAL_SERVER_ERROR
            }
        };

        // If there was an error, record it in the span
        if let Err(ref e) = result {
            http_span.record_error(e);
        }

        // Record HTTP metrics
        record_http_request(http::POST, status_code);

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
    // ✅ Import metrics for testing HTTP tracking
    use crate::metricss::register_metrics::{
        http, init_registration_metrics, REGISTRATION_HTTP_REQUESTS,
    };

    /// Creates a test router with the register handler and initialized metrics
    fn app() -> Router {
        // ✅ Initialize metrics for testing
        init_registration_metrics();

        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());

        Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn valid_registration_returns_201_created_with_http_metrics() {
        // Arrange
        let app = app();

        // Record initial HTTP metrics state
        let initial_created = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "201"])
            .get();

        let request_body = json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert HTTP response
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "success");
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("check your email"));

        // ✅ Assert HTTP metrics were recorded
        let final_created = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "201"])
            .get();
        assert_eq!(final_created, initial_created + 1.0);
    }

    #[tokio::test]
    async fn invalid_data_returns_400_bad_request_with_http_metrics() {
        // Arrange
        let app = app();

        // Record initial HTTP metrics state
        let initial_bad_request = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();

        let request_body = json!({
            "username": "",  // Empty username is invalid
            "email": "test@example.com",
            "password": "SecurePass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert HTTP response
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "validation_error");

        // ✅ Assert HTTP metrics were recorded
        let final_bad_request = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        assert_eq!(final_bad_request, initial_bad_request + 1.0);
    }

    #[tokio::test]
    async fn duplicate_registration_returns_400_with_http_metrics() {
        // Arrange
        let app = app();

        let request_body = json!({
            "username": "duplicate",
            "email": "duplicate@example.com",
            "password": "SecurePass123!"
        });

        // First registration - should succeed
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Record initial HTTP metrics state for second attempt
        let initial_bad_request = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();

        // Act - Second registration with same data
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - Should return BAD_REQUEST for duplicate data (validation error)
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("already"));

        // ✅ Assert HTTP metrics were recorded
        let final_bad_request = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        assert_eq!(final_bad_request, initial_bad_request + 1.0);
    }

    #[tokio::test]
    async fn missing_email_config_returns_500_with_http_metrics() {
        // ✅ Initialize metrics
        init_registration_metrics();

        // Arrange - Create state without email config
        let mut state = state_with_redis();
        state.email_config = None; // No email config

        let app = Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state));

        // Record initial HTTP metrics state
        let initial_server_error = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();

        let request_body = json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
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
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("Email configuration"));

        // ✅ Assert HTTP metrics were recorded
        let final_server_error = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();
        assert_eq!(final_server_error, initial_server_error + 1.0);
    }

    #[tokio::test]
    async fn missing_redis_returns_500_with_http_metrics() {
        // ✅ Initialize metrics
        init_registration_metrics();

        // Arrange - Create state without Redis
        let mut state = state_with_redis();
        state.redis_client = None; // No Redis client
        state.email_config = Some(EmailConfig::dummy());

        let app = Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state));

        // Record initial HTTP metrics state
        let initial_server_error = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();

        let request_body = json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
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
        assert!(body["message"].as_str().unwrap().contains("Redis client"));

        // ✅ Assert HTTP metrics were recorded
        let final_server_error = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();
        assert_eq!(final_server_error, initial_server_error + 1.0);
    }

    #[tokio::test]
    async fn test_http_metrics_comprehensive_coverage() {
        // Test that we can track all possible HTTP status codes
        init_registration_metrics();

        // Record baseline
        let initial_201 = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "201"])
            .get();
        let initial_400 = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        let initial_500 = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();

        // Test successful registration
        let app_success = app();
        let _ = app_success
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "success_user",
                            "email": "success@test.com",
                            "password": "SecurePass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Test validation error
        let app_validation = app();
        let _ = app_validation
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "",  // Invalid
                            "email": "invalid@test.com",
                            "password": "SecurePass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Test configuration error
        let mut state_no_email = state_with_redis();
        state_no_email.email_config = None;
        let app_config_error = Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state_no_email));

        let _ = app_config_error
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "config_user",
                            "email": "config@test.com",
                            "password": "SecurePass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // ✅ Assert all HTTP status codes were tracked
        let final_201 = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "201"])
            .get();
        let final_400 = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        let final_500 = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "500"])
            .get();

        assert_eq!(final_201, initial_201 + 1.0, "Should track 201 Created");
        assert_eq!(final_400, initial_400 + 1.0, "Should track 400 Bad Request");
        assert_eq!(
            final_500,
            initial_500 + 1.0,
            "Should track 500 Internal Server Error"
        );
    }
}
