//! User login HTTP handler.
//!
//! Provides the REST API interface for user authentication with
//! proper request validation, error handling, and observability.

use axum::{extract::State, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

use crate::{
    app::AppState,
    handlers::login_logic::process_login,
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

/// Login request payload.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(alias = "email", alias = "login", alias = "username")]
    pub email: String,  // Internal field name stays "email"
    pub password: String,
}

/// Handles POST /auth/login requests.
///
/// # Request Format
/// ```json
/// {
///   "email": "user@example.com",
///   "password": "SecurePassword123!"
/// }
/// ```
///
/// # Response Format
/// - 200 OK: Login successful with user data and tokens
/// - 400 Bad Request: Validation errors or inactive account
/// - 429 Too Many Requests: Rate limit exceeded
/// - 500 Internal Server Error: Server issues
pub async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "POST",
        path = "/auth/login",
        email_domain = req.email.split('@').nth(1).unwrap_or("unknown")
    );
    let span_for_instrument = span.clone();
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/login");

    async move {
        info!("Received login request");
        
        // Process login - pass the login field (which contains email OR username)
        let result = process_login(&app_state, &req.email, &req.password).await; // Note: req.email contains the login value due to serde alias

        // Map result to HTTP status code
        let status = match &result {
            Ok(_) => {
                info!("Login successful");
                200
            }
            Err(AuthServiceError::Validation { .. }) => {  // Fixed: use struct pattern
                info!("Login failed - validation error");
                400
            }
            // Fixed: Removed RateLimit variant since it doesn't exist in our simplified error system
            // Rate limiting errors are now handled as validation errors
            Err(e) => {
                error!("Login failed - unexpected error: {}", e);
                500
            }
        };
        
        // Record metrics
        span.record("http.status_code", &status);
        metrics::http::request("/auth/login", "POST", status);
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

    use crate::db::users::User;
    use crate::utils::test_utils::state_with_redis;

    /// Create test app with mocked dependencies
    fn make_app() -> Router {
        metrics::init();
        let state = state_with_redis();
        
        Router::new()
            .route("/auth/login", post(login_handler))
            .with_state(Arc::new(state))
    }

    fn create_test_user(email: &str, password: &str) {
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Generate a unique username for each test
        let username = format!("testuser_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        
        let new_user = User::new_for_insert(&username, email, password);
        let mut user = User::save_new(new_user, &mut conn).unwrap();
        user.is_active = true; // Activate for testing
        user.update(&mut conn).unwrap();
    }

    #[tokio::test]
    async fn test_valid_login_returns_200() {
        let app = make_app();
        let email = format!("valid_{}@example.com", uuid::Uuid::new_v4());
        create_test_user(&email, "ValidPass123!");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": email,
                            "password": "ValidPass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify response structure
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "success");
        assert!(body["data"]["user"]["id"].is_number());
        assert!(body["data"]["tokens"]["access_token"].is_string());
        assert!(body["data"]["tokens"]["refresh_token"].is_string());
    }

    #[tokio::test]
    async fn test_invalid_email_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": "not-an-email",
                            "password": "password"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_empty_password_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": "test@example.com",
                            "password": ""
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_nonexistent_user_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": "nonexistent@example.com",
                            "password": "password"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 400 (validation error) to prevent user enumeration
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_password_returns_400() {
        let app = make_app();
        let email = format!("wrong_pass_{}@example.com", uuid::Uuid::new_v4());
        create_test_user(&email, "CorrectPass123!");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": email,
                            "password": "WrongPass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 400 (validation error) to prevent user enumeration
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_inactive_account_returns_400() {
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        let email = format!("inactive_{}@example.com", uuid::Uuid::new_v4());
        let new_user = User::new_for_insert("inactive", &email, "TestPass123!");
        User::save_new(new_user, &mut conn).unwrap();
        // Don't activate the user

        let app = make_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": email,
                            "password": "TestPass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        // The login system uses a generic error message for security reasons
        // to prevent user enumeration attacks
        let message = body["message"].as_str().unwrap();
        assert!(
            message.contains("Invalid email or password") || 
            message.contains("credentials"),
            "Unexpected error message: '{}'", 
            message
        );
    }

    #[tokio::test]
    async fn test_missing_fields_returns_422() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"email": "test@example.com"}).to_string()))
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
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{invalid-json}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Fix: Axum is returning 400 Bad Request for malformed JSON, not 422 Unprocessable Entity
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_multiple_logins_succeed() {
        let app = make_app();
        
        // Test that multiple users can login
        for i in 0..3 {
            let email = format!("user_{}@example.com", i);
            create_test_user(&email, "Password123!");
            
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/login")
                        .header("Content-Type", "application/json")
                        .body(Body::from(
                            json!({
                                "email": email,
                                "password": "Password123!"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
        }
    }
}