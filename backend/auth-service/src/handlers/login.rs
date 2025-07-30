//! User authentication HTTP handler for the BuildHub Auth Service.
//!
//! This module provides the API endpoint for user login, supporting both:
//! - Username-based authentication
//! - Email-based authentication
//!
//! The handler includes comprehensive request tracing, structured logging,
//! and proper error handling to facilitate debugging and security auditing.
//! - Unified error handling with automatic HTTP response conversion

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::instrument;

use crate::{
    app::AppState,
    handlers::login_logic::process_login,
    utils::error_new::AuthServiceError, // ← Add unified error system
    log_info,
    metricss::login_metrics::{
        record_http_request, http::{POST, OK, BAD_REQUEST, INTERNAL_SERVER_ERROR, TOO_MANY_REQUESTS},
    },
};

/// Request payload for user authentication.
///
/// The `login` field accepts either username or email address.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// The user's identifier (username or email)
    pub login: String,
    
    /// The user's password
    pub password: String,
}

/// Handles user login requests.
///
/// # Endpoint: POST /auth/login
///
/// Authenticates a user using either username or email address along with
/// their password. Returns JWT tokens (access and refresh) on successful authentication.
///
/// ## Request Body
/// ```json
/// {
///   "login": "username_or_email",
///   "password": "user_password"
/// }
/// ```
///
/// ## Responses
///
/// * `200 OK` - Authentication successful, returns tokens and user info
/// * `400 Bad Request` - Invalid credentials or validation error
/// * `500 Internal Server Error` - Server-side error
/// * `503 Service Unavailable` - Database unavailable
///
/// ## Example success response
/// ```json
/// {
///   "status": "success",
///   "message": "Authentication successful",
///   "data": {
///     "access_token": "<jwt-access-token>",
///     "refresh_token": "<jwt-refresh-token>",
///     "token_type": "Bearer",
///     "username": "user123",
///     "email": "user@example.com"
///   }
/// }
/// ```
///
/// ## Example error responses
/// ```json
/// {
///   "status": "validation_error",
///   "message": "credentials: Invalid credentials"
/// }
/// ```
/// ```json
/// {
///   "status": "service_unavailable",
///   "message": "Could not get a database connection"
/// }
/// ```
///
/// ## Security Features
///
/// - Constant-time password comparison to prevent timing attacks
/// - Generic error messages that don't reveal user existence
/// - Consistent response timing regardless of error type
/// - Comprehensive logging for security auditing
#[instrument(
    name = "login_user",
    level = "info",
    skip(app_state, login_request),
    fields(
        path = "/auth/login", 
        method = "POST",
        login_type = tracing::field::Empty,
        login_length = tracing::field::Empty
    )
)]
pub async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthServiceError> { // ← Changed return type
    // Determine login type and add useful trace information without exposing credentials
    let login_type = if login_request.login.contains('@') { "email" } else { "username" };
    tracing::Span::current()
        .record("login_type", &tracing::field::display(login_type))
        .record("login_length", &tracing::field::display(login_request.login.len()));

    // Log the login attempt without revealing sensitive information
    log_info!("Auth", &format!("Login attempt via {} (length: {})", login_type, login_request.login.len()), "attempt");

    // Start HTTP duration timer
    let start = std::time::Instant::now();

    // Process the login request
    let result = process_login(&app_state, &login_request).await;

    // Record HTTP metrics
    let duration = start.elapsed().as_secs_f64();
    let status_code = match &result {
        Ok(_) => OK,
        Err(err) => match err {
            AuthServiceError::Validation(_) => BAD_REQUEST,
            AuthServiceError::Database(_) => INTERNAL_SERVER_ERROR,
            AuthServiceError::Jwt(_) => INTERNAL_SERVER_ERROR,
            AuthServiceError::Cache(_) => INTERNAL_SERVER_ERROR,
            AuthServiceError::Configuration(_) => INTERNAL_SERVER_ERROR,
            AuthServiceError::RateLimit(_) => TOO_MANY_REQUESTS, // Add this line
        },
    };

    crate::metricss::login_metrics::LOGIN_HTTP_DURATION
        .with_label_values(&[POST, &status_code.to_string()])
        .observe(duration);
    
    record_http_request(POST, status_code);

    // Return the result, letting ? operator handle error conversion
    result
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

    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};
    use crate::db::users::User;

    /// Creates a test router with the login handler
    fn app() -> Router {
        let state = state_with_redis();
        
        Router::new()
            .route("/auth/login", post(login_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn missing_login_field_returns_bad_request() {
        // Arrange
        let app = app();
        let request_body = json!({
            "password": "some_password" // Missing required "login" field
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - This will be handled by Axum's JSON extractor
        assert!(
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Response status should be 400 Bad Request or 422 Unprocessable Entity"
        );
    }

    #[tokio::test]
    async fn missing_password_field_returns_bad_request() {
        // Arrange
        let app = app();
        let request_body = json!({
            "login": "username" // Missing required "password" field
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - This will be handled by Axum's JSON extractor
        assert!(
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Response status should be 400 Bad Request or 422 Unprocessable Entity"
        );
    }

    #[tokio::test]
    async fn nonexistent_user_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let app = app();
        let request_body = json!({
            "login": "nonexistent_user",
            "password": "any_password"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
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
        
        // With unified error system, invalid credentials should be validation error
        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("credentials"));
    }

    #[tokio::test]
    async fn wrong_password_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let app = app();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("testuser", "test@example.com", "CorrectPass123!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        let request_body = json!({
            "login": "testuser",
            "password": "wrong_password"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
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
        
        // With unified error system, wrong password should be validation error
        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("credentials"));
    }

    #[tokio::test]
    async fn inactive_user_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let app = app();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Create inactive user
        let mut user = User::new("inactive", "inactive@example.com", "ValidPass123!");
        user.is_active = Some(false); // Inactive account
        user.save(&mut conn).unwrap();
        
        let request_body = json!({
            "login": "inactive",
            "password": "ValidPass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
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
        
        // With unified error system, inactive account should be validation error
        assert_eq!(body["status"], "validation_error");
        assert!(body["message"].as_str().unwrap().contains("credentials"));
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET environment variable
    async fn successful_login_returns_tokens() {
        // Arrange
        init_jwt_secret();
        let app = app();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("activeuser", "active@example.com", "ValidPass123!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        let request_body = json!({
            "login": "activeuser",
            "password": "ValidPass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
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
        assert_eq!(body["message"], "Authentication successful");
        assert!(body["data"].is_object());
        assert!(body["data"]["access_token"].is_string());
        assert!(body["data"]["refresh_token"].is_string());
        assert_eq!(body["data"]["token_type"], "Bearer");
        assert_eq!(body["data"]["username"], "activeuser");
        assert_eq!(body["data"]["email"], "active@example.com");
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET environment variable
    async fn email_login_works() {
        // Arrange
        init_jwt_secret();
        let app = app();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("emailuser", "email@example.com", "ValidPass123!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        // Login with email instead of username
        let request_body = json!({
            "login": "email@example.com", // Using email
            "password": "ValidPass123!"
        });

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
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
        
        // Verify success response
        assert_eq!(body["status"], "success");
        assert_eq!(body["data"]["username"], "emailuser");
        assert_eq!(body["data"]["email"], "email@example.com");
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
                    .uri("/auth/login")
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

    #[tokio::test]
    async fn empty_json_returns_bad_request() {
        // Arrange
        let app = app();
        let empty_json = "{}";

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(empty_json))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Assert - Empty JSON missing required fields should be rejected
        assert!(
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Empty JSON should return 400 or 422"
        );
    }
}