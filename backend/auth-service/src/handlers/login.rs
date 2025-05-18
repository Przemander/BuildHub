//! User authentication HTTP handler for the BuildHub Auth Service.
//!
//! This module provides the API endpoint for user login, supporting both:
//! - Username-based authentication
//! - Email-based authentication
//!
//! The handler includes comprehensive request tracing, structured logging,
//! and proper error handling to facilitate debugging and security auditing.

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    app::AppState,
    handlers::login_logic::process_login,
    log_info, log_error,
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

/// Response structure for successful authentication.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Operation status ("success")
    pub status: String,
    
    /// Success message
    pub message: String,
    
    /// Authentication data including tokens
    pub data: AuthData,
}

/// Authentication tokens and user information.
#[derive(Debug, Serialize)]
pub struct AuthData {
    /// JWT access token for API authorization
    pub access_token: String,
    
    /// JWT refresh token for obtaining new access tokens
    pub refresh_token: String,
    
    /// Token type (always "Bearer" for JWT)
    pub token_type: String,
    
    /// The authenticated user's username
    pub username: String,
    
    /// The authenticated user's email address
    pub email: String,
}

/// Handles user authentication requests.
///
/// # Endpoint: POST /auth/login
///
/// Authenticates a user with username/email and password,
/// returning JWT tokens on success.
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
/// * `200 OK` - Authentication successful, returns tokens
/// * `401 Unauthorized` - Invalid credentials
/// * `500 Internal Server Error` - Server-side error
///
/// ## Security Features
///
/// - Consistent response timing to mitigate timing attacks
/// - Password verification using secure comparison
/// - Comprehensive audit logging
/// - Rate limiting protection (applied at middleware level)
#[instrument(
    name = "user_login",
    level = "info",
    skip(app_state, login_request),
    fields(
        path = "/auth/login", 
        method = "POST",
        username_or_email = tracing::field::Empty,
        login_type = tracing::field::Empty
    )
)]
pub async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(login_request): Json<LoginRequest>,
) -> impl IntoResponse {
    // Determine login type (email vs username) for better tracing
    let login_type = if login_request.login.contains('@') { "email" } else { "username" };
    
    // Add structured information to the current span
    tracing::Span::current()
        .record("username_or_email", &tracing::field::display(&login_request.login))
        .record("login_type", &tracing::field::display(login_type));
    
    // Log authentication attempt
    log_info!(
        "Auth", 
        &format!("Login attempt with {}: {}", login_type, login_request.login), 
        "attempt"
    );

    // Process login request through business logic layer
    match process_login(&app_state.pool, &login_request).await {
        Ok((status, body)) => {
            // Log successful authentication
            log_info!(
                "Auth", 
                &format!("Login successful for {}", login_request.login), 
                "success"
            );
            
            // Return success response
            (status, AxumJson(body)).into_response()
        }
        Err(err) => {
            // Log failed authentication attempt with error reason
            log_error!(
                "Auth", 
                &format!("Login failed for {}: {}", login_request.login, err), 
                "failure"
            );
            
            // Return error response
            err.into_response()
        }
    }
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

    /// Creates a test router with the login handler
    fn app() -> (Router, Arc<AppState>) {
        let state = Arc::new(state_with_redis());
        
        let app = Router::new()
            .route("/auth/login", post(login_handler))
            .with_state(state.clone());
            
        (app, state)
    }

    #[tokio::test]
    async fn invalid_credentials_return_401() {
        // Arrange
        let (app, _) = app();
        let request_body = json!({
            "login": "nonexistent",
            "password": "wrong"
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
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "unauthorized");
        assert!(body["message"].as_str().unwrap().contains("Invalid"));
    }

    #[tokio::test]
    async fn missing_fields_return_400() {
        // Arrange
        let (app, _) = app();
        let request_body = json!({
            // Missing required fields
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

        // Assert - accept either 400 or 422 as both are used for validation errors
        assert!(
            response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Response status should be 400 Bad Request or 422 Unprocessable Entity"
        );
    }

    #[tokio::test]
    #[ignore] // requires DB setup with test user
    async fn valid_credentials_return_200_with_tokens() {
        // Arrange
        let (app, state) = app();
        
        // Set up test user
        let mut conn = state.pool.get().unwrap();
        let test_user = "test_login_user";
        let test_password = "TestPass123!";
        let test_email = "test_login@example.com";
        
        let mut user = User::new(test_user, test_email, test_password);
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        let request_body = json!({
            "login": test_user,
            "password": test_password
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
        
        assert_eq!(body["status"], "success");
        assert!(body["data"]["access_token"].is_string());
        assert!(body["data"]["refresh_token"].is_string());
        assert_eq!(body["data"]["token_type"], "Bearer");
        assert_eq!(body["data"]["username"], test_user);
        assert_eq!(body["data"]["email"], test_email);
    }
    
    #[tokio::test]
    #[ignore] // requires DB setup with test user
    async fn login_with_email_returns_200_with_tokens() {
        // Arrange
        let (app, state) = app();
        
        // Set up test user
        let mut conn = state.pool.get().unwrap();
        let test_user = "test_email_login";
        let test_password = "TestPass123!";
        let test_email = "test_email_login@example.com";
        
        let mut user = User::new(test_user, test_email, test_password);
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        let request_body = json!({
            "login": test_email,  // Login with email instead of username
            "password": test_password
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
        
        assert_eq!(body["status"], "success");
        assert_eq!(body["data"]["username"], test_user);
    }
}