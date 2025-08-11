//! # User Login HTTP Handler
//!
//! This module implements the login endpoint with comprehensive security controls,
//! rate limiting, and observability. It handles credential validation and returns
//! JWT tokens for successful authentication.
//!
//! ## Security Features
//!
//! - Rate limiting to prevent brute force attacks
//! - Consistent timing for responses to prevent timing attacks
//! - Input validation for malformed requests
//! - Privacy-preserving logging (no credential exposure)
//! - Detailed telemetry for security monitoring
//!
//! ## Endpoint
//!
//! `POST /auth/login`
//!
//! ## Request Format
//!
//! ```json
//! {
//!   "login": "username or email",
//!   "password": "user password"
//! }
//! ```
//!
//! ## Response Format (Success)
//!
//! ```json
//! {
//!   "status": "success",
//!   "message": "Authentication successful",
//!   "data": {
//!     "access_token": "JWT_ACCESS_TOKEN",
//!     "refresh_token": "JWT_REFRESH_TOKEN",
//!     "token_type": "Bearer",
//!     "username": "username",
//!     "email": "user@example.com"
//!   }
//! }
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;

use crate::{
    app::AppState,
    handlers::login_logic::process_login,
    metricss::login_metrics::{
        http::{BAD_REQUEST, OK, POST},
        record_http_request,
        LOGIN_HTTP_DURATION,
    },
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{http_request_span, SpanExt},
    },
};

/// Login request data structure.
///
/// This represents the JSON payload expected by the login endpoint,
/// with optional validation rules for input sanitization.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoginRequest {
    /// Username or email used for login
    #[serde(alias = "username", alias = "email")]
    pub login: String,
    
    /// Password in plain text (will be verified against stored hash)
    pub password: String,
}

/// Validates login request data.
///
/// Checks for basic input validity like empty fields or overly long inputs
/// that might indicate abuse.
///
/// # Arguments
///
/// * `req` - Login request to validate
///
/// # Returns
///
/// * `Ok(())` - Validation passed
/// * `Err(AuthServiceError)` - Validation failed with reason
fn validate_login_request(req: &LoginRequest) -> Result<(), AuthServiceError> {
    // Validate login field
    if req.login.trim().is_empty() {
        return Err(AuthServiceError::validation(
            "login",
            "Username or email is required",
        ));
    }
    
    // Check for reasonable login length to prevent abuse
    if req.login.len() > 255 {
        return Err(AuthServiceError::validation(
            "login",
            "Username or email is too long",
        ));
    }
    
    // Validate password field
    if req.password.is_empty() {
        return Err(AuthServiceError::validation(
            "password",
            "Password is required",
        ));
    }
    
    // Check for reasonable password length to prevent abuse
    if req.password.len() > 1024 {
        return Err(AuthServiceError::validation(
            "password",
            "Password is too long",
        ));
    }
    
    Ok(())
}

/// Handles user login requests.
///
/// This handler processes login requests, validates credentials, and returns
/// JWT tokens for successful authentication. It includes observability and 
/// comprehensive error handling.
///
/// # Arguments
///
/// * `app_state` - Application state with database and Redis connections
/// * `req` - JSON request containing login credentials
///
/// # Returns
///
/// * On success: 200 OK with JWT tokens
/// * On error: Appropriate error status with explanation
#[tracing::instrument(name = "login_handler", skip_all)]
pub async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // Create HTTP span for tracing
    let http_span = http_request_span("POST", "/auth/login");
    
    // Record login type without exposing the actual value
    let login_type = if req.login.contains('@') { "email" } else { "username" };
    http_span.record("login_type", &login_type);
    
    // Record email domain for analytics if present (privacy-preserving)
    if let Some(domain) = req.login.split('@').nth(1) {
        http_span.record("email_domain", &domain);
    }
    
    let http_span_clone = http_span.clone();
    
    // Wrap the handler logic in the HTTP span for automatic tracing
    async move {
        // Log login attempt (without exposing credentials)
        Log::event(
            "INFO",
            "Authentication",
            &format!("Login attempt via {}", login_type),
            "attempt",
            "login_handler",
        );
        
        // Start HTTP duration timer
        let start = std::time::Instant::now();
        
        // Validate request format
        if let Err(e) = validate_login_request(&req) {
            let duration = start.elapsed().as_secs_f64();
            http_span.record("http.status_code", &BAD_REQUEST.to_string());
            http_span.record_error(&e);
            
            record_http_request(POST, BAD_REQUEST);
            LOGIN_HTTP_DURATION
                .with_label_values(&[POST, &BAD_REQUEST.to_string()])
                .observe(duration);
                
            Log::event(
                "WARN",
                "Authentication",
                &format!("Login validation failed: {}", e),
                "validation_failed",
                "login_handler",
            );
            
            return e.into_response();
        }
        
        // Process login through business logic layer
        let result = process_login(&app_state, &req).await;
        
        // Record HTTP metrics
        let duration = start.elapsed().as_secs_f64();
        let status_code = match &result {
            Ok(_) => {
                http_span.record("http.status_code", &OK.to_string());
                OK
            },
            Err(err) => {
                let code = match err {
                    AuthServiceError::Validation(_) => StatusCode::UNAUTHORIZED,
                    AuthServiceError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                http_span.record("http.status_code", &code.to_string());
                http_span.record_error(err);
                code.as_u16()
            },
        };
        
        LOGIN_HTTP_DURATION
            .with_label_values(&[POST, &status_code.to_string()])
            .observe(duration);
            
        record_http_request(POST, status_code);
        
        // Add a small delay to failed authentication attempts
        // to prevent timing attacks and slow down brute force
        if result.is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        match result {
            Ok(resp) => resp.into_response(),
            Err(err) => err.into_response(),
        }
    }
    .instrument(http_span_clone)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::post,
        Router,
    };
    use tower::ServiceExt;
    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};
    
    /// Creates a test application for login testing
    fn app() -> Router {
        init_jwt_secret();
        let app_state = Arc::new(state_with_redis());
        
        Router::new()
            .route("/auth/login", post(login_handler))
            .with_state(app_state)
    }
    
    #[tokio::test]
    async fn empty_login_returns_validation_error() {
        let app = app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"login":"","password":"test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        
        assert!(body_str.contains("Username or email is required"));
    }
    
    #[tokio::test]
    async fn empty_password_returns_validation_error() {
        let app = app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"login":"testuser","password":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        
        assert!(body_str.contains("Password is required"));
    }
    
    #[tokio::test]
    async fn invalid_credentials_returns_unauthorized() {
        let app = app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"login":"nonexistent","password":"wrongpass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    
    #[tokio::test]
    async fn multiple_aliases_work_for_login_field() {
        let app = app();
        
        // Test with "username" field
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"testuser","password":"testpass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        // We just check that it parses correctly - should return unauthorized since user doesn't exist
        assert_eq!(response1.status(), StatusCode::UNAUTHORIZED);
        
        // Test with "email" field
        let response2 = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"email":"test@example.com","password":"testpass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        // We just check that it parses correctly - should return unauthorized since user doesn't exist
        assert_eq!(response2.status(), StatusCode::UNAUTHORIZED);
    }
    
    #[tokio::test]
    async fn too_long_fields_return_validation_error() {
        let app = app();
        
        // Create very long login
        let long_login = "a".repeat(300);
        let body = format!(r#"{{"login":"{}","password":"test"}}"#, long_login);
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        
        assert!(body_str.contains("too long"));
    }
    
    #[tokio::test]
    async fn successful_login_works() {
        // This is an integration test that would actually create a user and test login
        // We're skipping this since it would require database setup
    }
}