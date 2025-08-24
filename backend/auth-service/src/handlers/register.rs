//! HTTP handler for user registration endpoint.
//!
//! Provides the REST API interface for user registration with
//! proper request validation, error handling, and observability.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

use crate::{
    app::AppState,
    db::users::RegisterData,
    handlers::register_logic::process_registration,
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

/// Handles POST /auth/register requests.
///
/// # Request Format
/// ```json
/// {
///   "username": "john_doe",
///   "email": "john@example.com",
///   "password": "SecurePass123!"
/// }
/// ```
///
/// # Response Format
/// - 201 Created: Registration successful
/// - 400 Bad Request: Validation failed or duplicate user
/// - 500 Internal Server Error: Server configuration or database issues
pub async fn register_handler(
    State(app_state): State<Arc<AppState>>,
    Json(data): Json<RegisterData>,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "POST",
        path = "/auth/register",
        email_domain = data.email.split('@').nth(1).unwrap_or("unknown")
    );
    let span_for_instrument = span.clone();
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/register");

    async move {
        info!("Received registration request");
        
        // Process the registration
        let result = process_registration(&app_state, data).await;

        // Map result to HTTP status code
        let status = match &result {
            Ok(_) => {
                info!("Registration successful");
                StatusCode::CREATED
            }
            Err(AuthServiceError::Validation { .. }) => {  // Fixed: use struct pattern
                info!("Registration failed - validation error");
                StatusCode::BAD_REQUEST
            }
            Err(AuthServiceError::Configuration(_)) => {
                error!("Registration failed - configuration error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Err(e) => {
                error!("Registration failed - unexpected error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        
        // Record metrics
        span.record("http.status_code", &status.as_u16());
        metrics::http::request("/auth/register", "POST", status.as_u16());
        drop(timer); // Timer records duration when dropped
        
        result
    }
    .instrument(span_for_instrument)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::User;
    use crate::utils::test_utils::state_with_redis;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::json;
    use tower::ServiceExt;
    use std::sync::Arc;

    // Function to create a test app
    fn make_app() -> Router {
        metrics::init();
        let mut state = state_with_redis();
        
        // Add missing email configuration
        state.email_config = Some(crate::utils::email::EmailConfig::dummy());
        
        Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state))
    }

    // Helper function to ensure a user exists
    #[allow(dead_code)]
    fn ensure_user_exists(test_username: &str, test_email: &str) -> User {
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Check if user exists
        use crate::db::schema::users::dsl::*;
        use diesel::prelude::*;
        let existing = users
            .filter(username.eq(test_username))
            .first::<User>(&mut conn)
            .optional()
            .unwrap();
            
        match existing {
            Some(user) => user,
            None => {
                // Create and return new user
                let new_user = User::new_for_insert(test_username, test_email, "TestPass123!");
                User::save_new(new_user, &mut conn).unwrap()
            }
        }
    }

    // Helper function to delete a user if it exists
    fn ensure_user_doesnt_exist(test_username: &str, test_email: &str) {
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Delete any existing user
        use crate::db::schema::users::dsl::*;
        use diesel::prelude::*;
        let _ = diesel::delete(
            users.filter(username.eq(test_username).or(email.eq(test_email)))
        )
        .execute(&mut conn);
    }

    // Fix test_valid_registration_returns_201
    #[tokio::test]
    async fn test_valid_registration_returns_201() {
        // Generate unique username/email to avoid conflicts
        let unique_id = uuid::Uuid::new_v4().to_string();
        let test_username = format!("testuser_{}", &unique_id[..8]);
        let test_email = format!("test_{}@example.com", &unique_id[..8]);
        
        // Make sure user doesn't exist
        ensure_user_doesnt_exist(&test_username, &test_email);
        
        let app = make_app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": test_username,
                            "email": test_email,
                            "password": "TestPass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // Fix test_duplicate_username_returns_400
    #[tokio::test]
    async fn test_duplicate_username_returns_400() {
        // Initialize test environment
        crate::utils::test_utils::init_test_env();
        metrics::init();
        
        // Use a simple, predictable username
        let test_username = "dup_test_user";
        let test_email = "dup_test@example.com";
        
        // Create a shared state that will be used throughout the test
        let mut shared_state = state_with_redis();
        shared_state.email_config = Some(crate::utils::email::EmailConfig::dummy());
        let shared_state = Arc::new(shared_state);
        
        // Get a connection from the shared state
        let mut conn = shared_state.pool.get().expect("Failed to get DB connection");
        
        // Clean up any existing user first
        use crate::db::schema::users::dsl::*;
        use diesel::prelude::*;
        
        let deleted = diesel::delete(users.filter(username.eq(test_username)))
            .execute(&mut conn)
            .unwrap_or(0);
        
        println!("Deleted {} existing users with username '{}'", deleted, test_username);
        
        // First, register the user using the API to ensure it goes through the same flow
        let app = Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(shared_state.clone());
        
        let first_response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": test_username,
                            "email": test_email,
                            "password": "TestPass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        
        let first_status = first_response.status();
        let first_body = hyper::body::to_bytes(first_response.into_body()).await.unwrap();
        let first_body_str = String::from_utf8_lossy(&first_body);
        
        println!("First registration - Status: {}, Body: {}", first_status, first_body_str);
        assert_eq!(first_status, StatusCode::CREATED, "First registration should succeed");
        
        // Verify the user exists in the database
        let mut conn = shared_state.pool.get().expect("Failed to get DB connection");
        let count: i64 = users
            .filter(username.eq(test_username))
            .count()
            .get_result(&mut conn)
            .expect("Failed to count users");
            
        println!("Found {} users with username '{}'", count, test_username);
        assert!(count > 0, "Test user was not created properly");
        
        // Now try to register with the same username - this should fail
        let app = Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(shared_state.clone());
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": test_username,
                            "email": "different@example.com",
                            "password": "TestPass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        
        println!("Duplicate registration - Status: {}, Body: {}", status, body_str);
        
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Expected 400 for duplicate username, got {} with body: {}",
            status,
            body_str
        );
        
        // Verify error message
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
            if let Some(message) = json.get("message").and_then(|m| m.as_str()) {
                assert!(
                    message.to_lowercase().contains("username") || 
                    message.to_lowercase().contains("taken") ||
                    message.to_lowercase().contains("already"),
                    "Error message doesn't indicate duplicate username: '{}'",
                    message
                );
            }
        }
    }
    
    #[tokio::test]
    async fn test_invalid_username_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "ab",  // Too short
                            "email": "test@example.com",
                            "password": "SecurePass123!"
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
    async fn test_invalid_email_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "validuser",
                            "email": "invalid-email",  // Invalid format
                            "password": "SecurePass123!"
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
    async fn test_weak_password_returns_400() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "validuser",
                            "email": "test@example.com",
                            "password": "weak"  // Too weak
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
    async fn test_missing_field_returns_422() {
        let app = make_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "testuser",
                            // Missing email and password
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_missing_config_returns_500() {
        // Initialize metrics
        crate::utils::metrics::init();
        
        // Create state without email config
        let mut state = state_with_redis();
        state.email_config = None; // No email config

        // Build router with this state
        let app = Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "testuser",
                            "email": "test@example.com",
                            "password": "SecurePass123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}