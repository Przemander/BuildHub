//! User registration HTTP handler with email activation.
//!
//! This module provides the API endpoint for user registration with:
//! - Input validation
//! - User creation in the database
//! - Account activation flow via email
//! - Structured error responses
//! - OpenAPI documentation
//! - Comprehensive request tracing

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::Value;
use std::sync::Arc;
use tracing::instrument;

use crate::{
    app::AppState,
    db::users::RegisterData,
    handlers::register_logic::process_registration,
};

/// Handles user registration requests.
///
/// # Endpoint: POST /auth/register
///
/// Takes JSON user data, validates it, creates an inactive account, 
/// and initiates the email verification flow.
///
/// ## Request body
/// ```json
/// {
///   "username": "johndoe",
///   "email": "john.doe@example.com",
///   "password": "SecureP@ssw0rd"
/// }
/// ```
///
/// ## Responses
///
/// * `201 Created` - Registration successful, verification email sent
/// * `400 Bad Request` - Invalid input data
/// * `409 Conflict` - Username or email already exists
/// * `500 Internal Server Error` - Server-side error
///
/// ## Example success response
/// ```json
/// {
///   "status": "success",
///   "message": "Registration successful! Please check your email to activate your account."
/// }
/// ```
#[instrument(
    name = "register_user",
    level = "info",
    skip(app_state, register_data),
    fields(
        path = "/auth/register",
        method = "POST",
        username = tracing::field::Empty,
        email_domain = tracing::field::Empty
    )
)]
pub async fn register_handler(
    State(app_state): State<Arc<AppState>>,
    Json(register_data): Json<RegisterData>,
) -> impl IntoResponse {
    // Add useful trace information without exposing full PII
    tracing::Span::current()
        .record("username", &tracing::field::display(&register_data.username))
        .record(
            "email_domain",
            &tracing::field::display(
                register_data
                    .email
                    .split('@')
                    .nth(1)
                    .unwrap_or("invalid"),
            ),
        );

    // Process the registration request
    let (status, body): (StatusCode, Value) = 
        process_registration(&app_state, register_data).await;
    
    // Return the response with appropriate status code
    (status, Json(body))
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

    /// Creates a test router with the register handler
    fn app() -> Router {
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        
        Router::new()
            .route("/auth/register", post(register_handler))
            .with_state(Arc::new(state))
    }

    #[tokio::test]
    async fn valid_registration_returns_201_created() {
        // Arrange
        let app = app();
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
        assert_eq!(response.status(), StatusCode::CREATED);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "success");
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("check your email"));
    }

    #[tokio::test]
    async fn invalid_data_returns_400_bad_request() {
        // Arrange
        let app = app();
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

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(body["status"], "error");
    }

    #[tokio::test]
    async fn duplicated_registration_returns_409_conflict() {
        // Arrange
        let app = app();
        let request_body = json!({
            "username": "duplicate",
            "email": "duplicate@example.com",
            "password": "SecurePass123!"
        });

        // First registration
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

        // Assert
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}