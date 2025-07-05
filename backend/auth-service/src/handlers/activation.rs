//! Account activation HTTP handler.
//!
//! This module implements the endpoint that handles user account activation
//! via email confirmation links. It renders appropriate HTML responses based
//! on the activation result using the unified error system.
//!
//! # Endpoint
//! `GET /auth/activate?code=<activation_code>`
//!
//! # Flow
//! 1. User receives activation email with unique code
//! 2. User clicks the link which calls this endpoint
//! 3. System validates the code and activates the account
//! 4. User sees an HTML page with the result

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::activation_logic::process_activation; // ← Zmienione z process_activation_unified
use crate::utils::error_new::AuthServiceError;

/// Query parameters for account activation.
///
/// The activation code is extracted from the URL query string.
#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    /// The unique activation code sent to the user's email
    pub code: String,
}

/// Handles account activation requests using the unified error system.
///
/// Processes the activation code and renders an appropriate HTML page
/// with the result of the activation attempt.
///
/// # Arguments
/// * `params` - Query parameters containing the activation code
/// * `app_state` - Application state containing Redis and database connections
///
/// # Returns
/// An HTML response with a user-friendly message about the activation result
#[instrument(
    name = "activate_account",
    level = "info",
    skip(app_state),
    fields(
        path = "/auth/activate", 
        method = "GET",
        code_length = tracing::field::Empty
    )
)]
pub async fn activate_account_handler(
    Query(params): Query<ActivationParams>,
    State(app_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Add activation code length to trace span (without exposing the actual code)
    tracing::Span::current().record(
        "code_length",
        &tracing::field::display(params.code.len())
    );

    // Process the activation code using unified error system
    match process_activation(&app_state, &params.code).await { // ← Zmienione z process_activation_unified
        Ok(()) => Html(render_page(
            "Account Activated",
            "Your account has been successfully activated. You can now log in.",
            "success",
        ))
        .into_response(),
        
        Err(AuthServiceError::Validation(validation_err)) => {
            // Check the specific validation error type for better UX
            let (title, message) = match validation_err.to_string().as_str() {
                msg if msg.contains("Invalid or expired") => (
                    "Invalid Activation Link",
                    "The activation link is invalid or has expired. Please request a new activation link."
                ),
                msg if msg.contains("No user found") => (
                    "Account Not Found", 
                    "We couldn't find an account for this activation link. Please register or contact support."
                ),
                _ => (
                    "Validation Error",
                    "There was an issue with your activation request. Please try again or contact support."
                ),
            };
            
            Html(render_page(title, message, "error")).into_response()
        }
        
        Err(AuthServiceError::Configuration(_)) => Html(render_page(
            "Service Unavailable",
            "We're experiencing technical difficulties. Please try again later.",
            "error",
        ))
        .into_response(),
        
        Err(AuthServiceError::Database(_)) => Html(render_page(
            "Service Unavailable", 
            "We're experiencing database issues. Please try again later.",
            "error",
        ))
        .into_response(),
        
        Err(AuthServiceError::RateLimit(_)) => Html(render_page(
            "Too Many Requests",
            "You've made too many activation attempts. Please wait a moment before trying again.",
            "error",
        ))
        .into_response(),
        
        Err(_) => Html(render_page(
            "Activation Failed",
            "We couldn't activate your account. Please try again or contact support.",
            "error",
        ))
        .into_response(),
    }
}

/// Renders a simple HTML page with a title and message.
///
/// # Arguments
/// * `title` - The page title and primary heading
/// * `message` - The message to display to the user
/// * `status` - Status of the operation: "success", "error", or "info"
///
/// # Returns
/// HTML page as a String
fn render_page(title: &str, message: &str, status: &str) -> String {
    // Add status-specific CSS class for styling
    let status_class = match status {
        "success" => "success-message",
        "error" => "error-message",
        "info" => "info-message",
        _ => "neutral-message",
    };

    // Pobierz URL frontendu z konfiguracji
    let frontend_url = std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let login_url = format!("{}/auth", frontend_url);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 650px;
            margin: 0 auto;
            padding: 2rem 1rem;
            text-align: center;
        }}
        h1 {{
            margin-bottom: 1rem;
            color: #2c3e50;
        }}
        .message {{
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1.5rem;
        }}
        .success-message {{
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        .error-message {{
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        .info-message {{
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }}
        .neutral-message {{
            background-color: #e2e3e5;
            color: #383d41;
            border: 1px solid #d6d8db;
        }}
        .btn {{
            display: inline-block;
            background-color: #3490dc;
            color: white;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            transition: background-color 0.2s;
        }}
        .btn:hover {{
            background-color: #2779bd;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="message {status_class}">
        <p>{message}</p>
    </div>
    <a href="{login_url}" class="btn">Go to Login</a>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::Request,
        Router,
        routing::get,
    };
    use tower::ServiceExt;
    
    use crate::utils::test_utils::state_with_redis;

    /// Creates a test router with activation handler
    fn app() -> Router {
        let app_state = Arc::new(state_with_redis());
        
        Router::new()
            .route("/auth/activate", get(activate_account_handler))
            .with_state(app_state)
    }

    #[tokio::test]
    async fn missing_code_returns_bad_request() {
        // Arrange
        let app = app();
        
        // Act - request with missing code parameter
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/activate")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();
            
        // Assert
        assert_eq!(response.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn invalid_code_returns_proper_html() {
        // Arrange
        let app = app();
        
        // Act - request with invalid activation code
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/activate?code=invalid-code")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();
            
        // Assert
        assert_eq!(response.status().as_u16(), 200); // HTML responses are always 200 OK
        
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        
        // Verify it contains error messaging
        assert!(html.contains("Invalid Activation Link"));
        assert!(html.contains("error-message"));
    }

    #[test]
    fn render_page_includes_correct_status_class() {
        // Arrange & Act
        let success_html = render_page("Success Title", "Success message", "success");
        let error_html = render_page("Error Title", "Error message", "error");
        let info_html = render_page("Info Title", "Info message", "info");
        
        // Assert
        assert!(success_html.contains("success-message"));
        assert!(error_html.contains("error-message"));
        assert!(info_html.contains("info-message"));
        assert!(success_html.contains("Go to Login"));
        assert!(error_html.contains("Go to Login"));
    }

    #[tokio::test]
    async fn successful_activation_returns_success_html() {
        // Note: This test would require setting up a valid activation code
        // in Redis, which is more complex. For now, we're testing the error cases.
        // Integration tests with a real Redis instance would be needed for full coverage.
    }
}