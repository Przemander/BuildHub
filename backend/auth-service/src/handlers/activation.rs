//! Account activation HTTP handler.
//!
//! Provides user-friendly HTML responses for email activation links
//! with proper error handling and observability.

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

use crate::{
    app::AppState,
    handlers::activation_logic::process_activation,
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

/// Query parameters for account activation.
#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    pub code: String,
}

/// Handles GET /auth/activate requests.
///
/// Returns HTML pages for user-friendly activation feedback.
/// This endpoint is typically accessed via email links.
pub async fn activate_account_handler(
    Query(params): Query<ActivationParams>,
    State(app_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Create HTTP request span with request metadata
    let span = span!(Level::INFO, "http_request",
        method = "GET",
        path = "/auth/activate",
        code_length = params.code.len()
    );
    let span_for_instrument = span.clone();
    // Start timing for metrics
    let timer = metrics::http::timer("/auth/activate");

    async move {
        info!("Received activation request");
        
        // Process activation
        let result = process_activation(&app_state, &params.code).await;

        // Map result to HTTP status code
        let status = match &result {
            Ok(_) => {
                info!("Account activation successful");
                200
            }
            Err(AuthServiceError::Validation { .. }) => {  // Fixed: use struct pattern
                info!("Account activation failed - invalid code");
                400
            }
            Err(AuthServiceError::Configuration(_)) => {
                error!("Account activation failed - service configuration issue");
                500
            }
            Err(AuthServiceError::Database(_)) => {
                error!("Account activation failed - database issue");
                500
            }
            Err(e) => {
                error!("Account activation failed - unexpected error: {}", e);
                500
            }
        };
        
        // Record metrics
        span.record("http.status_code", &status);
        metrics::http::request("/auth/activate", "GET", status);
        drop(timer);

        // Render HTML response based on result
        match result {
            Ok(_) => Html(render_page(
                "Account Activated",
                "Your account has been successfully activated. You can now log in.",
                "success",
            )),
            
            Err(AuthServiceError::Validation { message, .. }) => {  // Fixed: use struct pattern with destructuring
                let (title, message) = if message.contains("expired") {
                    ("Invalid Activation Link", "The activation link is invalid or has expired.")
                } else if message.contains("not found") || message.contains("no longer exists") {
                    ("Account Not Found", "We couldn't find an account for this activation link.")
                } else {
                    ("Validation Error", "There was an issue with your activation request.")
                };
                Html(render_page(title, message, "error"))
            },
            
            Err(AuthServiceError::Configuration(_) | AuthServiceError::Database(_)) => {
                Html(render_page(
                    "Service Unavailable",
                    "We're experiencing technical difficulties. Please try again later.",
                    "error",
                ))
            },
            
            Err(_) => Html(render_page(
                "Activation Failed",
                "We couldn't activate your account. Please try again or contact support.",
                "error",
            )),
        }
    }
    .instrument(span_for_instrument)
    .await
}

/// Renders a simple HTML page with a title and message.
fn render_page(title: &str, message: &str, status: &str) -> String {
    let status_class = match status {
        "success" => "success",
        "error" => "error",
        _ => "info",
    };

    let frontend_url = std::env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    let login_url = format!("{}/auth", frontend_url);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }}
        .card {{
            background: white;
            border-radius: 12px;
            padding: 2.5rem;
            max-width: 420px;
            width: 100%;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            text-align: center;
        }}
        h1 {{
            color: #2d3748;
            font-size: 1.75rem;
            margin-bottom: 1rem;
        }}
        .message {{
            padding: 1rem;
            border-radius: 8px;
            margin: 1.5rem 0;
            font-size: 0.95rem;
            line-height: 1.5;
        }}
        .success {{
            background: #c6f6d5;
            color: #22543d;
            border: 1px solid #9ae6b4;
        }}
        .error {{
            background: #fed7d7;
            color: #742a2a;
            border: 1px solid #fc8181;
        }}
        .info {{
            background: #bee3f8;
            color: #2c5282;
            border: 1px solid #90cdf4;
        }}
        .btn {{
            display: inline-block;
            background: #667eea;
            color: white;
            text-decoration: none;
            padding: 0.75rem 2rem;
            border-radius: 6px;
            font-weight: 500;
            transition: all 0.2s;
            margin-top: 0.5rem;
        }}
        .btn:hover {{
            background: #5a67d8;
            transform: translateY(-1px);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{title}</h1>
        <div class="message {status_class}">
            {message}
        </div>
        <a href="{login_url}" class="btn">Go to Login</a>
    </div>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    use crate::utils::test_utils::state_with_redis;

    fn app() -> Router {
        metrics::init();
        let app_state = Arc::new(state_with_redis());
        Router::new()
            .route("/auth/activate", get(activate_account_handler))
            .with_state(app_state)
    }

    #[tokio::test]
    async fn test_missing_code_returns_bad_request() {
        let app = app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/activate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn test_invalid_code_returns_proper_html() {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/activate?code=invalid-code")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 200); // HTML always returns 200
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        
        // Should contain error messaging
        assert!(html.contains("Invalid") || html.contains("expired"));
        assert!(html.contains("error"));
        assert!(html.contains("Go to Login"));
    }

    #[test]
    fn test_render_page_includes_correct_status_class() {
        let success_html = render_page("Success", "Test", "success");
        let error_html = render_page("Error", "Test", "error");
        
        // Fix: check for the combined class string "message success" instead of just "success"
        assert!(success_html.contains(r#"class="message success""#));
        assert!(error_html.contains(r#"class="message error""#));
        assert!(success_html.contains("Go to Login"));
    }

    #[tokio::test]
    async fn test_activation_with_empty_code_returns_html() {
        let app = app();
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/activate?code=")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 200);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<html"));
        assert!(html.contains("error"));
    }

    #[test]
    fn test_frontend_url_from_env() {
        std::env::set_var("FRONTEND_URL", "https://example.com");
        let html = render_page("Test", "Message", "success");
        assert!(html.contains("https://example.com/auth"));
        std::env::remove_var("FRONTEND_URL");
    }

    #[test]
    fn test_frontend_url_default() {
        std::env::remove_var("FRONTEND_URL");
        let html = render_page("Test", "Message", "success");
        assert!(html.contains("http://localhost:8080/auth"));
    }
}
