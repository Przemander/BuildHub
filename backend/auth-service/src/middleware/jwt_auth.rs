//! JWT authentication middleware for BuildHub.
//!
//! This middleware validates JWT tokens on protected routes using the shared JWT utility functions.
//! It checks for token presence, validity, and revocation (via Redis blocklist).
//! On failure, it returns a 401 Unauthorized response and logs the event.

use crate::app::AppState;
use crate::utils::error_new::ApiError; // ← Zmienione z utils::errors
use crate::utils::jwt;
use crate::{log_error, log_info, log_warn};
use axum::{extract::State, http::Request, middleware::Next, response::IntoResponse};
use std::sync::Arc;
use crate::metricss::middleware_metrics::jwt_auth;
use std::time::Instant;

pub async fn jwt_auth_middleware<B>(
    State(app_state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    
    // Extract the Authorization header and validate Bearer token format
    let token = match extract_bearer_token(&req) {
        Some(token) => token,
        None => {
            log_warn!("JWTAuth", "Missing or invalid Authorization header", "unauthorized");
            // 🆕 Record middleware metrics
            jwt_auth::record_unauthorized("protected", "missing_header");
            return ApiError::unauthorized("Missing or invalid Authorization header")
                .into_response();
        }
    };

    // Get Redis client for token validation (required for blocklist check)
    let redis_client = match &app_state.redis_client {
        Some(redis) => redis,
        None => {
            log_error!("JWTAuth", "Redis unavailable for token validation", "system_error");
            // 🆕 Record service unavailable
            jwt_auth::record_service_unavailable("protected");
            return ApiError::service_unavailable("Redis unavailable for token validation")
                .into_response();
        }
    };

    // Validate the token and handle authentication result
    match jwt::validate_token(token, redis_client).await {
        Ok(claims) => {
            log_info!("JWTAuth", &format!("Token valid for user {}", claims.sub), "success");
            // 🆕 Record successful authentication
            jwt_auth::record_success("protected");
            
            let response = next.run(req).await;
            
            // 🆕 Record processing duration
            let duration = start_time.elapsed().as_secs_f64();
            crate::metricss::middleware_metrics::record_middleware_duration(
                duration, "jwt_auth", "protected"
            );
            
            response
        }
        Err(err) => {
            log_warn!(
                "JWTAuth",
                &format!("Invalid or expired token: {}", err),
                "unauthorized"
            );
            
            // 🆕 Record authentication failure with context
            jwt_auth::record_unauthorized("protected", "token_validation_failed");
            
            let api_error = ApiError::from(err);
            api_error.into_response()
        }
    }
}

/// Extracts a Bearer token from the Authorization header of a request.
///
/// Returns `None` if:
/// - The header is missing
/// - The header value isn't valid UTF-8
/// - The header doesn't begin with "Bearer "
///
/// Otherwise, returns `Some(token)` with the extracted token string.
fn extract_bearer_token<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|value| {
            if value.starts_with("Bearer ") {
                Some(value.trim_start_matches("Bearer ").trim())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::database::{init_pool, run_migrations};
    use crate::utils::jwt::{self, TOKEN_TYPE_ACCESS};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use chrono::Duration;
    use redis::Client;
    use std::env;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A dummy handler that returns "OK" for testing
    async fn ok_handler() -> &'static str {
        "OK"
    }

    /// Build AppState with optional Redis URL, using in-memory SQLite
    fn make_state(redis_url: Option<&str>) -> Arc<AppState> {
        // Configure test environment
        env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-for-security-compliance");
        env::set_var("DATABASE_URL", ":memory:");
        
        // Initialize database
        let pool = init_pool();
        run_migrations(&pool).expect("Failed to run migrations on in-memory DB");
        
        // Create AppState with optional Redis client
        let redis_client = redis_url.map(Client::open).transpose().unwrap();
        Arc::new(AppState {
            pool,
            redis_client,
            email_config: None,
        })
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        
        // Verify response body contains JSON error
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("unauthorized"), "Response should contain error status");
        assert!(body_str.contains("Missing or invalid Authorization header"), "Response should contain specific error message");
    }

    #[tokio::test]
    async fn valid_token_calls_next() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .unwrap();

        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act
        let req = Request::builder()
            .uri("/")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        
        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(resp.into_response().into_body())
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn malformed_auth_header_returns_401() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act - Send a request with a malformed Authorization header (missing "Bearer" prefix)
        let req = Request::builder()
            .uri("/")
            .header("authorization", "invalid-format-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        
        // Verify response is JSON with proper error structure
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("\"status\":\"unauthorized\""), "Response should be structured JSON error");
    }

    #[tokio::test]
    async fn expired_token_returns_401_with_proper_error() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        
        // Generate expired token
        let expired_token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1)))
            .unwrap();

        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act
        let req = Request::builder()
            .uri("/")
            .header("authorization", format!("Bearer {}", expired_token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        
        // Verify response contains expiration error information
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("expired"), "Response should mention token expiration");
    }

    #[tokio::test]
    async fn redis_unavailable_returns_503() {
        // Arrange - state without Redis
        let state = make_state(None);
        let token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .unwrap();

        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act
        let req = Request::builder()
            .uri("/")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        
        // Verify response mentions Redis unavailability
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Redis unavailable"), "Response should mention Redis unavailability");
    }

    #[tokio::test]
    async fn extract_bearer_token_handles_edge_cases() {
        // Case 1: No Authorization header
        let req = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Case 2: Invalid format (not starting with "Bearer ")
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Token abc123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Case 3: Valid Bearer token
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Bearer abc123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("abc123"));

        // Case 4: Bearer token with extra whitespace
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Bearer  abc123  ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("abc123"));
    }

    #[tokio::test]
    async fn invalid_token_format_returns_401() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act - Send request with completely invalid token
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Bearer not-a-jwt-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        
        // Verify proper error structure
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("\"status\":\"unauthorized\""), "Should return structured JSON error");
        assert!(body_str.contains("Invalid token"), "Should mention token invalidity");
    }
}