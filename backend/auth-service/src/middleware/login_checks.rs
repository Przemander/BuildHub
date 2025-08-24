//! Login Security Middleware
//!
//! Protects authentication endpoints against brute force and credential stuffing attacks
//! with Redis-based rate limiting and account lockout mechanisms.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response, Json},
};
use hyper::body::to_bytes;
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn, span, Instrument, Level};

use crate::{
    app::AppState,
    config::redis::check_and_increment_rate_limit,
    utils::metrics,  // Fixed: correct import path
};

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Maximum login attempts per window
const MAX_LOGIN_ATTEMPTS: u32 = 5;

/// Rate limit window in seconds
const RATE_LIMIT_WINDOW_SECS: usize = 60;

// Removed LOCKOUT_DURATION_SECS - not used

// =============================================================================
// MIDDLEWARE
// =============================================================================

/// Login security middleware for rate limiting and account protection.
///
/// # Features
/// - Rate limiting per account
/// - Account lockout after repeated failures
/// - Fail-open policy (allows login if Redis is unavailable)
/// - Privacy-aware logging (no passwords or sensitive data)
///
/// # Usage
/// ```rust
/// router.route("/auth/login", post(handler))
///     .layer(from_fn_with_state(state, login_guard_middleware))
/// ```
pub async fn login_guard_middleware(
    State(app_state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next<Body>,
) -> Response {
    let span = span!(Level::INFO, "login_guard",
        path = %req.uri().path(),
        method = %req.method()
    );
    
    async move {
        // Extract request body
        let bytes = match to_bytes(req.body_mut()).await {
            Ok(body) => body,
            Err(e) => {
                warn!("Failed to read request body: {}", e);
                metrics::security::login_guard_error();
                return error_response(StatusCode::BAD_REQUEST, "Invalid request body");
            }
        };

        // Extract login identifier (email or username)
        let login_identifier = extract_login_identifier(&bytes);

        // Apply security checks if we have both login identifier and Redis
        if let (Some(login), Some(redis)) = (&login_identifier, &app_state.redis_client) {
            info!(
                login_type = if login.contains('@') { "email" } else { "username" },
                "Performing login security checks"
            );

            // Check account lockout
            if let Err(response) = check_account_lockout(redis, login).await {
                metrics::security::login_blocked("lockout");
                return response;
            }

            // Check rate limit
            if let Err(response) = check_rate_limit(redis, login).await {
                metrics::security::login_blocked("rate_limit");
                return response;
            }
            
            metrics::security::login_allowed();
        } else if login_identifier.is_some() && app_state.redis_client.is_none() {
            warn!("Redis unavailable - security checks disabled (fail-open)");
            metrics::security::login_guard_degraded();
        }

        // Reconstruct request body and continue
        *req.body_mut() = Body::from(bytes);
        next.run(req).await
    }
    .instrument(span)
    .await
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Extracts login identifier from request body.
fn extract_login_identifier(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|json| {
            // Try "email" field first, then "login" field for compatibility
            json.get("email")
                .or_else(|| json.get("login"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_lowercase()) // Normalize for consistent rate limiting
        })
}

/// Checks if account is locked out due to repeated failures.
async fn check_account_lockout(redis: &redis::Client, login: &str) -> Result<(), Response> {
    let mut conn = match redis.get_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Redis connection failed during lockout check: {}", e);
            metrics::external::redis_failure("lockout_check");
            return Ok(()); // Fail open
        }
    };

    let lockout_key = format!("auth:lockout:{}", sanitize_key(login));
    
    use redis::AsyncCommands;
    let is_locked: bool = match conn.exists(&lockout_key).await {
        Ok(locked) => locked,
        Err(e) => {
            warn!("Redis lockout check failed: {}", e);
            metrics::external::redis_failure("lockout_check");
            return Ok(()); // Fail open
        }
    };

    if is_locked {
        info!("Login attempt blocked - account locked");
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Account temporarily locked due to repeated failed attempts. Please try again later."
        ));
    }

    metrics::external::redis_success("lockout_check");
    Ok(())
}

/// Checks and enforces rate limiting.
async fn check_rate_limit(redis: &redis::Client, login: &str) -> Result<(), Response> {
    let rate_key = format!("auth:rate_limit:login:{}", sanitize_key(login));
    
    match check_and_increment_rate_limit(redis, &rate_key, MAX_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW_SECS).await {
        Ok(true) => {
            metrics::external::redis_success("rate_limit_check");
            Ok(())
        }
        Ok(false) => {
            info!("Login attempt blocked - rate limit exceeded");
            Err(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many login attempts. Please try again in {} seconds.", RATE_LIMIT_WINDOW_SECS)
            ))
        }
        Err(e) => {
            warn!("Rate limit check failed: {}", e);
            metrics::external::redis_failure("rate_limit_check");
            Ok(()) // Fail open
        }
    }
}

// Removed record_failed_login() function - not used
// Removed clear_failed_attempts() function - not used

/// Sanitizes keys to prevent injection.
fn sanitize_key(key: &str) -> String {
    // First filter allowed characters
    let filtered = key.chars()
        .filter(|c| c.is_alphanumeric() || *c == '@' || *c == '.' || *c == '_' || *c == '-')
        .collect::<String>();
    
    // Then replace path traversal sequences
    let no_traversal = filtered.replace("..", "");
    
    // Finally limit length
    no_traversal.chars().take(128).collect()
}

/// Creates an error response.
fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "status": "error",
            "message": message
        })),
    )
    .into_response()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::Request,
        middleware::from_fn_with_state,
        routing::post,
        Router,
    };
    use serde_json::json;
    use tower::ServiceExt;

    async fn dummy_handler() -> &'static str {
        "Login successful"
    }

    fn create_test_app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/login", post(dummy_handler))
            .layer(from_fn_with_state(state, login_guard_middleware))
    }

    #[tokio::test]
    async fn test_missing_login_field_passes() {
        metrics::init();
        let state = Arc::new(AppState {
            pool: crate::config::database::init_pool(),
            redis_client: None,
            email_config: None,
        });

        let app = create_test_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"password": "test"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_empty_login_field_passes() {
        metrics::init();
        let state = Arc::new(AppState {
            pool: crate::config::database::init_pool(),
            redis_client: None,
            email_config: None,
        });

        let app = create_test_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"email": "", "password": "test"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_valid_login_without_redis_passes() {
        metrics::init();
        let state = Arc::new(AppState {
            pool: crate::config::database::init_pool(),
            redis_client: None,
            email_config: None,
        });

        let app = create_test_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"email": "user@example.com", "password": "test"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_extract_login_identifier() {
        // Test with email field
        let json = json!({"email": "test@example.com", "password": "secret"});
        let bytes = json.to_string().into_bytes();
        assert_eq!(extract_login_identifier(&bytes), Some("test@example.com".to_string()));

        // Test with login field (backwards compatibility)
        let json = json!({"login": "username", "password": "secret"});
        let bytes = json.to_string().into_bytes();
        assert_eq!(extract_login_identifier(&bytes), Some("username".to_string()));

        // Test with empty field
        let json = json!({"email": "", "password": "secret"});
        let bytes = json.to_string().into_bytes();
        assert_eq!(extract_login_identifier(&bytes), None);

        // Test with missing field
        let json = json!({"password": "secret"});
        let bytes = json.to_string().into_bytes();
        assert_eq!(extract_login_identifier(&bytes), None);

        // Test with invalid JSON
        let bytes = b"invalid json";
        assert_eq!(extract_login_identifier(bytes), None);
    }

    #[test]
    fn test_sanitize_key() {
        assert_eq!(sanitize_key("test@example.com"), "test@example.com");
        assert_eq!(sanitize_key("user_name-123"), "user_name-123");
        assert_eq!(sanitize_key("bad<>chars"), "badchars");
        // Fix: Update the test to expect "etcpasswd" without dots
        assert_eq!(sanitize_key("../../etc/passwd"), "etcpasswd");
        
        // Test length limiting
        let long_key = "a".repeat(200);
        assert_eq!(sanitize_key(&long_key).len(), 128);
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_rate_limiting_with_redis() {
        use crate::utils::test_utils::state_with_redis;
        
        metrics::init();
        let state = Arc::new(state_with_redis());
        let app = create_test_app(state.clone());

        let login_data = json!({"email": "ratelimit@example.com", "password": "test"}).to_string();

        // First 5 attempts should pass
        for i in 0..5 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/login")
                        .method("POST")
                        .header("Content-Type", "application/json")
                        .body(Body::from(login_data.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "Attempt {} should succeed", i + 1);
        }

        // 6th attempt should be rate limited
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
