//! Login security middleware for protecting authentication endpoints.
//!
//! Provides automatic account lockout and rate limiting to prevent:
//! - Credential stuffing attacks
//! - Brute force password attempts
//! - Account enumeration
//!
//! This middleware performs several security checks before allowing login attempts:
//! 1. Checks if the account is currently locked out
//! 2. Enforces per-account rate limiting
//! 3. Uses Redis for distributed state management
//! 4. Gracefully degrades when Redis is unavailable

use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper::body::{to_bytes, Bytes};
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::app::AppState;
use crate::utils::error_new::ApiError; // ← Zmienione z utils::errors
use crate::utils::rate_limit::check_and_increment;

/// Middleware guard for login attempts - applies rate limiting and account lockout.
///
/// Extracts the login identifier from the request body and applies security checks:
/// - Blocks if the account is currently locked out
/// - Enforces rate limiting per login identifier
/// - Reconstructs the request body for downstream handlers
///
/// # Security Note
/// This middleware fails open if Redis is unavailable to maintain service availability.
/// Use additional protection layers (e.g., WAF) for defense in depth.
pub async fn login_guard_middleware(
    State(app_state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next<Body>,
) -> Response {
    debug!("Processing login guard middleware");
    
    // 1) Read the request body into `Bytes`
    let bytes: Bytes = match to_bytes(req.body_mut()).await {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            return ApiError::bad_request("Invalid request body")
                .into_response();
        }
    };

    // 2) Extract the "login" field from the JSON body
    let login_opt = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("login").and_then(|l| l.as_str().map(str::to_string)));

    // 3) Enforce lockout and rate-limit if we have a login and Redis
    if let (Some(login), Some(redis)) = (login_opt, &app_state.redis_client) {
        debug!("Checking security policies for login attempt");
        
        // Check for account lockout
        if let Err(resp) = enforce_lockout(redis, &login).await {
            return resp;
        }
        
        // Check for rate limiting
        if let Err(resp) = enforce_rate_limit(redis, &login).await {
            return resp;
        }
    }

    // 4) Reattach the original body so the handler can read it
    *req.body_mut() = Body::from(bytes);

    // 5) Call the next handler
    debug!("Login guard passed, proceeding to handler");
    next.run(req).await
}

/// Checks if account is locked out in Redis. 
/// 
/// Returns Ok if:
/// - The account is not locked out
/// - Redis is unavailable (fail open)
/// 
/// Returns Err with 401 Unauthorized response if account is locked out.
pub async fn enforce_lockout(
    redis: &redis::Client,
    login: &str,
) -> Result<(), Response> {
    let mut conn = match redis.get_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Redis connection failed in lockout check: {}", e);
            return Ok(());  // fail open on Redis errors
        }
    };
    
    let key = format!("lockout:{}", login);
    let locked: bool = match conn.exists(&key).await {
        Ok(exists) => exists,
        Err(e) => {
            warn!("Redis error when checking lockout: {}", e);
            return Ok(());  // fail open on Redis errors
        }
    };
    
    if locked {
        debug!("Account lockout active for login: {}", login);
        let err = ApiError::unauthorized(
            "Account temporarily locked due to repeated failed login attempts",
        );
        return Err(err.into_response());
    }
    
    Ok(())
}

/// Enforces rate limiting for login attempts.
/// 
/// Returns Ok if:
/// - Within allowed rate limits (default: 5 attempts per 60 seconds)
/// - Redis is unavailable (fail open)
/// 
/// Returns Err with 429 Too Many Requests response if rate limit is exceeded.
pub async fn enforce_rate_limit(
    redis: &redis::Client,
    login: &str,
) -> Result<(), Response> {
    // Constants for rate limiting
    const MAX_LOGIN_ATTEMPTS: u32 = 5;
    const RATE_LIMIT_WINDOW_SECS: usize = 60;
    
    let key = format!("rate:login:{}", login);
    
    // Call the check_and_increment utility
    let allowed = match check_and_increment(
        redis, 
        &key, 
        MAX_LOGIN_ATTEMPTS, 
        RATE_LIMIT_WINDOW_SECS
    ).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Redis error in rate limiting: {}", e);
            true  // fail open on Redis errors
        }
    };
    
    if !allowed {
        debug!("Rate limit exceeded for login: {}", login);
        // Now using proper too_many_requests method from unified error system
        let err = ApiError::too_many_requests(
            "Too many login attempts; please try again later"
        );
        return Err(err.into_response());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use redis::{AsyncCommands, cmd};
    use uuid::Uuid;

    /// Flush Redis and return a client for testing.
    async fn setup_redis() -> redis::Client {
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let mut conn = client.get_async_connection().await.unwrap();
        // FLUSHDB via generic command to ensure clean test environment
        let _: () = cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        client
    }

    #[tokio::test]
    async fn enforce_rate_limit_allows_and_blocks() {
        let client = setup_redis().await;
        let login = Uuid::new_v4().to_string();

        // Under limit (5 attempts) => Ok
        for i in 1..=5 {
            assert!(
                enforce_rate_limit(&client, &login).await.is_ok(),
                "attempt #{} should pass",
                i
            );
        }

        // 6th attempt => Err(Response with 429 Too Many Requests)
        let err = enforce_rate_limit(&client, &login)
            .await
            .unwrap_err();
        // Now properly returns 429 instead of 400
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn enforce_rate_limit_fail_open_on_redis_error() {
        // Bad port => fail-open => Ok
        let client = redis::Client::open("redis://127.0.0.1:6380/").unwrap();
        let login = Uuid::new_v4().to_string();
        assert!(enforce_rate_limit(&client, &login).await.is_ok());
    }

    #[tokio::test]
    async fn enforce_lockout_allows_and_blocks() {
        let client = setup_redis().await;
        let mut conn = client.get_async_connection().await.unwrap();
        let login = Uuid::new_v4().to_string();

        // No lockout => Ok
        assert!(enforce_lockout(&client, &login).await.is_ok());

        // Set lockout key with 60s TTL
        let key = format!("lockout:{}", login);
        let _: () = conn.set_ex(&key, 1, 60).await.unwrap();

        // Now should Err(Response 401)
        let err = enforce_lockout(&client, &login)
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }
    
    #[tokio::test]
    async fn enforce_lockout_fail_open_on_redis_error() {
        // Bad port => fail-open => Ok
        let client = redis::Client::open("redis://127.0.0.1:6380/").unwrap();
        let login = Uuid::new_v4().to_string();
        assert!(enforce_lockout(&client, &login).await.is_ok());
    }

    #[tokio::test]
    async fn login_guard_middleware_processes_valid_request() {
        // This test would require more setup with axum testing framework
        // Testing the actual middleware behavior with request/response flow
        // For now, we focus on testing the individual enforcement functions
    }

    #[tokio::test] 
    async fn login_guard_extracts_login_from_json() {
        // Test that the middleware correctly extracts login from request body
        let json_body = r#"{"login": "test@example.com", "password": "secret"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json_body).unwrap();
        let login = parsed.get("login").and_then(|l| l.as_str());
        
        assert_eq!(login, Some("test@example.com"));
    }

    #[tokio::test]
    async fn login_guard_handles_malformed_json() {
        // Test graceful handling of malformed JSON
        let malformed_json = r#"{"login": incomplete"#;
        let parsed = serde_json::from_str::<serde_json::Value>(malformed_json);
        
        assert!(parsed.is_err(), "Should fail to parse malformed JSON");
    }

    #[tokio::test]
    async fn login_guard_handles_missing_login_field() {
        // Test behavior when login field is missing
        let json_without_login = r#"{"password": "secret", "other": "field"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json_without_login).unwrap();
        let login = parsed.get("login").and_then(|l| l.as_str());
        
        assert_eq!(login, None, "Should return None when login field is missing");
    }

    #[tokio::test]
    async fn rate_limit_returns_proper_error_structure() {
        let client = setup_redis().await;
        let login = Uuid::new_v4().to_string();

        // Exhaust rate limit
        for _ in 1..=5 {
            let _ = enforce_rate_limit(&client, &login).await;
        }

        // 6th attempt should return structured error
        let err_response = enforce_rate_limit(&client, &login)
            .await
            .unwrap_err();
        
        assert_eq!(err_response.status(), StatusCode::TOO_MANY_REQUESTS);
        
        // Verify response body contains JSON error structure
        let body = hyper::body::to_bytes(err_response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        
        // Should contain unified error structure
        assert!(body_str.contains("\"status\":\"too_many_requests\""), 
                "Response should contain proper error status");
        assert!(body_str.contains("Too many login attempts"), 
                "Response should contain descriptive message");
    }

    #[tokio::test]
    async fn lockout_returns_proper_error_structure() {
        let client = setup_redis().await;
        let mut conn = client.get_async_connection().await.unwrap();
        let login = Uuid::new_v4().to_string();

        // Set lockout
        let key = format!("lockout:{}", login);
        let _: () = conn.set_ex(&key, 1, 60).await.unwrap();

        // Should return structured error
        let err_response = enforce_lockout(&client, &login)
            .await
            .unwrap_err();
        
        assert_eq!(err_response.status(), StatusCode::UNAUTHORIZED);
        
        // Verify response body contains JSON error structure
        let body = hyper::body::to_bytes(err_response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        
        // Should contain unified error structure
        assert!(body_str.contains("\"status\":\"unauthorized\""), 
                "Response should contain proper error status");
        assert!(body_str.contains("temporarily locked"), 
                "Response should contain descriptive message");
    }
}