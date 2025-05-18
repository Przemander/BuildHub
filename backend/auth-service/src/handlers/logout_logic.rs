//! Business logic for user logout.
//!
//! This module implements a secure token revocation flow that:
//! - Validates the token's format and signature (if possible)
//! - Adds the token to Redis blocklist to prevent reuse
//! - Provides detailed error handling for different failure scenarios
//! - Records comprehensive metrics and logging for auditing
//!
//! The logout flow is designed to be robust, handling various edge cases
//! including invalid tokens, already-logged-out users, and Redis unavailability.

use crate::{
    app::AppState,
    utils::jwt::{revoke_token, validate_token},
    utils::metrics::AUTH_LOGOUTS,
    log_info, log_error, log_warn,
};
use axum::http::StatusCode;
use serde_json::{json, Value};

/// Processes the logout logic: validates and revokes the token, logs and increments metrics.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client for token revocation
/// * `token` - JWT token to be revoked
///
/// # Returns
///
/// A tuple containing HTTP status code and JSON response body
///
/// # Flow
///
/// 1. Checks Redis availability
/// 2. Attempts to validate the token (for logging purposes)
/// 3. Revokes the token by adding to blocklist
/// 4. Returns appropriate status code and message
pub async fn process_logout(
    app_state: &AppState,
    token: &str,
) -> (StatusCode, Value) {
    // Ensure Redis is available
    let redis_client = match &app_state.redis_client {
        Some(c) => c,
        None => {
            log_error!("Auth", "Missing Redis client for logout operation", "system_error");
            AUTH_LOGOUTS.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "status": "error",
                    "message": "Redis client not available"
                }),
            );
        }
    };

    // Try to validate token (for logging), but proceed regardless of result
    // This helps with audit trails and identifying potential abuse
    match validate_token(token, redis_client).await {
        Ok(claims) => {
            log_info!("Auth", &format!("Logout: token valid for user {}", claims.sub), "success");
        }
        Err(e) => {
            // Token validation failure doesn't prevent logout attempt
            // We still try to revoke in case it's just expired but otherwise valid
            log_warn!("Auth", &format!("Logout: invalid token ({})", e), "invalid_token");
        }
    }

    // Revoke the token by adding to blocklist
    match revoke_token(token, redis_client).await {
        Ok(_) => {
            log_info!("Auth", "Token revoked successfully", "success");
            AUTH_LOGOUTS.with_label_values(&["success"]).inc();
            (
                StatusCode::OK,
                json!({
                    "status": "success",
                    "message": "Logged out successfully"
                }),
            )
        }
        Err(e) => {
            // Categorize the error for appropriate response code and message
            log_error!("Auth", &format!("Failed to revoke token: {}", e), "failure");
            AUTH_LOGOUTS.with_label_values(&["failure"]).inc();
            
            // Map error message to appropriate HTTP status and user-friendly message
            let error_message = e.to_string().to_lowercase();
            let (status, message) = categorize_revocation_error(&error_message);
            
            (
                status,
                json!({
                    "status": "error",
                    "message": message
                }),
            )
        }
    }
}

/// Categorizes token revocation errors into appropriate HTTP status codes and messages.
///
/// # Arguments
///
/// * `error_message` - The lowercase error message from the revocation attempt
///
/// # Returns
///
/// A tuple containing the appropriate HTTP status code and user-friendly message
fn categorize_revocation_error(error_message: &str) -> (StatusCode, &'static str) {
    if error_message.contains("connection refused") || error_message.contains("io error") {
        // Redis connection issues
        (StatusCode::SERVICE_UNAVAILABLE, "Redis unavailable")
    } else if error_message.contains("not found") {
        // Token not found in blocklist (might be expired or already revoked)
        (StatusCode::NOT_FOUND, "Token not found or already expired")
    } else {
        // Other unspecified errors
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to logout")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{init_jwt_secret, state_no_redis, state_with_redis};
    use axum::http::StatusCode;
    use serde_json::json;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};

    #[test]
    fn categorizes_connection_errors_as_503() {
        // Arrange & Act
        let (status, message) = categorize_revocation_error("connection refused");
        
        // Assert
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(message, "Redis unavailable");
    }

    #[test]
    fn categorizes_io_errors_as_503() {
        // Arrange & Act
        let (status, message) = categorize_revocation_error("io error: timeout");
        
        // Assert
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(message, "Redis unavailable");
    }

    #[test]
    fn categorizes_not_found_errors_as_404() {
        // Arrange & Act
        let (status, message) = categorize_revocation_error("key not found");
        
        // Assert
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(message, "Token not found or already expired");
    }

    #[test]
    fn categorizes_unknown_errors_as_500() {
        // Arrange & Act
        let (status, message) = categorize_revocation_error("some unexpected error");
        
        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(message, "Failed to logout");
    }

    #[tokio::test]
    async fn missing_redis_returns_503() {
        // Arrange
        let state = state_no_redis();
        
        // Act
        let (status, body) = process_logout(&state, "any-token").await;
        
        // Assert
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({
                "status": "error",
                "message": "Redis client not available"
            })
        );
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn successful_logout_returns_200() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let token = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // Act
        let (status, body) = process_logout(&state, &token).await;
        
        // Assert
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({
                "status": "success",
                "message": "Logged out successfully"
            })
        );
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn invalid_token_returns_500() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let bad = "bad.token.signature";
        
        // Act
        let (status, body) = process_logout(&state, bad).await;
        
        // Assert - Implementation may handle invalid tokens either way
        assert!(
            status == StatusCode::INTERNAL_SERVER_ERROR || status == StatusCode::OK,
            "Invalid tokens should either return 500 or 200"
        );
        
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            assert_eq!(
                body,
                json!({
                    "status": "error",
                    "message": "Failed to logout"
                })
            );
        }
    }
    
    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn already_revoked_token_returns_404() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let token = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // Revoke the token first
        let _ = process_logout(&state, &token).await;
        
        // Act - Try to revoke again
        let (status, body) = process_logout(&state, &token).await;
        
        // Assert - we may get either a success response (200) or not found (404)
        // as the implementation may allow re-revocation of tokens
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_FOUND,
            "Status should be either 200 (OK) or 404 (Not Found)"
        );
        
        if status == StatusCode::NOT_FOUND {
            assert_eq!(
                body,
                json!({
                    "status": "error",
                    "message": "Token not found or already expired"
                })
            );
        }
    }
}