//! Business logic for user logout.
//!
//! This module implements a secure token revocation flow that:
//! - Validates the token's format and signature (if possible)
//! - Adds the token to Redis blocklist to prevent reuse
//! - Provides detailed error handling for different failure scenarios
//! - Records comprehensive metrics and logging for auditing
//! - Unified error handling with automatic HTTP response conversion
//!
//! The logout flow is designed to be robust, handling various edge cases
//! including invalid tokens, already-logged-out users, and Redis unavailability.

use crate::{
    app::AppState,
    utils::{
        error_new::AuthServiceError, // ← Add unified error system
        jwt::{revoke_token, validate_token},
        metrics::AUTH_LOGOUTS,
    },
    log_info, log_warn,
};
use axum::{http::StatusCode, response::IntoResponse, Json}; // ← Add IntoResponse
use serde_json::json;

/// Processes the logout logic: validates and revokes the token, logs and increments metrics.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client for token revocation
/// * `token` - JWT token to be revoked
///
/// # Returns
///
/// Result that can be converted to HTTP response via unified error system
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
) -> Result<impl IntoResponse, AuthServiceError> { // ← Changed return type
    // Ensure Redis is available - automatic conversion via ? operator
    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis client not available for logout operation"))?;

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

    // Revoke the token by adding to blocklist - automatic conversion via ? operator
    revoke_token(token, redis_client).await?;

    // Log success and record metrics
    log_info!("Auth", "Token revoked successfully", "success");
    AUTH_LOGOUTS.with_label_values(&["success"]).inc();

    // Return success response using Axum's Json wrapper
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Logged out successfully"
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::{init_jwt_secret, state_no_redis, state_with_redis};

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        // Arrange
        let state = state_no_redis();
        
        // Act
        let result = process_logout(&state, "any-token").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a configuration error
        match result.err().unwrap() {
            AuthServiceError::Configuration(msg) => {
                assert!(msg.contains("Redis client"));
            }
            other => panic!("Expected configuration error, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn successful_logout_returns_success() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let token = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // Act
        let result = process_logout(&state, &token).await;
        
        // Assert
        assert!(result.is_ok());
        // Since we can't easily extract the JSON from impl IntoResponse in tests,
        // we just verify the result is Ok. In integration tests, we'd verify
        // the actual HTTP response structure.
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn invalid_token_proceeds_with_revocation() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let bad_token = "bad.token.signature";
        
        // Act
        let result = process_logout(&state, bad_token).await;
        
        // Assert - Invalid tokens should still attempt revocation
        // The result depends on whether the revocation succeeds or fails
        // This test verifies that we don't fail early on token validation
        match result {
            Ok(_) => {
                // Token revocation succeeded (token was added to blocklist)
            }
            Err(AuthServiceError::Jwt(_)) => {
                // JWT error during revocation process - acceptable
            }
            Err(AuthServiceError::Cache(_)) => {
                // Cache error during revocation process - acceptable
            }
            Err(other) => {
                panic!("Unexpected error type: {:?}", other);
            }
        }
    }
    
    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn double_logout_handles_gracefully() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let token = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // First logout
        let result1 = process_logout(&state, &token).await;
        assert!(result1.is_ok(), "First logout should succeed");
        
        // Act - Second logout with same token
        let result2 = process_logout(&state, &token).await;
        
        // Assert - Second logout behavior depends on implementation
        // It may succeed (idempotent) or fail (already revoked)
        match result2 {
            Ok(_) => {
                // Idempotent logout - acceptable behavior
            }
            Err(AuthServiceError::Jwt(_)) => {
                // JWT error due to revoked token - acceptable behavior
            }
            Err(AuthServiceError::Cache(_)) => {
                // Cache error during second revocation - acceptable behavior
            }
            Err(other) => {
                panic!("Unexpected error type for double logout: {:?}", other);
            }
        }
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn empty_token_returns_jwt_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Act
        let result = process_logout(&state, "").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a JWT error (empty token should fail validation/revocation)
        match result.err().unwrap() {
            AuthServiceError::Jwt(_) => {
                // Expected - empty token should cause JWT error
            }
            other => panic!("Expected JWT error for empty token, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn malformed_token_returns_jwt_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let malformed_token = "not.a.valid.jwt.format.at.all";
        
        // Act
        let result = process_logout(&state, malformed_token).await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a JWT error (malformed token should fail validation/revocation)
        match result.err().unwrap() {
            AuthServiceError::Jwt(_) => {
                // Expected - malformed token should cause JWT error
            }
            other => panic!("Expected JWT error for malformed token, got: {:?}", other),
        }
    }
}