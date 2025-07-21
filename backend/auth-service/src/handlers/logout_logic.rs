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
    },
    log_info, log_warn,
    // Import logout metrics
    metricss::logout_metrics::{
        time_complete_logout_flow, record_logout_success, record_logout_failure,
        record_redis_check_success, record_redis_check_failure,
        record_token_validation_success, record_token_validation_failure,
        record_token_revocation_success, record_token_revocation_failure,
        error_types,
    },
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
    // Start complete logout flow timer
    let _logout_timer = time_complete_logout_flow();

    log_info!(
        "Auth", 
        "Starting logout process", 
        "logout_start"
    );

    // Step 1: Check Redis availability with metrics
    let redis_client = match &app_state.redis_client {
        Some(client) => {
            record_redis_check_success();
            client
        }
        None => {
            record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
            record_logout_failure();
            return Err(AuthServiceError::configuration("Redis client not available for logout operation"));
        }
    };

    // Step 2: Try to validate token (for logging) with metrics
    match validate_token(token, redis_client).await {
        Ok(claims) => {
            record_token_validation_success();
            log_info!("Auth", &format!("Logout: token valid for user {}", claims.sub), "success");
        }
        Err(e) => {
            // Token validation failure doesn't prevent logout attempt
            record_token_validation_failure(error_types::INVALID_TOKEN);
            log_warn!("Auth", &format!("Logout: invalid token ({})", e), "invalid_token");
        }
    }

    // Step 3: Revoke the token by adding to blocklist with metrics
    match revoke_token(token, redis_client).await {
        Ok(_) => {
            record_token_revocation_success();
            log_info!("Auth", "Token revoked successfully", "token_revoked");
        }
        Err(e) => {
            record_token_revocation_failure(error_types::REVOCATION_FAILED);
            record_logout_failure();
            return Err(e);
        }
    }

    // Record overall success
    record_logout_success();

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
    use crate::metricss::logout_metrics::{
        init_logout_metrics, LOGOUT_OPERATIONS, LOGOUT_FAILURES, LOGOUT_DURATION,
        steps, results, error_types
    };

    /// Initialize logout metrics for testing
    fn setup_metrics() {
        init_logout_metrics();
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        setup_metrics();
        // Arrange
        let state = state_no_redis();
        
        let initial_redis_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
            .get();
        let initial_logout_failure = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

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

        let final_redis_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
            .get();
        let final_logout_failure = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_redis_failure, initial_redis_failure + 1.0);
        assert_eq!(final_logout_failure, initial_logout_failure + 1.0);
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn successful_logout_returns_success() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let token = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        let initial_logout_success = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let initial_duration = LOGOUT_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        // Act
        let result = process_logout(&state, &token).await;
        
        // Assert
        assert!(result.is_ok());

        let final_logout_success = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let final_duration = LOGOUT_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        assert_eq!(final_logout_success, initial_logout_success + 1.0);
        assert_eq!(final_duration, initial_duration + 1);
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn invalid_token_proceeds_with_revocation() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let bad_token = "bad.token.signature";
        
        let initial_validation_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
            .get();

        // Act
        let result = process_logout(&state, bad_token).await;
        
        // Assert - Invalid tokens should still attempt revocation
        // The result depends on whether the revocation succeeds or fails
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

        let final_validation_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
            .get();
        
        assert_eq!(final_validation_failure, initial_validation_failure + 1.0);
    }
    
    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn double_logout_handles_gracefully() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let token = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        let initial_logout_success = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

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

        let final_logout_success = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        // At least the first logout succeeded
        assert!(final_logout_success >= initial_logout_success + 1.0);
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn empty_token_returns_jwt_error() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        let initial_validation_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
            .get();

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

        let final_validation_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
            .get();

        assert_eq!(final_validation_failure, initial_validation_failure + 1.0);
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn malformed_token_returns_jwt_error() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let malformed_token = "not.a.valid.jwt.format.at.all";
        
        let initial_validation_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
            .get();

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

        let final_validation_failure = LOGOUT_FAILURES
            .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
            .get();

        assert_eq!(final_validation_failure, initial_validation_failure + 1.0);
    }
}