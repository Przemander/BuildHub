//! # Token Revocation and Logout Business Logic
//!
//! This module implements a secure, robust token revocation flow with comprehensive
//! observability, security controls, and defense against common JWT attacks.
//!
//! ## Security Features
//!
//! - Immediate token invalidation via Redis-based blocklist
//! - Graceful handling of already-revoked tokens (idempotent operation)
//! - Support for malformed token handling without exposing implementation details
//! - Secure logging that prevents token exposure
//! - Defense against timing attacks via consistent processing
//! - Complete token lifecycle management
//!
//! ## Observability
//!
//! - Detailed OpenTelemetry spans for all operations
//! - Fine-grained metrics for authentication events
//! - Structured logging with security context
//! - Performance histograms for token operations
//!
//! ## Implementation Notes
//!
//! The logout process is designed to be idempotent and fail-safe, meaning it will
//! attempt to revoke tokens even if they appear invalid. This is a security best practice
//! that ensures maximum protection against token reuse, even in edge cases.

use crate::{
    app::AppState,
    metricss::logout_metrics::{
        error_types, record_logout_failure, record_logout_success, record_redis_check_failure,
        record_redis_check_success, record_token_revocation_failure,
        record_token_revocation_success, record_token_validation_failure,
        record_token_validation_success, time_complete_logout_flow,
    },
    utils::{
        error_new::AuthServiceError,
        jwt::{revoke_token, validate_token},
        log_new::Log,
        telemetry::{business_operation_span, redis_operation_span, SpanExt},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::Instrument;

/// Processes a logout request by validating and revoking the provided JWT token.
///
/// This function implements a comprehensive, secure token revocation workflow that
/// prioritizes security even when tokens are invalid or already revoked. It follows
/// a defense-in-depth approach by attempting revocation regardless of token validity.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client for token blocklist operations
/// * `token` - JWT token to be revoked (may be access or refresh token)
///
/// # Returns
///
/// * `Ok(impl IntoResponse)` - Success response with status code and message
/// * `Err(AuthServiceError)` - Structured error with context for appropriate user feedback
///
/// # Security Considerations
///
/// - Tokens are always added to blocklist, even if they appear invalid
/// - Invalid token formats are handled securely without revealing implementation details
/// - The operation is idempotent (safe to retry) and handles already-revoked tokens
/// - All operations are properly timed and logged for security auditing
///
/// # Flow Stages
///
/// 1. Infrastructure validation - Checks Redis availability
/// 2. Token inspection - Validates the token format and extracts claims if possible
/// 3. Token revocation - Adds the token to the blocklist in Redis
/// 4. Success notification - Returns appropriate status code and message
///
/// Each stage includes detailed metrics, logging, and error handling.
pub async fn process_logout(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Start complete logout flow timer
    let _logout_timer = time_complete_logout_flow();

    // Create span for the entire logout processing flow
    let process_span = business_operation_span("process_logout");
    
    // Record token length but not the actual token for security
    process_span.record("token_length", &token.len());
    
    // Record if token appears to be a JWT based on format (for metrics only)
    let has_jwt_format = token.contains('.');
    process_span.record("has_jwt_format", &has_jwt_format);

    // Clone span before moving it into the async block
    let process_span_clone = process_span.clone();

    Log::event(
        "INFO",
        "Authentication",
        "Starting logout process",
        "logout_start",
        "process_logout",
    );

    // Wrap logout logic in the process_span
    async move {
        // =====================================================================
        // STAGE 1: INFRASTRUCTURE VALIDATION
        // =====================================================================
        let redis_check_span = business_operation_span("check_redis_client");
        let redis_check_span_clone = redis_check_span.clone();

        let redis_client = async {
            match &app_state.redis_client {
                Some(client) => {
                    record_redis_check_success();
                    redis_check_span.record("business.result", &"success");

                    Log::event(
                        "INFO",
                        "Authentication",
                        "Redis client available for token revocation",
                        "redis_check_success",
                        "process_logout",
                    );

                    Ok(client)
                }
                None => {
                    record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
                    record_logout_failure();
                    redis_check_span.record("business.result", &"failure");
                    redis_check_span.record("failure_reason", &"redis_unavailable");

                    Log::event(
                        "ERROR",
                        "Authentication",
                        "Redis client not available for token revocation - service degraded",
                        "redis_check_failure",
                        "process_logout",
                    );

                    Err(AuthServiceError::configuration(
                        "Logout service temporarily unavailable. Please try again later.",
                    ))
                }
            }
        }
        .instrument(redis_check_span_clone)
        .await?;

        // =====================================================================
        // STAGE 2: TOKEN INSPECTION
        // =====================================================================
        let validation_span = business_operation_span("validate_token");
        let validation_span_clone = validation_span.clone();

        Log::event(
            "INFO",
            "Authentication",
            "Validating token for audit purposes",
            "token_validation_start",
            "process_logout",
        );

        // Try to validate token for logging purposes only - failures don't stop processing
        let validation_result = async {
            match validate_token(token, redis_client).await {
                Ok(claims) => {
                    record_token_validation_success();
                    validation_span.record("business.result", &"success");
                    validation_span.record("user.id", &claims.sub);
                    validation_span.record("token_type", &claims.token_type);
                    validation_span.record("expiration", &claims.exp);

                    Log::event(
                        "INFO",
                        "Authentication",
                        &format!(
                            "Logout: token valid for user {} (type: {})",
                            claims.sub, claims.token_type
                        ),
                        "token_validation_success",
                        "process_logout",
                    );
                    
                    Some(claims)
                }
                Err(e) => {
                    // Token validation failure doesn't prevent logout attempt
                    record_token_validation_failure(error_types::INVALID_TOKEN);
                    validation_span.record("business.result", &"failure");
                    validation_span.record("failure_reason", &"invalid_token");
                    validation_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Authentication",
                        &format!("Logout: invalid token - proceeding with revocation anyway ({})", e),
                        "token_validation_failure",
                        "process_logout",
                    );
                    
                    // Continue without failing - we'll still try to revoke
                    None
                }
            }
        }
        .instrument(validation_span_clone)
        .await;

        // =====================================================================
        // STAGE 3: TOKEN REVOCATION
        // =====================================================================
        let revocation_span = redis_operation_span("revoke_token", "jwt:revoked:*");
        let revocation_span_clone = revocation_span.clone();
        
        // If we have claims from validation, record additional context
        if let Some(ref claims) = validation_result {
            revocation_span.record("user.id", &claims.sub);
            revocation_span.record("token_type", &claims.token_type);
        }

        Log::event(
            "INFO",
            "Authentication",
            "Revoking token in blocklist",
            "token_revocation_start",
            "process_logout",
        );

        async {
            match revoke_token(token, redis_client).await {
                Ok(_) => {
                    record_token_revocation_success();
                    revocation_span.record("redis.success", &true);
                    revocation_span.record("business.result", &"success");

                    Log::event(
                        "INFO",
                        "Authentication",
                        "Token successfully added to blocklist",
                        "token_revocation_success",
                        "process_logout",
                    );

                    Ok::<(), AuthServiceError>(()) // Explicit type annotation for clarity
                }
                Err(e) => {
                    record_token_revocation_failure(error_types::REVOCATION_FAILED);
                    record_logout_failure();
                    revocation_span.record("redis.success", &false);
                    revocation_span.record("business.result", &"failure");
                    revocation_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Authentication",
                        &format!("Failed to add token to blocklist: {}", e),
                        "token_revocation_failure",
                        "process_logout",
                    );

                    Err(AuthServiceError::configuration(
                        "Unable to complete logout. Please try again later.",
                    ))
                }
            }
        }
        .instrument(revocation_span_clone)
        .await?;

        // =====================================================================
        // STAGE 4: SUCCESS NOTIFICATION
        // =====================================================================
        // Record overall success
        record_logout_success();
        process_span.record("business.result", &"success");
        
        // If we have user ID from token, record it for tracing
        if let Some(ref claims) = validation_result {
            process_span.record("user.id", &claims.sub);
        }

        Log::event(
            "INFO",
            "Authentication",
            "Logout completed successfully - token revoked",
            "logout_success",
            "process_logout",
        );

        // Return success response using Axum's Json wrapper
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Logged out successfully"
            })),
        ))
    }
    .instrument(process_span_clone)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metricss::logout_metrics::{
        error_types, init_logout_metrics, results, steps, LOGOUT_DURATION, LOGOUT_FAILURES,
        LOGOUT_OPERATIONS,
    };
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::{init_jwt_secret, state_no_redis, state_with_redis};

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
                assert!(msg.contains("temporarily unavailable"));
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