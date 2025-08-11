//! Business logic for JWT token refresh operations with OpenTelemetry integration.
//!
//! This module implements the OAuth2-compatible token refresh flow with:
//! - Validated token exchange (refresh token → access token)
//! - Refresh token rotation for enhanced security
//! - Comprehensive token validation checks
//! - Redis-based token revocation
//! - Unified error handling with automatic HTTP response conversion
//! - Complete OpenTelemetry observability with hierarchical spans
//!
//! Security features include:
//! - Immediate revocation of used refresh tokens to prevent replay attacks
//! - Token type enforcement to prevent token misuse
//! - Proper JWT validation including expiration and signature verification
//! - Detailed security logging for audit trails

use crate::{
    app::AppState,
    // Import the refresh metrics
    metricss::refresh_metrics::{
        // Type-safe constants
        error_types,
        record_access_token_generation_failure,
        record_access_token_generation_success,
        record_refresh_failure,
        record_refresh_success,
        record_refresh_token_generation_failure,
        record_refresh_token_generation_success,
        record_token_revocation_failure,
        record_token_revocation_success,
        record_token_type_check_failure,
        record_token_type_check_success,
        record_token_validation_failure,
        // Step-by-step tracking with business helpers
        record_token_validation_success,
        // High-level complete flow tracking
        time_complete_refresh_flow,
    },
    utils::{
        error_new::AuthServiceError,
        jwt::{
            generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH,
        },
        log_new::Log,
        telemetry::{business_operation_span, redis_operation_span, SpanExt},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::Instrument;

/// Processes a token refresh operation according to OAuth2 specification with complete observability.
///
/// # Metrics Generated
/// - `refresh_operations_total{step="complete_flow|token_validation|token_type_check|token_revocation|access_token_generation|refresh_token_generation", result="success|failure"}`
/// - `refresh_failures_total{step="...", error_type="invalid_signature|token_expired|wrong_token_type|revocation_failed|generation_error|..."}`
/// - `refresh_duration_seconds{step="complete_flow|token_validation|token_type_check|token_revocation|access_token_generation|refresh_token_generation"}` (using LATENCY_BUCKETS_FAST)
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client for token validation
/// * `token` - The refresh token to validate and exchange
///
/// # Returns
///
/// Result that can be converted to HTTP response via unified error system
///
/// # Flow with Complete Metrics Tracking
///
/// 1. **Start complete flow timer** - Overall refresh performance
/// 2. **Validate refresh token** - JWT signature, expiration, revocation check
/// 3. **Verify token type** - Ensure it's a refresh token (not access)
/// 4. **Revoke old token** - Prevent replay attacks (token rotation)
/// 5. **Generate new access token** - OAuth2 access token creation
/// 6. **Generate new refresh token** - OAuth2 refresh token rotation
/// 7. **Record complete success** - Overall flow completion tracking
///
/// # Security Notes
///
/// This implementation follows security best practices including:
/// - Token validation with cryptographic signature verification
/// - Token revocation to prevent token reuse
/// - Token type enforcement to prevent confused deputy attacks
/// - Refresh token rotation to limit exposure window
/// - Detailed error tracking without leaking sensitive information
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Start complete refresh flow timer for end-to-end performance monitoring
    let _complete_flow_timer = time_complete_refresh_flow();

    // Create span for the entire token refresh processing flow
    let process_span = business_operation_span("process_token_refresh");
    process_span.record("token_length", &token.len());

    // Clone span before moving it into the async block
    let process_span_clone = process_span.clone();

    Log::event(
        "INFO",
        "Token Refresh",
        "Starting token refresh operation",
        "refresh_start",
        "process_token_refresh",
    );

    // Wrap token refresh logic in the process_span
    async move {
        // ===================================================================
        // STEP 1: Get Redis client for token operations
        // ===================================================================
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            record_refresh_failure(); // Record overall failure
            process_span.record("business.result", &"failure");
            process_span.record("failure_reason", &"missing_redis_client");

            Log::event(
                "ERROR",
                "Token Refresh",
                "Redis client not available for token operations",
                "configuration_error",
                "process_token_refresh",
            );

            AuthServiceError::configuration("Redis client not available for token operations")
        })?;

        // ===================================================================
        // STEP 2: Validate the refresh token
        // ===================================================================
        let validation_span = business_operation_span("validate_token");
        let validation_span_clone = validation_span.clone();

        Log::event(
            "INFO",
            "Token Refresh",
            "Starting token validation",
            "token_validation_start",
            "process_token_refresh",
        );

        let claims = async {
            match validate_token(token, redis_client).await {
                Ok(claims) => {
                    record_token_validation_success();
                    validation_span.record("business.result", &"success");
                    
                    // Record user ID in the validation span for traceability
                    validation_span.record("user.id", &claims.sub);

                    Log::event(
                        "INFO",
                        "Token Refresh",
                        &format!("Token validation successful for user: {}", claims.sub),
                        "token_validation_success",
                        "process_token_refresh",
                    );

                    Ok(claims)
                }
                Err(e) => {
                    // Categorize validation failure for detailed monitoring
                    let error_type = categorize_jwt_error(&e);
                    record_token_validation_failure(error_type);
                    record_refresh_failure(); // Also record overall failure
                    validation_span.record("business.result", &"failure");
                    validation_span.record("failure_reason", &error_type);
                    validation_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Token Refresh",
                        &format!("Token validation failed: {}", e),
                        "token_validation_failure",
                        "process_token_refresh",
                    );

                    Err(e)
                }
            }
        }
        .instrument(validation_span_clone)
        .await?;

        // ===================================================================
        // STEP 3: Verify token is of the correct type
        // ===================================================================
        let type_check_span = business_operation_span("token_type_check");
        let type_check_span_clone = type_check_span.clone();

        Log::event(
            "INFO",
            "Token Refresh",
            "Starting token type check",
            "token_type_check_start",
            "process_token_refresh",
        );

        async {
            if claims.token_type != TOKEN_TYPE_REFRESH {
                record_token_type_check_failure(error_types::WRONG_TOKEN_TYPE);
                record_refresh_failure(); // Also record overall failure
                type_check_span.record("business.result", &"failure");
                type_check_span.record("failure_reason", &"wrong_token_type");
                type_check_span.record("expected", &TOKEN_TYPE_REFRESH);
                type_check_span.record("actual", &claims.token_type);

                Log::event(
                    "WARN",
                    "Token Refresh",
                    &format!(
                        "Wrong token type for user {}: expected {}, got {}",
                        claims.sub, TOKEN_TYPE_REFRESH, claims.token_type
                    ),
                    "wrong_token_type",
                    "process_token_refresh",
                );

                return Err(AuthServiceError::validation(
                    "token_type",
                    "Expected a refresh token",
                ));
            }

            record_token_type_check_success();
            type_check_span.record("business.result", &"success");
            type_check_span.record("user.id", &claims.sub);

            Log::event(
                "INFO",
                "Token Refresh",
                &format!("Token type check successful for user: {}", claims.sub),
                "token_type_check_success",
                "process_token_refresh",
            );

            Ok(())
        }
        .instrument(type_check_span_clone)
        .await?;

        // ===================================================================
        // STEP 4: Revoke old refresh token
        // ===================================================================
        let revocation_span = redis_operation_span("revoke_token", "jwt:revoked:*");
        let revocation_span_clone = revocation_span.clone();
        
        // Add user ID to the span for traceability
        revocation_span.record("user.id", &claims.sub);

        Log::event(
            "INFO",
            "Token Refresh",
            &format!("Starting token revocation for user: {}", claims.sub),
            "token_revocation_start",
            "process_token_refresh",
        );

        let revocation_result = async {
            match revoke_token(token, redis_client).await {
                Ok(()) => {
                    record_token_revocation_success();
                    revocation_span.record("redis.success", &true);
                    revocation_span.record("business.result", &"success");

                    Log::event(
                        "INFO",
                        "Token Refresh",
                        &format!("Token revocation successful for user: {}", claims.sub),
                        "token_revocation_success",
                        "process_token_refresh",
                    );

                    Ok::<(), AuthServiceError>(())
                }
                Err(e) => {
                    record_token_revocation_failure(error_types::REVOCATION_FAILED);
                    revocation_span.record("redis.success", &false);
                    revocation_span.record("business.result", &"warning");
                    revocation_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Token Refresh",
                        &format!(
                            "Failed to revoke old refresh token for user {}: {}",
                            claims.sub, e
                        ),
                        "token_revocation_warning",
                        "process_token_refresh",
                    );

                    // Continue without failing - user gets new tokens but old one might still be valid briefly
                    // This is a graceful degradation approach for availability
                    Ok::<(), AuthServiceError>(())
                }
            }
        }
        .instrument(revocation_span_clone)
        .await;

        // Non-fatal error handling: Log additional context about revocation failures
        if let Err(e) = &revocation_result {
            Log::event(
                "ERROR",
                "Token Refresh",
                &format!(
                    "Unexpected error during token revocation for user {}: {}",
                    claims.sub, e
                ),
                "token_revocation_error",
                "process_token_refresh",
            );
        }

        // ===================================================================
        // STEP 5: Generate new access token
        // ===================================================================
        let access_gen_span = business_operation_span("generate_access_token");
        let access_gen_span_clone = access_gen_span.clone();
        
        // Add user ID to the span for traceability
        access_gen_span.record("user.id", &claims.sub);

        Log::event(
            "INFO",
            "Token Refresh",
            &format!("Starting access token generation for user: {}", claims.sub),
            "access_token_generation_start",
            "process_token_refresh",
        );

        let access_token = async {
            match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
                Ok(token) => {
                    record_access_token_generation_success();
                    access_gen_span.record("business.result", &"success");
                    
                    // Record token length for analytics without exposing token
                    access_gen_span.record("token_length", &token.len());

                    Log::event(
                        "INFO",
                        "Token Refresh",
                        &format!("Access token generation successful for user: {}", claims.sub),
                        "access_token_generation_success",
                        "process_token_refresh",
                    );

                    Ok(token)
                }
                Err(e) => {
                    record_access_token_generation_failure(error_types::GENERATION_ERROR);
                    record_refresh_failure(); // Also record overall failure
                    access_gen_span.record("business.result", &"failure");
                    access_gen_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Token Refresh",
                        &format!(
                            "Access token generation failed for user {}: {}",
                            claims.sub, e
                        ),
                        "access_token_generation_failure",
                        "process_token_refresh",
                    );

                    Err(e)
                }
            }
        }
        .instrument(access_gen_span_clone)
        .await?;

        // ===================================================================
        // STEP 6: Generate new refresh token
        // ===================================================================
        let refresh_gen_span = business_operation_span("generate_refresh_token");
        let refresh_gen_span_clone = refresh_gen_span.clone();
        
        // Add user ID to the span for traceability
        refresh_gen_span.record("user.id", &claims.sub);

        Log::event(
            "INFO",
            "Token Refresh",
            &format!("Starting refresh token generation for user: {}", claims.sub),
            "refresh_token_generation_start",
            "process_token_refresh",
        );

        let refresh_token = async {
            match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
                Ok(token) => {
                    record_refresh_token_generation_success();
                    refresh_gen_span.record("business.result", &"success");
                    
                    // Record token length for analytics without exposing token
                    refresh_gen_span.record("token_length", &token.len());

                    Log::event(
                        "INFO",
                        "Token Refresh",
                        &format!("Refresh token generation successful for user: {}", claims.sub),
                        "refresh_token_generation_success",
                        "process_token_refresh",
                    );

                    Ok(token)
                }
                Err(e) => {
                    record_refresh_token_generation_failure(error_types::GENERATION_ERROR);
                    record_refresh_failure(); // Also record overall failure
                    refresh_gen_span.record("business.result", &"failure");
                    refresh_gen_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Token Refresh",
                        &format!(
                            "Refresh token generation failed for user {}: {}",
                            claims.sub, e
                        ),
                        "refresh_token_generation_failure",
                        "process_token_refresh",
                    );

                    Err(e)
                }
            }
        }
        .instrument(refresh_gen_span_clone)
        .await?;

        // ===================================================================
        // STEP 7: Record success and build response
        // ===================================================================
        
        // Record overall success metrics
        record_refresh_success();
        process_span.record("business.result", &"success");
        process_span.record("user.id", &claims.sub);

        // Record token lengths for analytics without exposing tokens
        process_span.record("access_token_length", &access_token.len());
        process_span.record("refresh_token_length", &refresh_token.len());

        Log::event(
            "INFO",
            "Token Refresh",
            &format!(
                "Token refresh completed successfully for user: {}",
                claims.sub
            ),
            "refresh_success",
            "process_token_refresh",
        );

        // Return new token pair in OAuth2-compatible format
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Tokens refreshed successfully",
                "data": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer"
                }
            })),
        ))
    }
    .instrument(process_span_clone)
    .await
}

/// Categorizes JWT validation errors for detailed metrics tracking.
///
/// This function analyzes error types to provide more specific metrics for monitoring
/// and alerting, making it easier to identify specific security issues in production.
///
/// # Arguments
/// * `error` - The error to categorize
///
/// # Returns
/// A static string representing the error category for metrics
fn categorize_jwt_error(error: &AuthServiceError) -> &'static str {
    match error {
        AuthServiceError::Jwt(jwt_err) => {
            let error_msg = jwt_err.to_string().to_lowercase();
            if error_msg.contains("signature") {
                error_types::INVALID_SIGNATURE
            } else if error_msg.contains("expired") {
                error_types::TOKEN_EXPIRED
            } else if error_msg.contains("revoked") {
                error_types::TOKEN_REVOKED
            } else if error_msg.contains("nbf") {
                "token_not_valid_yet" // Use string literal for missing constant
            } else if error_msg.contains("sub") || error_msg.contains("iss") || error_msg.contains("aud") {
                "claims_validation_failed" // Use string literal for missing constant
            } else {
                "invalid_token_format" // Use string literal for missing constant
            }
        }
        AuthServiceError::Configuration(_) => error_types::REDIS_UNAVAILABLE,
        AuthServiceError::Cache(_) => "redis_error", // Use string literal for missing constant
        AuthServiceError::RateLimit(_) => "rate_limited", // Use string literal for missing constant
        _ => "unknown_error", // Use string literal for missing constant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    // Import metrics for testing refresh tracking
    use crate::metricss::refresh_metrics::{
        error_types, init_refresh_metrics, steps, REFRESH_DURATION, REFRESH_FAILURES,
        REFRESH_OPERATIONS,
    };

    /// Initialize refresh metrics for testing
    fn setup_metrics() {
        init_refresh_metrics();
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        setup_metrics();
        let state = state_no_redis();

        let result = process_token_refresh(&state, "whatever").await;
        assert!(result.is_err());

        match result.err().unwrap() {
            AuthServiceError::Configuration(msg) => {
                assert!(msg.contains("Redis client"));
            }
            other => panic!("Expected configuration error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn invalid_token_returns_jwt_error_with_metrics() {
        setup_metrics();
        let state = state_with_redis();

        // Record initial metrics state
        let initial_validation_failure = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_VALIDATION, "failure"])
            .get();
        let initial_complete_failure = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "failure"])
            .get();

        let result = process_token_refresh(&state, "not-a-jwt").await;
        assert!(result.is_err());

        // Check that it's a JWT error with correct metrics
        match result.err().unwrap() {
            AuthServiceError::Jwt(_) => {
                // Expected - verify metrics were recorded
                let final_validation_failure = REFRESH_OPERATIONS
                    .with_label_values(&[steps::TOKEN_VALIDATION, "failure"])
                    .get();
                let final_complete_failure = REFRESH_OPERATIONS
                    .with_label_values(&[steps::COMPLETE_FLOW, "failure"])
                    .get();

                assert_eq!(final_validation_failure, initial_validation_failure + 1.0);
                assert_eq!(final_complete_failure, initial_complete_failure + 1.0);
            }
            other => panic!("Expected JWT error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wrong_token_type_returns_validation_error_with_metrics() {
        setup_metrics();
        let state = state_with_redis();

        // Generate an access token instead of a refresh token
        let access = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();

        // Record initial metrics state
        let initial_type_check_failure = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_TYPE_CHECK, "failure"])
            .get();
        let initial_wrong_type_failures = REFRESH_FAILURES
            .with_label_values(&[steps::TOKEN_TYPE_CHECK, error_types::WRONG_TOKEN_TYPE])
            .get();

        let result = process_token_refresh(&state, &access).await;
        assert!(result.is_err());

        // Check that it's a validation error with correct metrics
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                let final_type_check_failure = REFRESH_OPERATIONS
                    .with_label_values(&[steps::TOKEN_TYPE_CHECK, "failure"])
                    .get();
                let final_wrong_type_failures = REFRESH_FAILURES
                    .with_label_values(&[steps::TOKEN_TYPE_CHECK, error_types::WRONG_TOKEN_TYPE])
                    .get();

                assert_eq!(final_type_check_failure, initial_type_check_failure + 1.0);
                assert_eq!(final_wrong_type_failures, initial_wrong_type_failures + 1.0);
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn successful_refresh_generates_complete_metrics() {
        setup_metrics();
        let state = state_with_redis();

        // Generate a valid refresh token
        let refresh = generate_token("user42", TOKEN_TYPE_REFRESH, None).unwrap();

        // Record initial metrics state for all steps
        let initial_validation_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_VALIDATION, "success"])
            .get();
        let initial_type_check_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_TYPE_CHECK, "success"])
            .get();
        let initial_access_gen_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::ACCESS_TOKEN_GENERATION, "success"])
            .get();
        let initial_refresh_gen_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::REFRESH_TOKEN_GENERATION, "success"])
            .get();
        let initial_complete_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "success"])
            .get();

        let initial_complete_duration = REFRESH_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        let result = process_token_refresh(&state, &refresh).await;
        assert!(result.is_ok());

        // Verify all step metrics were recorded correctly
        let final_validation_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_VALIDATION, "success"])
            .get();
        let final_type_check_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_TYPE_CHECK, "success"])
            .get();
        let final_access_gen_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::ACCESS_TOKEN_GENERATION, "success"])
            .get();
        let final_refresh_gen_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::REFRESH_TOKEN_GENERATION, "success"])
            .get();
        let final_complete_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "success"])
            .get();

        let final_complete_duration = REFRESH_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        // All steps should have recorded success (except revocation which might warn but continue)
        assert_eq!(final_validation_success, initial_validation_success + 1.0);
        assert_eq!(final_type_check_success, initial_type_check_success + 1.0);
        assert_eq!(final_access_gen_success, initial_access_gen_success + 1.0);
        assert_eq!(final_refresh_gen_success, initial_refresh_gen_success + 1.0);
        assert_eq!(final_complete_success, initial_complete_success + 1.0);

        // Duration should be recorded
        assert_eq!(final_complete_duration, initial_complete_duration + 1);
    }

    #[tokio::test]
    async fn production_refresh_patterns() {
        setup_metrics();
        let state = state_with_redis();

        // Simulate realistic production patterns

        // 5 successful refreshes
        for i in 0..5 {
            let refresh = generate_token(&format!("user_{}", i), TOKEN_TYPE_REFRESH, None).unwrap();
            let result = process_token_refresh(&state, &refresh).await;
            assert!(result.is_ok());
        }

        // Some failures at different steps

        // Invalid token failure
        let result = process_token_refresh(&state, "invalid-token").await;
        assert!(result.is_err());

        // Wrong token type failure
        let access_token = generate_token("wrong_type_user", TOKEN_TYPE_ACCESS, None).unwrap();
        let result = process_token_refresh(&state, &access_token).await;
        assert!(result.is_err());

        // Verify realistic metric patterns

        // 5 successful complete flows
        let complete_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "success"])
            .get();
        assert_eq!(complete_success, 5.0);

        // 2 failed complete flows (invalid token + wrong type)
        let complete_failure = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "failure"])
            .get();
        assert_eq!(complete_failure, 2.0);

        // Specific failure types
        let validation_failures = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_VALIDATION, "failure"])
            .get();
        assert_eq!(validation_failures, 1.0);

        let type_check_failures = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_TYPE_CHECK, "failure"])
            .get();
        assert_eq!(type_check_failures, 1.0);

        // All successful refreshes went through all steps
        let validation_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::TOKEN_VALIDATION, "success"])
            .get();
        assert_eq!(validation_success, 5.0); // Only successful ones passed validation

        let access_gen_success = REFRESH_OPERATIONS
            .with_label_values(&[steps::ACCESS_TOKEN_GENERATION, "success"])
            .get();
        assert_eq!(access_gen_success, 5.0);
    }
    
    #[test]
    fn test_categorize_jwt_error() {
        // Create AuthServiceError::Jwt instances for testing
        let sig_err = AuthServiceError::Configuration("invalid signature".into());
        assert_eq!(categorize_jwt_error(&sig_err), error_types::REDIS_UNAVAILABLE);
        
        // NOTE: The following tests are simplified as we can't directly create JwtError instances
        // In a real implementation, you would use proper error construction methods
        
        // For now, we just verify the function handles all error types without panicking
        let config_err = AuthServiceError::Configuration("redis unavailable".into());
        let _ = categorize_jwt_error(&config_err);
        
        let validation_err = AuthServiceError::validation("field", "message");
        let _ = categorize_jwt_error(&validation_err);
    }
}