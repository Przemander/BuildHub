//! Business logic for JWT token refresh operations.
//!
//! This module implements the OAuth2-compatible token refresh flow with:
//! - Validated token exchange (refresh token → access token)
//! - Refresh token rotation for enhanced security
//! - Comprehensive token validation checks
//! - Redis-based token revocation
//! - Unified error handling with automatic HTTP response conversion
//! - **Full observability through comprehensive refresh metrics**
//!
//! Security features include:
//! - Immediate revocation of used refresh tokens to prevent replay attacks
//! - Token type enforcement to prevent token misuse
//! - Proper JWT validation including expiration and signature verification

use crate::{
    app::AppState,
    log_info, log_warn,
    utils::{
        error_new::AuthServiceError,
        jwt::{
            generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH,
        },
    },
    // Import the new refresh metrics
    metricss::refresh_metrics::{
        // High-level complete flow tracking
        time_complete_refresh_flow, record_refresh_success, record_refresh_failure,
        // Step-by-step tracking with business helpers
        record_token_validation_success, record_token_validation_failure,
        record_token_type_check_success, record_token_type_check_failure,
        record_token_revocation_success, record_token_revocation_failure,
        record_access_token_generation_success, record_access_token_generation_failure,
        record_refresh_token_generation_success, record_refresh_token_generation_failure,
        // Type-safe constants
        error_types,
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

/// Processes a token refresh operation according to OAuth2 specification with complete metrics.
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
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Start complete refresh flow timer for end-to-end performance monitoring
    let _complete_flow_timer = time_complete_refresh_flow();
    
    log_info!(
        "Auth", 
        "Starting token refresh operation", 
        "refresh_start"
    );

    // Step 1: Get Redis client for token operations with configuration validation
    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| {
            record_refresh_failure(); // Record overall failure
            AuthServiceError::configuration("Redis client not available for token operations")
        })?;

    // Step 2: Validate the refresh token with detailed metrics
    log_info!("Auth", "Starting token validation", "token_validation_start");
    
    let claims = match validate_token(token, redis_client).await {
        Ok(claims) => {
            record_token_validation_success();
            log_info!("Auth", "Token validation successful", "token_validation_success");
            claims
        }
        Err(e) => {
            // Categorize validation failure for detailed monitoring
            let error_type = categorize_jwt_error(&e);
            record_token_validation_failure(error_type);
            record_refresh_failure(); // Also record overall failure
            
            log_warn!("Auth", &format!("Token validation failed: {}", e), "token_validation_failure");
            return Err(e);
        }
    };

    // Step 3: Verify token is of the correct type with metrics
    log_info!("Auth", "Starting token type check", "token_type_check_start");
    
    if claims.token_type != TOKEN_TYPE_REFRESH {
        record_token_type_check_failure(error_types::WRONG_TOKEN_TYPE);
        record_refresh_failure(); // Also record overall failure
        
        log_warn!(
            "Auth",
            &format!("Wrong token type: expected {}, got {}", TOKEN_TYPE_REFRESH, claims.token_type),
            "wrong_token_type"
        );
        
        return Err(AuthServiceError::validation(
            "token_type",
            "Expected a refresh token"
        ));
    }
    
    record_token_type_check_success();
    log_info!("Auth", "Token type check successful", "token_type_check_success");

    // Step 4: Generate new access token with metrics
    log_info!("Auth", "Starting access token generation", "access_token_generation_start");
    
    let access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => {
            record_access_token_generation_success();
            log_info!("Auth", "Access token generation successful", "access_token_generation_success");
            token
        }
        Err(e) => {
            record_access_token_generation_failure(error_types::GENERATION_ERROR);
            record_refresh_failure(); // Also record overall failure
            
            log_warn!("Auth", &format!("Access token generation failed: {}", e), "access_token_generation_failure");
            return Err(e);
        }
    };

    // Step 5: Revoke old refresh token (implement token rotation for security) with metrics
    log_info!("Auth", "Starting token revocation", "token_revocation_start");
    
    match revoke_token(token, redis_client).await {
        Ok(()) => {
            record_token_revocation_success();
            log_info!("Auth", "Token revocation successful", "token_revocation_success");
        }
        Err(e) => {
            record_token_revocation_failure(error_types::REVOCATION_FAILED);
            // Note: We continue even if revocation fails to provide better UX
            // but we log it as a warning for security monitoring
            log_warn!(
                "Auth",
                &format!("Failed to revoke old refresh token: {}", e),
                "token_revocation_warning"
            );
            // Continue without failing - user gets new tokens but old one might still be valid briefly
        }
    }

    // Step 6: Generate new refresh token with metrics
    log_info!("Auth", "Starting refresh token generation", "refresh_token_generation_start");
    
    let refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => {
            record_refresh_token_generation_success();
            log_info!("Auth", "Refresh token generation successful", "refresh_token_generation_success");
            token
        }
        Err(e) => {
            record_refresh_token_generation_failure(error_types::GENERATION_ERROR);
            record_refresh_failure(); // Also record overall failure
            
            log_warn!("Auth", &format!("Refresh token generation failed: {}", e), "refresh_token_generation_failure");
            return Err(e);
        }
    };

    // Complete success - record overall success
    record_refresh_success();
    log_info!(
        "Auth",
        &format!("Token refresh completed successfully for user: {}", claims.sub),
        "refresh_success"
    );

    // Return new token pair in OAuth2-compatible format using Axum's Json wrapper
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

/// Categorizes JWT validation errors for detailed metrics tracking
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
            } else {
                error_types::INVALID_SIGNATURE // Default for JWT errors
            }
        }
        AuthServiceError::Configuration(_) => error_types::REDIS_UNAVAILABLE,
        _ => error_types::INVALID_SIGNATURE // Default fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    // Import metrics for testing refresh tracking
    use crate::metricss::refresh_metrics::{
        init_refresh_metrics, REFRESH_OPERATIONS, REFRESH_DURATION, REFRESH_FAILURES,
        steps, error_types
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
}