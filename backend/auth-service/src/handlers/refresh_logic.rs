//! Business logic for JWT token refresh operations.
//!
//! This module implements the OAuth2-compatible token refresh flow with:
//! - Validated token exchange (refresh token → access token)
//! - Refresh token rotation for enhanced security
//! - Comprehensive token validation checks
//! - Redis-based token revocation
//! - Unified error handling with automatic HTTP response conversion
//! - Full observability with detailed metrics
//!
//! Security features include:
//! - Immediate revocation of used refresh tokens to prevent replay attacks
//! - Token type enforcement to prevent token misuse
//! - Proper JWT validation including expiration and signature verification

use crate::{
    app::AppState,
    log_info, log_warn,
    utils::{
        error_new::AuthServiceError, // ← Add unified error system
        jwt::{
            generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH,
        },
        metrics::AUTH_REFRESHES,
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json}; // ← Add IntoResponse
use serde_json::json;

/// Processes a token refresh operation according to OAuth2 specification.
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
/// # Flow
///
/// 1. Validate the refresh token (signature, expiration, revocation)
/// 2. Verify token is of the correct type (must be a refresh token)
/// 3. Revoke the used refresh token to prevent replay attacks
/// 4. Generate a new access token
/// 5. Generate a new refresh token (token rotation)
/// 6. Return the new token pair
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> { // ← Changed return type
    // Get Redis client for token operations
    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis client not available for token operations"))?;

    // Step 1: Validate the refresh token - automatic conversion via ? operator
    let claims = validate_token(token, redis_client).await?;

    // Step 2: Verify token is of the correct type
    if claims.token_type != TOKEN_TYPE_REFRESH {
        log_warn!(
            "Auth",
            &format!("Wrong token type: expected {}, got {}", TOKEN_TYPE_REFRESH, claims.token_type),
            "wrong_type"
        );
        AUTH_REFRESHES.with_label_values(&["wrong_type"]).inc();
        
        // Return a proper validation error
        return Err(AuthServiceError::validation(
            "token_type",
            "Expected a refresh token"
        ));
    }

    // Step 3: Generate new access token - automatic conversion via ? operator
    let access_token = generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None)?;

    // Step 4: Revoke old refresh token (implement token rotation for security)
    // Note: We continue even if revocation fails to provide better UX
    if let Err(e) = revoke_token(token, redis_client).await {
        log_warn!(
            "Auth",
            &format!("Failed to revoke old refresh token: {}", e),
            "revoke_failed"
        );
        AUTH_REFRESHES.with_label_values(&["revoke_warning"]).inc();
        // Continue without failing - user gets new tokens but old one might still be valid briefly
    }

    // Step 5: Generate new refresh token - automatic conversion via ? operator
    let refresh_token = generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None)?;

    // Record successful refresh
    log_info!(
        "Auth",
        &format!("Token refresh successful for user: {}", claims.sub),
        "success"
    );
    AUTH_REFRESHES.with_label_values(&["success"]).inc();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::{state_no_redis, state_with_redis};

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        // Arrange
        let state = state_no_redis(); // state_no_redis() already sets JWT_SECRET internally
        
        // Act
        let result = process_token_refresh(&state, "whatever").await;
        
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
    async fn invalid_token_returns_jwt_error() {
        // Arrange
        let state = state_with_redis();
        
        // Act
        let result = process_token_refresh(&state, "not-a-jwt").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a JWT error
        match result.err().unwrap() {
            AuthServiceError::Jwt(_) => {
                // Expected - invalid token should return JWT error
            }
            other => panic!("Expected JWT error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wrong_token_type_returns_validation_error() {
        // Arrange
        let state = state_with_redis();
        // Generate an access token instead of a refresh token
        let access = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // Act
        let result = process_token_refresh(&state, &access).await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected - wrong token type should return validation error
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // requires real Redis & JWT_SECRET environment
    async fn successful_refresh_returns_new_tokens() {
        // Arrange
        let state = state_with_redis();
        // Generate a real refresh token
        let refresh = generate_token("user42", TOKEN_TYPE_REFRESH, None).unwrap();
        
        // Act
        let result = process_token_refresh(&state, &refresh).await;
        
        // Assert
        assert!(result.is_ok());
        
        // Since we can't easily extract the JSON from impl IntoResponse in tests,
        // we just verify the result is Ok. In integration tests, we'd verify
        // the actual HTTP response structure.
    }
}