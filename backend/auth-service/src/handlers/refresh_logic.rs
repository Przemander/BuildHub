//! Business logic for JWT token refresh operations.
//!
//! This module implements the OAuth2-compatible token refresh flow with:
//! - Validated token exchange (refresh token → access token)
//! - Refresh token rotation for enhanced security
//! - Comprehensive token validation checks
//! - Redis-based token revocation
//! - Structured error handling and logging
//! - Full observability with detailed metrics
//!
//! Security features include:
//! - Immediate revocation of used refresh tokens to prevent replay attacks
//! - Token type enforcement to prevent token misuse
//! - Proper JWT validation including expiration and signature verification

use crate::{
    app::AppState,
    log_error, log_info, log_warn,
    utils::{
        jwt::{
            generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH,
        },
        metrics::AUTH_REFRESHES,
    },
};
use axum::http::StatusCode;
use serde_json::{json, Value};

/// Processes a token refresh operation according to OAuth2 specification.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client for token validation
/// * `token` - The refresh token to validate and exchange
///
/// # Returns
///
/// A tuple containing HTTP status code and JSON response body
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
) -> (StatusCode, Value) {
    // Get Redis client for token operations
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Auth", "Missing Redis client for token operations", "system_error");
            AUTH_REFRESHES.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Redis unavailable"
                }),
            );
        }
    };

    // Step 1: Validate the refresh token
    let claims = match validate_token(token, redis_client).await {
        Ok(claims) => claims,
        Err(e) => {
            let error_message = e.to_string();
            log_error!(
                "Auth",
                &format!("Refresh token validation failed: {}", error_message),
                "failure"
            );

            // Classify token validation errors for better user feedback
            let (status, metric_label, user_message) = if error_message.contains("expired") {
                (StatusCode::UNAUTHORIZED, "expired", "Token has expired")
            } else if error_message.contains("revoked") {
                (StatusCode::UNAUTHORIZED, "revoked", "Token has been revoked")
            } else if error_message.contains("signature") {
                (StatusCode::UNAUTHORIZED, "invalid_signature", "Invalid token signature")
            } else {
                (StatusCode::UNAUTHORIZED, "invalid", "Invalid token")
            };

            // Record specific error metric
            AUTH_REFRESHES.with_label_values(&[metric_label]).inc();
            
            return (
                status,
                json!({
                    "status": "error",
                    "message": user_message
                }),
            );
        }
    };

    // Step 2: Verify token is of the correct type
    if claims.token_type != TOKEN_TYPE_REFRESH {
        log_warn!(
            "Auth",
            &format!("Wrong token type: {}", claims.token_type),
            "wrong_type"
        );
        AUTH_REFRESHES.with_label_values(&["wrong_type"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": "Expected a refresh token"
            }),
        );
    }

    // Step 3: Generate new access token
    let access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => token,
        Err(e) => {
            log_error!(
                "Auth",
                &format!("Access token generation failed: {}", e),
                "token_generation_error"
            );
            AUTH_REFRESHES.with_label_values(&["token_generation_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Failed to generate access token"
                }),
            );
        }
    };

    // Step 4: Revoke old refresh token (implement token rotation for security)
    // Note: We continue even if revocation fails to provide better UX
    if let Err(e) = revoke_token(token, redis_client).await {
        log_warn!(
            "Auth",
            &format!("Failed to revoke old refresh token: {}", e),
            "revoke_failed"
        );
        AUTH_REFRESHES.with_label_values(&["revoke_warning"]).inc();
    }

    // Step 5: Generate new refresh token
    let refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => token,
        Err(e) => {
            log_error!(
                "Auth",
                &format!("Refresh token generation failed: {}", e),
                "token_generation_error"
            );
            AUTH_REFRESHES.with_label_values(&["token_generation_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Failed to generate refresh token"
                }),
            );
        }
    };

    // Record successful refresh
    log_info!(
        "Auth",
        &format!("Token refresh successful for user: {}", claims.sub),
        "success"
    );
    AUTH_REFRESHES.with_label_values(&["success"]).inc();

    // Return new token pair in OAuth2-compatible format
    (
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "Tokens refreshed successfully",
            "data": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer"
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    #[tokio::test]
    async fn missing_redis_returns_500() {
        // Arrange
        let state = state_no_redis(); // state_no_redis() already sets JWT_SECRET internally
        
        // Act
        let (status, body) = process_token_refresh(&state, "whatever").await;
        
        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body,
            json!({
                "status": "error",
                "message": "Redis unavailable"
            })
        );
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        // Arrange
        let state = state_with_redis();
        
        // Act
        let (status, body) = process_token_refresh(&state, "not-a-jwt").await;
        
        // Assert
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body,
            json!({
                "status": "error",
                "message": "Invalid token"
            })
        );
    }

    #[tokio::test]
    async fn wrong_token_type_returns_400() {
        // Arrange
        let state = state_with_redis();
        // Generate an access token instead of a refresh token
        let access = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // Act
        let (status, body) = process_token_refresh(&state, &access).await;
        
        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            json!({
                "status": "error",
                "message": "Expected a refresh token"
            })
        );
    }

    #[tokio::test]
    #[ignore] // requires real Redis & JWT_SECRET environment
    async fn successful_refresh_returns_200_and_new_tokens() {
        // Arrange
        let state = state_with_redis();
        // Generate a real refresh token
        let refresh = generate_token("user42", TOKEN_TYPE_REFRESH, None).unwrap();
        
        // Act
        let (status, body) = process_token_refresh(&state, &refresh).await;
        
        // Assert
        assert_eq!(status, StatusCode::OK);

        // Verify response structure and content
        let data = body.get("data").expect("Response missing 'data' field");
        let access_token = data.get("access_token")
            .and_then(Value::as_str)
            .expect("Missing access_token");
        let refresh_token = data.get("refresh_token")
            .and_then(Value::as_str)
            .expect("Missing refresh_token");
        let token_type = data.get("token_type")
            .and_then(Value::as_str)
            .expect("Missing token_type");

        assert!(!access_token.is_empty(), "Access token should not be empty");
        assert!(!refresh_token.is_empty(), "Refresh token should not be empty");
        assert_eq!(token_type, "Bearer", "Token type should be 'Bearer'");
    }
}