//! JWT token refresh business logic.
//!
//! Implements secure token rotation with proper validation,
//! revocation, and comprehensive observability.

use crate::{
    app::AppState,
    utils::metrics,  // Fixed: correct import path
    utils::{
        errors::AuthServiceError,
        jwt::{generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{error, info, span, warn, Instrument, Level};

/// Process JWT token refresh request.
///
/// # Flow
/// 1. Verify Redis availability (required for token operations)
/// 2. Validate and verify the refresh token
/// 3. Check token type (must be refresh token)
/// 4. Revoke old token (best effort)
/// 5. Generate new token pair
/// 6. Return new tokens
///
/// # Security
/// - Validates token signature and expiration
/// - Checks token revocation status
/// - Rotates tokens to limit exposure window
/// - Best-effort revocation of old tokens
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create root span for the operation
    let span = span!(Level::INFO, "token_refresh",
        token_length = token.len()
    );
    let span_for_instrument = span.clone();  // Fixed: Clone for .instrument()

    async move {
        info!("Starting token refresh process");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::token_refresh_failure();
            AuthServiceError::configuration("Redis required for token operations")
        })?;

        // ===== 2. TOKEN VALIDATION =====
        let validation_span = span!(Level::INFO, "validate_token");
        let claims = async {
            validate_token(token, redis_client).await.map_err(|e| {
                let error_type = categorize_jwt_error(&e);
                error!("Token validation failed: {} (type: {})", e, error_type);
                metrics::auth::token_refresh_failure();
                e
            })
        }
        .instrument(validation_span)
        .await?;
        
        // Add username to span for tracing
        span.record("username", &claims.sub);
        info!(username = %claims.sub, "Token validated successfully");
        metrics::external::redis_success("validate_token");

        // ===== 3. TOKEN TYPE VERIFICATION =====
        if claims.token_type != TOKEN_TYPE_REFRESH {
            warn!(
                username = %claims.sub,
                provided_type = %claims.token_type,
                "Invalid token type - expected refresh token"
            );
            metrics::auth::token_refresh_failure();
            return Err(AuthServiceError::validation(
                "token_type",
                "Expected a refresh token, got access token",
            ));
        }
        info!(username = %claims.sub, "Token type verified");

        // ===== 4. REVOKE OLD TOKEN (BEST EFFORT) =====
        let revocation_span = span!(Level::INFO, "revoke_old_token");
        async {
            match revoke_token(token, redis_client).await {
                Ok(()) => {
                    info!(username = %claims.sub, "Old token revoked successfully");
                    metrics::external::redis_success("revoke_token");
                }
                Err(e) => {
                    // Don't fail the flow - token will expire naturally
                    warn!(
                        username = %claims.sub,
                        error = %e,
                        "Failed to revoke old token - continuing anyway"
                    );
                    metrics::external::redis_failure("revoke_token");
                }
            }
        }
        .instrument(revocation_span)
        .await;

        // ===== 5. GENERATE NEW TOKEN PAIR =====
        let generation_span = span!(Level::INFO, "generate_tokens");
        let (access_token, refresh_token) = async {
            let access = generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None).map_err(|e| {
                error!(username = %claims.sub, "Failed to generate access token: {}", e);
                metrics::auth::token_refresh_failure();
                e
            })?;

            let refresh = generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None).map_err(|e| {
                error!(username = %claims.sub, "Failed to generate refresh token: {}", e);
                metrics::auth::token_refresh_failure();
                e
            })?;

            info!(username = %claims.sub, "New token pair generated");
            Ok::<_, AuthServiceError>((access, refresh))
        }
        .instrument(generation_span)
        .await?;

        // ===== 6. SUCCESS RESPONSE =====
        metrics::auth::token_refresh_success();
        info!(username = %claims.sub, "Token refresh completed successfully");

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
    .instrument(span_for_instrument)  // Fixed: Use the clone
    .await
}

/// Categorize JWT errors for better observability.
#[inline]
fn categorize_jwt_error(error: &AuthServiceError) -> &'static str {
    match error {
        // Fixed: Removed Jwt variant since it doesn't exist in our simplified error system
        // JWT errors are now handled as Authentication or External errors
        AuthServiceError::Authentication(_) => "authentication_error",
        AuthServiceError::Configuration(_) => "configuration_error",
        AuthServiceError::Cache(_) => "cache_error",
        AuthServiceError::External(_) => "external_error",
        _ => "unknown_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
    use crate::utils::test_utils::{init_test_env, state_no_redis, state_with_redis};  // Fixed: correct function name

    #[tokio::test]
    async fn test_missing_redis_returns_configuration_error() {
        let state = state_no_redis();
        let result = process_token_refresh(&state, "token").await;
        assert!(matches!(result, Err(AuthServiceError::Configuration(_))));
    }

    #[tokio::test]
    async fn test_invalid_token_returns_authentication_error() {
        let state = state_with_redis();
        let result = process_token_refresh(&state, "invalid-jwt").await;
        // Fixed: JWT errors are now Authentication errors in our simplified system
        assert!(matches!(result, Err(AuthServiceError::Authentication(_))));
    }

    #[tokio::test]
    async fn test_wrong_token_type_returns_validation_error() {
        init_test_env();  // Fixed: correct function name
        let state = state_with_redis();
        let access = generate_token("testuser", TOKEN_TYPE_ACCESS, None).unwrap();
        
        let result = process_token_refresh(&state, &access).await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_successful_refresh() {
        init_test_env();  // Fixed: correct function name
        let state = state_with_redis();
        let refresh = generate_token("testuser", TOKEN_TYPE_REFRESH, None).unwrap();
        
        let result = process_token_refresh(&state, &refresh).await;
        assert!(result.is_ok());
        
        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_expired_token_returns_authentication_error() {
        init_test_env();  // Fixed: correct function name
        let state = state_with_redis();
        let expired = generate_token(
            "testuser",
            TOKEN_TYPE_REFRESH,
            Some(chrono::Duration::seconds(-1))
        ).unwrap();
        
        let result = process_token_refresh(&state, &expired).await;
        // Fixed: JWT errors are now Authentication errors in our simplified system
        assert!(matches!(result, Err(AuthServiceError::Authentication(_))));
    }

    #[tokio::test]
    async fn test_multiple_successful_refreshes() {
        init_test_env();  // Fixed: correct function name
        let state = state_with_redis();
        
        // Test multiple users can refresh
        for i in 0..3 {
            let username = format!("user_{}", i);
            let token = generate_token(&username, TOKEN_TYPE_REFRESH, None).unwrap();
            let result = process_token_refresh(&state, &token).await;
            assert!(result.is_ok());
        }
    }
}