//! JWT token logout business logic.
//!
//! Implements secure token revocation with idempotent operations
//! and comprehensive observability.

use crate::{
    app::AppState,
    utils::metrics,  // Fixed: correct import path
    utils::{
        errors::AuthServiceError,
        jwt::{revoke_token, validate_token},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{error, info, span, warn, Instrument, Level};

/// Process user logout request.
///
/// # Flow
/// 1. Verify Redis availability (required for token operations)
/// 2. Validate token (best effort - continue even if invalid)
/// 3. Revoke token (always attempt for security)
/// 4. Return success
///
/// # Security
/// - Idempotent operation (safe to retry)
/// - Revokes even invalid tokens (defense in depth)
/// - Prevents token reuse after logout
pub async fn process_logout(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create root span for the operation
    let span = span!(Level::INFO, "logout_operation",
        token_length = token.len()
    );
    let span_for_instrument = span.clone();

    async move {
        info!("Starting logout process");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::logout_failure();
            AuthServiceError::configuration("Logout service temporarily unavailable")
        })?;

        // ===== 2. TOKEN VALIDATION (BEST EFFORT) =====
        let validation_span = span!(Level::INFO, "validate_token");
        let user_id = async {
            match validate_token(token, redis_client).await {
                Ok(claims) => {
                    info!(username = %claims.sub, "Token validated successfully");
                    metrics::external::redis_success("validate_token");
                    Some(claims.sub)
                }
                Err(e) => {
                    // Don't fail - we still want to revoke invalid tokens
                    warn!("Token validation failed: {} - continuing with revocation", e);
                    metrics::external::redis_failure("validate_token");
                    None
                }
            }
        }
        .instrument(validation_span)
        .await;

        // Add username to span if available
        if let Some(ref uid) = user_id {
            span.record("username", uid.as_str());
        }

        // ===== 3. TOKEN REVOCATION =====
        let revocation_span = span!(Level::INFO, "revoke_token");
        async {
            revoke_token(token, redis_client).await.map_err(|e| {
                error!("Token revocation failed: {}", e);
                metrics::external::redis_failure("revoke_token");
                metrics::auth::logout_failure();
                AuthServiceError::configuration("Unable to complete logout. Please try again.")
            })?;
            
            info!("Token revoked successfully");
            metrics::external::redis_success("revoke_token");
            Ok::<_, AuthServiceError>(())
        }
        .instrument(revocation_span)
        .await?;

        // ===== 4. SUCCESS =====
        metrics::auth::logout_success();
        if let Some(uid) = user_id {
            info!(username = %uid, "User logged out successfully");
        } else {
            info!("Logout completed successfully (invalid token revoked)");
        }

        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Logged out successfully"
            })),
        ))
    }
    .instrument(span_for_instrument)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::{state_no_redis, state_with_redis, init_test_env};

    #[tokio::test]
    async fn test_missing_redis_returns_configuration_error() {
        let state = state_no_redis();
        let result = process_logout(&state, "any-token").await;
        assert!(matches!(result, Err(AuthServiceError::Configuration(_))));
    }

    #[tokio::test]
    async fn test_invalid_token_still_succeeds() {
        let state = state_with_redis();
        // Invalid token should still be "revoked" (added to blocklist)
        let result = process_logout(&state, "invalid.jwt.token").await;
        // Should succeed (revocation is best-effort)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_empty_token_succeeds() {
        let state = state_with_redis();
        let result = process_logout(&state, "").await;
        // Empty token should be handled gracefully
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_valid_token_logout() {
        init_test_env(); // Fixed: use the correct function name
        let state = state_with_redis();
        let token = generate_token("testuser", TOKEN_TYPE_ACCESS, None).unwrap();
        
        let result = process_logout(&state, &token).await;
        assert!(result.is_ok());
        
        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_double_logout_is_idempotent() {
        init_test_env(); // Fixed: use the correct function name
        let state = state_with_redis();
        let token = generate_token("testuser", TOKEN_TYPE_ACCESS, None).unwrap();
        
        // First logout
        let result1 = process_logout(&state, &token).await;
        assert!(result1.is_ok());
        
        // Second logout should also succeed (idempotent)
        let result2 = process_logout(&state, &token).await;
        assert!(result2.is_ok());
    }
}