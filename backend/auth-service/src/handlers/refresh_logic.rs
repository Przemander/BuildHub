//! JWT token refresh business logic.
//!
//! Implements secure token rotation with proper validation,
//! revocation, and comprehensive observability.

use crate::{
    app::AppState,
    utils::{
        errors::AuthServiceError,
        jwt::{generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
        metrics,
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{error, info, span, warn, Instrument, Level};

/// Process JWT token refresh request.
///
/// # Flow
/// 1. Verify Redis availability (required for token operations).
/// 2. Validate and verify the refresh token.
/// 3. Check token type (must be a refresh token).
/// 4. Revoke the old token (best effort).
/// 5. Generate a new token pair.
/// 6. Return the new tokens.
///
/// # Security
/// - Validates token signature and expiration.
/// - Checks token revocation status via Redis.
/// - Rotates tokens to limit the exposure window of any single token.
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "token_refresh",
        token_length = token.len()
    );

    async move {
        info!("Starting token refresh process");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::token_refresh_failure();
            AuthServiceError::configuration("Token refresh service temporarily unavailable")
        })?;

        // ===== 2. TOKEN VALIDATION =====
        let validation_span = span!(Level::INFO, "validate_token");
        let claims = async {
            validate_token(token, redis_client).await.map_err(|e| {
                error!("Token validation failed: {}", e);
                metrics::auth::token_refresh_failure();
                e
            })
        }
        .instrument(validation_span)
        .await?;

        tracing::Span::current().record("username", &claims.sub);
        info!(username = %claims.sub, "Token validated successfully");

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
                "Expected a refresh token, but received an access token.",
            ));
        }
        info!(username = %claims.sub, "Token type verified as refresh token");

        // ===== 4. REVOKE OLD TOKEN (BEST EFFORT) =====
        let revocation_span = span!(Level::INFO, "revoke_old_token");
        async {
            if let Err(e) = revoke_token(token, redis_client).await {
                warn!(
                    username = %claims.sub,
                    error = %e,
                    "Failed to revoke old token (non-critical)"
                );
            } else {
                info!(username = %claims.sub, "Old token revoked successfully");
            }
        }
        .instrument(revocation_span)
        .await;

        // ===== 5. GENERATE NEW TOKEN PAIR =====
        let generation_span = span!(Level::INFO, "generate_tokens");
        let (access_token, refresh_token) = async {
            let access = generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None)?;
            let refresh = generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None)?;
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
    .instrument(span)
    .await
}