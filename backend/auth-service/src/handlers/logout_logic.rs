//! JWT token logout business logic.
//!
//! Implements secure token revocation with idempotent operations
//! and comprehensive observability.

use crate::{
    app::AppState,
    utils::{
        errors::AuthServiceError,
        jwt::{revoke_token, validate_token},
        metrics,
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{error, info, span, warn, Instrument, Level};

/// Process user logout request.
///
/// # Flow
/// 1. Verify Redis availability (required for token operations).
/// 2. Validate token (best effort - continue even if invalid).
/// 3. Revoke token (always attempt for security).
/// 4. Return success.
///
/// # Security
/// - Idempotent operation (safe to retry).
/// - Revokes even invalid tokens (defense in depth).
/// - Prevents token reuse after logout.
pub async fn process_logout(
    app_state: &AppState,
    token: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create root span for the operation.
    let span = span!(Level::INFO, "logout_operation",
        token_length = token.len()
    );

    async move {
        info!("Starting logout process");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::logout_failure();
            AuthServiceError::configuration("Logout service temporarily unavailable")
        })?;

        // ===== 2. TOKEN VALIDATION (BEST EFFORT) =====
        // We try to validate the token to get the username for logging, but we don't
        // fail the request if validation fails. We still want to revoke the token.
        let validation_span = span!(Level::INFO, "validate_token");
        let username = async {
            match validate_token(token, redis_client).await {
                Ok(claims) => {
                    info!(username = %claims.sub, "Token validated successfully for logout");
                    Some(claims.sub)
                }
                Err(e) => {
                    warn!("Token validation failed (continuing with revocation): {}", e);
                    None
                }
            }
        }
        .instrument(validation_span)
        .await;

        // Add username to the current span if available.
        if let Some(ref uname) = username {
            tracing::Span::current().record("username", uname.as_str());
        }

        // ===== 3. TOKEN REVOCATION =====
        // This is the critical step. We always attempt to revoke the token.
        let revocation_span = span!(Level::INFO, "revoke_token");
        async {
            revoke_token(token, redis_client).await.map_err(|e| {
                error!("Token revocation failed: {}", e);
                // Business-level metric for logout failure.
                metrics::auth::logout_failure();
                AuthServiceError::external("Unable to complete logout. Please try again.")
            })
        }
        .instrument(revocation_span)
        .await?;

        // ===== 4. SUCCESS =====
        metrics::auth::logout_success();
        if let Some(uname) = username {
            info!(username = %uname, "User logged out successfully");
        } else {
            info!("Logout completed successfully (invalid or expired token revoked)");
        }

        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Logged out successfully"
            })),
        ))
    }
    .instrument(span)
    .await
}