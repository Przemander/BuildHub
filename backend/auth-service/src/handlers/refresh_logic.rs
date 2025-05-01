//! Business logic for token refresh.

use crate::{
    app::AppState,
    utils::jwt::{generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
    utils::metrics::AUTH_REFRESHES,
    log_info, log_error, log_warn,
};
use axum::http::StatusCode;
use serde_json::{json, Value};

/// Processes the token refresh logic: validates, revokes, issues new tokens, logs and increments metrics.
///
/// Returns (StatusCode, JSON body) for the handler to respond.
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> (StatusCode, Value) {
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Auth", "Missing Redis client", "system_error");
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

    // 1. Validate the refresh token
    let claims = match validate_token(token, redis_client).await {
        Ok(claims) => claims,
        Err(e) => {
            let msg = e.to_string();
            log_error!("Auth", &format!("Refresh token validation failed: {}", msg), "failure");
            let (status, label, message) = if msg.contains("expired") {
                (StatusCode::UNAUTHORIZED, "expired", "Token has expired")
            } else if msg.contains("revoked") {
                (StatusCode::UNAUTHORIZED, "revoked", "Token has been revoked")
            } else if msg.contains("signature") {
                (StatusCode::UNAUTHORIZED, "invalid_signature", "Invalid token signature")
            } else {
                (StatusCode::UNAUTHORIZED, "invalid", "Invalid token")
            };
            AUTH_REFRESHES.with_label_values(&[label]).inc();
            return (
                status,
                json!({
                    "status": "error",
                    "message": message
                }),
            );
        }
    };

    // 2. Ensure token type is refresh
    if claims.token_type != TOKEN_TYPE_REFRESH {
        log_warn!("Auth", &format!("Wrong token type: {}", claims.token_type), "wrong_type");
        AUTH_REFRESHES.with_label_values(&["wrong_type"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": "Expected a refresh token"
            }),
        );
    }

    // 3. Generate new access token
    let access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => token,
        Err(e) => {
            log_error!("Auth", &format!("Access token generation failed: {}", e), "failure");
            AUTH_REFRESHES.with_label_values(&["failure"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Failed to generate access token"
                }),
            );
        }
    };

    // 4. Revoke old refresh token (non-fatal)
    if let Err(e) = revoke_token(token, redis_client).await {
        log_warn!("Auth", &format!("Failed to revoke old refresh token: {}", e), "revoke_failed");
        AUTH_REFRESHES.with_label_values(&["revoke_failed"]).inc();
    }

    // 5. Generate new refresh token
    let refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => token,
        Err(e) => {
            log_error!("Auth", &format!("Refresh token generation failed: {}", e), "failure");
            AUTH_REFRESHES.with_label_values(&["failure"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Failed to generate refresh token"
                }),
            );
        }
    };

    log_info!("Auth", "Token refresh successful", "success");
    AUTH_REFRESHES.with_label_values(&["success"]).inc();

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