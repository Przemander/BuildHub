//! Business logic for user logout.

use crate::{
    app::AppState,
    utils::jwt::{revoke_token, validate_token},
    utils::metrics::AUTH_LOGOUTS,
    log_info, log_error, log_warn,
};
use axum::http::StatusCode;
use serde_json::{json, Value};

/// Processes the logout logic: validates and revokes the token, logs and increments metrics.
///
/// Returns (StatusCode, JSON body) for the handler to respond.
pub async fn process_logout(
    app_state: &AppState,
    token: &str,
) -> (StatusCode, Value) {
    // Ensure Redis is available
    let redis_client = match &app_state.redis_client {
        Some(c) => c,
        None => {
            log_error!("Auth", "Missing Redis client", "system_error");
            AUTH_LOGOUTS.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "status": "error",
                    "message": "Redis client not available"
                }),
            );
        }
    };

    // Try to validate token (for logging), but proceed regardless
    match validate_token(token, redis_client).await {
        Ok(claims) => {
            log_info!("Auth", &format!("Logout: token valid for user {}", claims.sub), "success");
        }
        Err(e) => {
            log_warn!("Auth", &format!("Logout: invalid token ({})", e), "invalid_token");
        }
    }

    // Revoke the token
    match revoke_token(token, redis_client).await {
        Ok(_) => {
            log_info!("Auth", "Token revoked successfully", "success");
            AUTH_LOGOUTS.with_label_values(&["success"]).inc();
            (
                StatusCode::OK,
                json!({
                    "status": "success",
                    "message": "Logged out successfully"
                }),
            )
        }
        Err(e) => {
            log_error!("Auth", &format!("Failed to revoke token: {}", e), "failure");
            AUTH_LOGOUTS.with_label_values(&["failure"]).inc();
            let msg = e.to_string();
            let (status, message) = if msg.contains("connection") {
                (StatusCode::SERVICE_UNAVAILABLE, "Redis unavailable")
            } else if msg.contains("not found") {
                (StatusCode::NOT_FOUND, "Token not found or already expired")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to logout")
            };
            (
                status,
                json!({
                    "status": "error",
                    "message": message
                }),
            )
        }
    }
}