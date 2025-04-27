//! User logout handler.
//!
//! Provides functionality for invalidating JWT tokens during logout
//! by adding them to a revocation list in Redis.

use std::sync::Arc;

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use redis::Client as RedisClient;

use crate::{log_info, log_warn, log_error, log_debug};
use crate::app::AppState;
use crate::utils::errors::{ApiError, ApiStatus};
use crate::utils::jwt::{validate_token, revoke_token};
use crate::utils::metrics::{
    TOKEN_OPERATIONS, TOKEN_VALIDATIONS,
    REQUESTS_TOTAL, RequestTimer,
};

/// All possible label values for TOKEN_OPERATIONS:
/// type: "any", operation: "revoke", result: "success", "failure"
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handler for logout which revokes a token.
/// Logs errors and overall summary, relying on metrics for high-frequency events.
pub async fn logout_handler(
    State(app_state): State<Arc<AppState>>,
    Json(logout_request): Json<TokenRequest>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/logout", "POST");
    REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "pending"]).inc();

    // Get Redis client (prefer reference if possible)
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Session Management", "Missing Redis client", "failure");
            timer.set_status("500");
            return ApiError::internal("Redis client not available").into_response();
        },
    };

    let result = process_logout(redis_client, &logout_request.token).await;

    match &result {
        Ok(_) => {
            log_info!("Session Management", "Logout successful", "success");
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "200"]).inc();
        },
        Err(e) => {
            let status_code = match e.status {
                ApiStatus::Unauthorized => {
                    log_warn!("Session Management", &format!("Invalid token: {}", e.message), "warning");
                    "401"
                },
                ApiStatus::NotFound => {
                    log_warn!("Session Management", &format!("Token not found: {}", e.message), "warning");
                    "404"
                },
                ApiStatus::ServiceUnavailable => {
                    log_error!("Session Management", &format!("Redis unavailable: {}", e.message), "failure");
                    "503"
                },
                _ => {
                    log_error!("Session Management", &format!("Logout failed: {}", e.message), "failure");
                    "500"
                }
            };
            timer.set_status(status_code);
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", status_code]).inc();
        },
    }

    // No need to call timer.complete(); Drop will handle it.
    result.into_response()
}

/// Processes logout by validating and revoking the token.
/// Logs errors only when token revocation fails.
async fn process_logout(
    redis_client: &RedisClient,
    token: &str,
) -> Result<impl IntoResponse, ApiError> {
    log_debug!("Session Management", "Processing logout request", "start");
    
    // Attempt to validate token, but we'll revoke it regardless
    let user_id = match validate_token(token, redis_client).await {
        Ok(claims) => {
            TOKEN_VALIDATIONS.with_label_values(&["valid"]).inc();
            log_debug!("Session Management", &format!("Valid token for user {}", claims.sub), "success");
            claims.sub
        },
        Err(e) => {
            TOKEN_VALIDATIONS.with_label_values(&["invalid"]).inc();
            log_debug!("Session Management", &format!("Invalid token: {}", e), "warning");
            // Continue with revocation even if token is invalid
            "unknown".to_string()
        }
    };

    // Revoke the token in Redis
    match revoke_token(token, redis_client).await {
        Ok(_) => {
            TOKEN_OPERATIONS.with_label_values(&["any", "revoke", "success"]).inc();
            log_info!("Session Management", &format!("Token revoked for user {}", user_id), "success");
        },
        Err(e) => {
            TOKEN_OPERATIONS.with_label_values(&["any", "revoke", "failure"]).inc();
            log_error!("Session Management", &format!("Token revocation failed: {}", e), "failure");
            let err_str = e.to_string();
            if err_str.contains("connection") {
                return Err(ApiError::service_unavailable("Redis service unavailable. Please try again later."));
            } else if err_str.contains("not found") {
                return Err(ApiError::not_found("Token not found or already expired"));
            } else {
                return Err(ApiError::internal("Failed to logout due to an internal error"));
            }
        }
    }

    // Return successful response
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "status": "success",
            "message": "Successfully logged out"
        }))
    ))
}