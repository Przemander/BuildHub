//! User logout handler.
//!
//! Provides functionality for invalidating JWT tokens during logout
//! by adding them to a revocation list in Redis.

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use redis::Client as RedisClient;

use crate::{log_info, log_error};
use crate::app::AppState;
use crate::utils::errors::ApiError;
use crate::utils::jwt::{validate_token, revoke_token};
use crate::utils::metrics::{
    TOKEN_OPERATIONS, TOKEN_VALIDATIONS,
    REQUESTS_TOTAL, RequestTimer,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handler for logout which revokes a token.
/// Logs errors and overall summary, relying on metrics for high-frequency events.
pub async fn logout_handler(
    State(app_state): State<AppState>,
    Json(logout_request): Json<TokenRequest>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/logout");
    REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "pending"]).inc();

    let redis_client = match app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Session Management", "Missing Redis client", "failure");
            timer.set_status("500");
            timer.complete("POST");
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "500"]).inc();
            return ApiError::internal_error("Redis client not available").into_response();
        },
    };

    let result = process_logout(redis_client.clone(), logout_request.token).await;

    match &result {
        Ok(_) => {
            log_info!("Session Management", "Logout successful", "success");
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "200"]).inc();
        },
        Err(_) => {
            log_error!("Session Management", "Logout failed", "failure");
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "500"]).inc();
        },
    }

    timer.complete("POST");
    result.into_response()
}

/// Processes logout by validating and revoking the token.
/// Logs errors only when token revocation fails.
async fn process_logout(
    redis_client: RedisClient,
    token: String,
) -> Result<impl IntoResponse, ApiError> {
    // Attempt to validate token, but we'll revoke it regardless
    let _user_info = match validate_token(&token, &redis_client).await {
        Ok(claims) => {
            TOKEN_VALIDATIONS.with_label_values(&["valid"]).inc();
            claims.sub
        },
        Err(_) => {
            TOKEN_VALIDATIONS.with_label_values(&["invalid"]).inc();
            "unknown".to_string()
        }
    };

    match revoke_token(&token, &redis_client).await {
        Ok(_) => {
            TOKEN_OPERATIONS.with_label_values(&["any", "revoke"]).inc();
            log_info!("Session Management", "Token revoked", "success");
        },
        Err(_) => {
            TOKEN_OPERATIONS.with_label_values(&["any", "revoke_error"]).inc();
            log_error!("Session Management", "Token revocation failed", "failure");
            return Err(ApiError::internal_error("Failed to logout"));
        }
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Successfully logged out"
        }))
    ))
}