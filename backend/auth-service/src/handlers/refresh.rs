//! Token refresh handler.
//!
//! Provides functionality for refreshing JWT tokens using a valid refresh token.
//! Validates the provided refresh token, revokes it, and issues new tokens.

use std::sync::Arc;

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use redis::Client as RedisClient;

use crate::{log_info, log_warn, log_error, log_debug};
use crate::app::AppState;
use crate::utils::errors::{ApiError, ApiStatus};
use crate::utils::jwt::{generate_token, validate_token, revoke_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
use crate::utils::metrics::{
    TOKEN_OPERATIONS, TOKEN_VALIDATIONS,
    REQUESTS_TOTAL, RequestTimer,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshSuccessData {
    pub access_token: String,
    pub refresh_token: String,
}

/// Handler for token refresh requests.
/// Logs overall outcome and critical errors while using metrics for each step.
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(refresh_request): Json<TokenRequest>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/refresh", "POST");
    REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "pending"]).inc();

    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Token Management", "Missing Redis client", "failure");
            timer.set_status("500");
            return ApiError::internal("Redis client not available").into_response();
        },
    };

    let result = process_token_refresh(redis_client, &refresh_request.token).await;

    match &result {
        Ok(_) => {
            log_info!("Token Management", "Token refresh successful", "success");
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "200"]).inc();
        },
        Err(api_error) => {
            let status_code = match api_error.status {
                ApiStatus::Unauthorized => {
                    log_warn!("Token Management", &format!("Token refresh unauthorized: {}", api_error.message), "failure");
                    "401"
                },
                ApiStatus::BadRequest => {
                    log_warn!("Token Management", &format!("Token refresh bad request: {}", api_error.message), "failure");
                    "400"
                },
                ApiStatus::ServiceUnavailable => {
                    log_error!("Token Management", &format!("Token refresh service unavailable: {}", api_error.message), "failure");
                    "503"
                },
                _ => {
                    log_error!("Token Management", &format!("Token refresh internal error: {}", api_error.message), "failure");
                    "500"
                },
            };
            timer.set_status(status_code);
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", status_code]).inc();
        },
    }

    timer.complete();
    result.into_response()
}

/// Processes token refresh by verifying and revoking the old token.
/// Generates new tokens and logs only key failures or overall success.
async fn process_token_refresh(
    redis_client: &RedisClient,
    token: &str,
) -> Result<impl IntoResponse, ApiError> {
    log_debug!("Token Management", "Starting token refresh process", "start");
    
    // Validate the token
    let claims = match validate_token(token, redis_client).await {
        Ok(claims) => {
            TOKEN_VALIDATIONS.with_label_values(&["valid"]).inc();
            log_info!("Token Management", &format!("Refresh token validated for user {}", claims.sub), "success");
            claims
        },
        Err(e) => {
            TOKEN_VALIDATIONS.with_label_values(&["invalid"]).inc();
            log_warn!("Token Management", &format!("Refresh token validation failed: {}", e), "failure");
            // Provide more detailed error messages based on error type
            let msg = e.to_string();
            if msg.contains("expired") {
                return Err(ApiError::unauthorized("Token has expired"));
            } else if msg.contains("revoked") {
                return Err(ApiError::unauthorized("Token has been revoked"));
            } else if msg.contains("signature") {
                return Err(ApiError::unauthorized("Invalid token signature"));
            } else {
                return Err(ApiError::unauthorized("Invalid token"));
            }
        }
    };

    // Verify token type
    if claims.token_type != TOKEN_TYPE_REFRESH {
        TOKEN_VALIDATIONS.with_label_values(&["wrong_type"]).inc();
        log_warn!("Token Management", &format!("Incorrect token type: {}", claims.token_type), "failure");
        return Err(ApiError::bad_request("Expected refresh token, got different token type"));
    }

    log_info!("Token Management", "Token type verified", "success");

    // Generate new access token
    let new_access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "issue"]).inc();
            log_debug!("Token Management", "Access token generated", "success");
            token
        },
        Err(e) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "error"]).inc();
            log_error!("Token Management", &format!("Access token generation failed: {}", e), "failure");
            // Do not leak internal error details to client
            return Err(ApiError::internal("Failed to generate access token"));
        }
    };

    // Revoke old refresh token - non-fatal if it fails
    match revoke_token(token, redis_client).await {
        Ok(_) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "revoke"]).inc();
            log_info!("Token Management", "Old refresh token revoked", "success");
        },
        Err(e) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc();
            log_warn!("Token Management", &format!("Failed to revoke old refresh token: {}", e), "warning");
            // Continue execution - this is non-fatal
        }
    }

    // Generate new refresh token
    let new_refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "issue"]).inc();
            log_debug!("Token Management", "Refresh token generated", "success");
            token
        },
        Err(e) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc();
            log_error!("Token Management", &format!("Refresh token generation failed: {}", e), "failure");
            // Do not leak internal error details to client
            return Err(ApiError::internal("Failed to generate refresh token"));
        }
    };

    // Return success response
    log_info!("Token Management", &format!("Token refresh completed for user {}", claims.sub), "success");
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Tokens refreshed successfully",
            "data": {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer"
            }
        }))
    ))
}