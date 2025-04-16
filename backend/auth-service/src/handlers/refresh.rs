//! Token refresh handler.
//!
//! Provides functionality for refreshing JWT tokens using a valid refresh token.
//! Validates the provided refresh token, revokes it, and issues new tokens.

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use redis::Client as RedisClient;

use crate::{log_info, log_warn, log_error};
use crate::app::AppState;
use crate::utils::errors::ApiError;
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
    State(app_state): State<AppState>,
    Json(refresh_request): Json<TokenRequest>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/refresh");
    REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "pending"]).inc();

    let redis_client = match app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Token Management", "Missing Redis client", "failure");
            timer.set_status("500");
            timer.complete("POST");
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "500"]).inc();
            return ApiError::internal_error("Redis client not available").into_response();
        },
    };

    let result = process_token_refresh(redis_client.clone(), refresh_request.token).await;

    match &result {
        Ok(_) => {
            log_info!("Token Management", "Token refresh successful", "success");
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "200"]).inc();
        },
        Err(api_error) => {
            log_warn!("Token Management", "Token refresh failed", "failure");
            let status_code = match api_error.status.as_str() {
                "unauthorized" => "401",
                "bad_request" => "400",
                _ => "500",
            };
            timer.set_status(status_code);
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", status_code]).inc();
        },
    }

    timer.complete("POST");
    result.into_response()
}

/// Processes token refresh by verifying and revoking the old token.
/// Generates new tokens and logs only key failures or overall success.
async fn process_token_refresh(
    redis_client: RedisClient,
    token: String,
) -> Result<impl IntoResponse, ApiError> {
    let claims = match validate_token(&token, &redis_client).await {
        Ok(claims) => {
            TOKEN_VALIDATIONS.with_label_values(&["valid"]).inc();
            log_info!("Token Management", "Refresh token validated", "success");
            claims
        },
        Err(_) => {
            TOKEN_VALIDATIONS.with_label_values(&["invalid"]).inc();
            log_warn!("Token Management", "Refresh token validation failed", "failure");
            return Err(ApiError::unauthorized_error("Invalid or expired token"));
        }
    };

    if claims.token_type != TOKEN_TYPE_REFRESH {
        TOKEN_VALIDATIONS.with_label_values(&["wrong_type"]).inc();
        log_warn!("Token Management", "Incorrect token type", "failure");
        return Err(ApiError::bad_request_error("Not a refresh token"));
    }

    log_info!("Token Management", "Token type verified", "success");

    let new_access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "issue"]).inc();
            token
        },
        Err(_) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "error"]).inc();
            log_error!("Token Management", "Access token generation failed", "failure");
            return Err(ApiError::internal_error("Token refresh failed"));
        }
    };

    match revoke_token(&token, &redis_client).await {
        Ok(_) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "revoke"]).inc();
            log_info!("Token Management", "Old refresh token revoked", "success");
        },
        Err(_) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "revoke_error"]).inc();
            log_warn!("Token Management", "Failed to revoke old refresh token", "failure");
        }
    }

    let new_refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "issue"]).inc();
            token
        },
        Err(_) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc();
            log_error!("Token Management", "Refresh token generation failed", "failure");
            return Err(ApiError::internal_error("Token refresh failed"));
        }
    };

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