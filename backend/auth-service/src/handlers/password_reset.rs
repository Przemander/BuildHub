//! Password reset endpoints for BuildHub Auth Service.
//!
//! - POST /auth/password-reset/request: Request a password reset link.
//! - POST /auth/password-reset/confirm: Reset password using a token.

use std::sync::Arc;
use axum::{
    extract::{State, Json},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use rand::{RngCore, rngs::OsRng};
use redis::Commands;
use base64::{engine::general_purpose, Engine as _};

use crate::{log_info, log_warn, log_error};
use crate::app::AppState;
use crate::db::users::User;
use crate::utils::errors::ApiError;
use crate::utils::validators::validate_password;
use crate::utils::metrics::{AUTH_PASSWORD_RESETS, REQUESTS_TOTAL, RequestTimer};
use crate::utils::email::send_password_reset_email;

const RESET_TOKEN_TTL_SECS: usize = 60 * 30; // 30 minutes

#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
    pub status: String,
    pub message: String,
}

/// POST /auth/password-reset/request
/// Always returns 200 to avoid leaking user existence.
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/password-reset/request", "POST");
    REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/request", "POST", "pending"]).inc();

    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("PasswordReset", "Missing Redis client", "failure");
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/request", "POST", "500"]).inc();
            return ApiError::internal("Redis unavailable").into_response();
        }
    };

    // Always respond 200, even if email is not found, to prevent enumeration.
    let mut conn = match app_state.pool.get() {
        Ok(conn) => conn,
        Err(_) => {
            log_error!("PasswordReset", "DB connection failed", "failure");
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/request", "POST", "500"]).inc();
            return ApiError::internal("Database unavailable").into_response();
        }
    };

    let user = User::find_by_email(&mut conn, &req.email);
    if let Ok(user) = user {
        // Generate secure random token
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let token = general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes);

        // Store token in Redis with TTL
        let redis_key = format!("pwreset:{}", &token);
        let mut redis_conn = match redis_client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                log_error!("PasswordReset", "Redis connection failed", "failure");
                AUTH_PASSWORD_RESETS.with_label_values(&["request", "failure"]).inc();
                timer.set_status("500");
                REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/request", "POST", "500"]).inc();
                return ApiError::internal("Redis unavailable").into_response();
            }
        };
        let set_result: redis::RedisResult<()> = redis_conn.set_ex(&redis_key, &user.email, RESET_TOKEN_TTL_SECS as usize);
        if let Err(e) = set_result {
            log_error!("PasswordReset", &format!("Failed to store reset token: {}", e), "failure");
            AUTH_PASSWORD_RESETS.with_label_values(&["request", "failure"]).inc();
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/request", "POST", "500"]).inc();
            return ApiError::internal("Failed to store reset token").into_response();
        }

        // Send password reset email (non-fatal if it fails)
        if let Some(email_config) = &app_state.email_config {
            match send_password_reset_email(email_config, &user.email, &token).await {
                Ok(_) => {
                    log_info!("PasswordReset", "Reset email sent", "success");
                    AUTH_PASSWORD_RESETS.with_label_values(&["request", "success"]).inc();
                }
                Err(e) => {
                    log_warn!("PasswordReset", &format!("Failed to send reset email: {}", e), "failure");
                    AUTH_PASSWORD_RESETS.with_label_values(&["request", "failure"]).inc();
                }
            }
        }
    }

    timer.set_status("200");
    REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/request", "POST", "200"]).inc();
    axum::Json(PasswordResetResponse {
        status: "success".to_string(),
        message: "If the email exists, a password reset link has been sent.".to_string(),
    })
    .into_response()
}

/// POST /auth/password-reset/confirm
pub async fn password_reset_confirm_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetConfirm>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/password-reset/confirm", "POST");
    REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "pending"]).inc();

    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("PasswordReset", "Missing Redis client", "failure");
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "500"]).inc();
            return ApiError::internal("Redis unavailable").into_response();
        }
    };

    // Validate token in Redis
    let redis_key = format!("pwreset:{}", &req.token);
    let email: Option<String> = {
        let mut redis_conn = match redis_client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                log_error!("PasswordReset", "Redis connection failed", "failure");
                timer.set_status("500");
                REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "500"]).inc();
                return ApiError::internal("Redis unavailable").into_response();
            }
        };
        match redis_conn.get::<_, Option<String>>(&redis_key) {
            Ok(email) => email,
            Err(_) => None,
        }
    };

    if email.is_none() {
        AUTH_PASSWORD_RESETS.with_label_values(&["complete", "failure"]).inc();
        timer.set_status("400");
        REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "400"]).inc();
        return ApiError::bad_request("Invalid or expired reset token").into_response();
    }
    let email = email.unwrap();

    // Validate new password
    if let Err(e) = validate_password(&req.new_password) {
        AUTH_PASSWORD_RESETS.with_label_values(&["complete", "failure"]).inc();
        timer.set_status("400");
        REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "400"]).inc();
        return ApiError::validation("password", &e.to_string()).into_response();
    }

    // Update password in DB
    let mut conn = match app_state.pool.get() {
        Ok(conn) => conn,
        Err(_) => {
            log_error!("PasswordReset", "DB connection failed", "failure");
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "500"]).inc();
            return ApiError::internal("Database unavailable").into_response();
        }
    };

    let mut user = match User::find_by_email(&mut conn, &email) {
        Ok(user) => user,
        Err(_) => {
            AUTH_PASSWORD_RESETS.with_label_values(&["complete", "failure"]).inc();
            timer.set_status("400");
            REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "400"]).inc();
            return ApiError::bad_request("Invalid reset token").into_response();
        }
    };

    // Use a public method to set and hash the password, then update the user.
    if let Err(e) = user.set_password_and_update(&mut conn, &req.new_password) {
        log_error!("PasswordReset", &format!("Failed to update password: {}", e), "failure");
        AUTH_PASSWORD_RESETS.with_label_values(&["complete", "failure"]).inc();
        timer.set_status("500");
        REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "500"]).inc();
        return ApiError::internal("Failed to update password").into_response();
    }

    // Remove token from Redis
    let mut redis_conn = redis_client.get_connection().ok();
    if let Some(ref mut c) = redis_conn {
        let _: Result<(), _> = c.del(&redis_key);
    }

    // TODO: Invalidate all user sessions/tokens here if you track them

    AUTH_PASSWORD_RESETS.with_label_values(&["complete", "success"]).inc();
    timer.set_status("200");
    REQUESTS_TOTAL.with_label_values(&["/auth/password-reset/confirm", "POST", "200"]).inc();
    axum::Json(PasswordResetResponse {
        status: "success".to_string(),
        message: "Password has been reset successfully.".to_string(),
    })
    .into_response()
}