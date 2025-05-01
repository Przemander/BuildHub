use axum::http::StatusCode;
use metrics::counter;
use serde_json::{json, Value};
use std::env;
use std::time::Duration;
use tokio::time::sleep;

use crate::{
    config::database::DbPool,
    db::users::User,
    handlers::login::LoginRequest,
    utils::errors::ApiError,
    utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
    log_info, log_error,
};

/// Processes a login request. Assumes lockout and rate limiting are enforced by middleware.
///
/// Returns a tuple of (StatusCode, JSON body) on success, or an ApiError on failure.
pub async fn process_login(
    pool: &DbPool, // kept for interface compatibility, but not used here
    req: &LoginRequest,
) -> Result<(StatusCode, Value), ApiError> {
    log_info!("Auth", &format!("Login attempt for {}", req.login), "attempt");

    let delay_ms = env::var("INVALID_CREDENTIAL_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // 1) DB lookup
    let mut conn = pool
        .get()
        .map_err(|e| {
            log_error!("Auth", &format!("DB error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            ApiError::internal(format!("DB error: {}", e))
        })?;

    let user_opt = if req.login.contains('@') {
        User::find_by_email(&mut conn, &req.login).ok()
    } else {
        User::find_by_username(&mut conn, &req.login).ok()
    };

    // 2) verify or dummy‑hash
    let password_good = if let Some(u) = &user_opt {
        u.verify_password(&req.password).unwrap_or(false)
    } else {
        let _ = User::hash_password(&req.password);
        false
    };
    if !password_good {
        sleep(Duration::from_millis(delay_ms)).await;
        log_error!("Auth", &format!("Bad password for {}", req.login), "failure");
        counter!("auth_login_attempts_total", 1, "result" => "failure");
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    let user = user_opt.unwrap();

    // 3) active?
    if !user.is_active.unwrap_or(false) {
        sleep(Duration::from_millis(delay_ms)).await;
        log_error!("Auth", &format!("Inactive account for {}", req.login), "inactive");
        counter!("auth_login_attempts_total", 1, "result" => "inactive");
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    // 4) issue JWTs
    let access = generate_token(&user.username, TOKEN_TYPE_ACCESS, None)
        .map_err(|e| {
            log_error!("Auth", &format!("Token error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            ApiError::internal(format!("Token error: {}", e))
        })?;
    let refresh = generate_token(&user.username, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            log_error!("Auth", &format!("Token error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            ApiError::internal(format!("Token error: {}", e))
        })?;

    log_info!("Auth", &format!("Login success for {}", req.login), "success");
    counter!("auth_login_attempts_total", 1, "result" => "success");

    let body = json!({
        "status": "success",
        "data": {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "user": { "username": user.username, "email": user.email }
        }
    });

    Ok((StatusCode::OK, body))
}