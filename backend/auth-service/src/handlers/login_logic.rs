use axum::http::StatusCode;
use metrics::counter;
use serde_json::{json, Value};
use std::env;
use std::time::Duration;
use tokio::time::sleep;

use crate::{
    config::database::DbPool, db::users::User, handlers::login::LoginRequest, log_error, log_info, utils::{errors::ApiError, jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH}, metrics::RequestTimer}
};

/// Processes a login request. Assumes lockout and rate limiting are enforced by middleware.
///
/// Returns a tuple of (StatusCode, JSON body) on success, or an ApiError on failure.
pub async fn process_login(
    pool: &DbPool,
    req: &LoginRequest,
) -> Result<(StatusCode, Value), ApiError> {
    // Start the request timer
    let mut timer = RequestTimer::start("/auth/login", "POST");

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
            timer.set_status("500"); // Set status for system error
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
        timer.set_status("401"); // Set status for unauthorized
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    let user = user_opt.unwrap();

    // 3) active?
    if !user.is_active.unwrap_or(false) {
        sleep(Duration::from_millis(delay_ms)).await;
        log_error!("Auth", &format!("Inactive account for {}", req.login), "inactive");
        counter!("auth_login_attempts_total", 1, "result" => "inactive");
        timer.set_status("401"); // Set status for unauthorized
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    // 4) issue JWTs
    let access = generate_token(&user.username, TOKEN_TYPE_ACCESS, None)
        .map_err(|e| {
            log_error!("Auth", &format!("Token error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            timer.set_status("500"); // Set status for system error
            ApiError::internal(format!("Token error: {}", e))
        })?;
    let refresh = generate_token(&user.username, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            log_error!("Auth", &format!("Token error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            timer.set_status("500"); // Set status for system error
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

    timer.set_status("200"); // Set status for success
    timer.complete(); // Complete the timer
    Ok((StatusCode::OK, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{make_pool, init_jwt_secret};
    use crate::db::users::User;
    use crate::handlers::login::LoginRequest;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn invalid_credentials_returns_unauthorized() {
        init_jwt_secret();
        let pool = make_pool();
        let req = LoginRequest {
            login: "no-such-user".into(),
            password: "whatever".into(),
        };
        let err = process_login(&pool, &req).await.unwrap_err();
        assert!(err.to_string().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn inactive_account_returns_unauthorized() {
        init_jwt_secret();
        let pool = make_pool();
        let mut conn = pool.get().unwrap();
        let mut u = User::new("bob", "bob@example.com", "B0bSecret!");
        u.is_active = Some(false);
        u.save(&mut conn).unwrap();

        let req = LoginRequest {
            login: "bob".into(),
            password: "B0bSecret!".into(),
        };
        let err = process_login(&pool, &req).await.unwrap_err();
        assert!(err.to_string().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn successful_login_returns_tokens_and_user() {
        init_jwt_secret();
        let pool = make_pool();
        let mut conn = pool.get().unwrap();
        let mut u = User::new("alice", "alice@example.com", "Al1cePwd!");
        u.is_active = Some(true);
        u.save(&mut conn).unwrap();

        let req = LoginRequest {
            login: "alice".into(),
            password: "Al1cePwd!".into(),
        };
        let (status, body) = process_login(&pool, &req).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], json!("success"));
        let access = body["data"]["access_token"].as_str().unwrap();
        let refresh = body["data"]["refresh_token"].as_str().unwrap();
        assert!(!access.is_empty());
        assert!(!refresh.is_empty());
        assert_eq!(body["data"]["user"]["username"], json!("alice"));
        assert_eq!(body["data"]["user"]["email"], json!("alice@example.com"));
    }
}