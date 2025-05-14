//! Business logic for password reset.

use crate::{
    app::AppState,
    db::users::User,
    utils::email::send_password_reset_email,
    utils::metrics::AUTH_PASSWORD_RESETS,
    utils::validators::validate_password,
    log_info, log_error, log_warn,
};
use axum::http::StatusCode;
use base64::{engine::general_purpose, Engine as _};
use rand::{rngs::OsRng, RngCore};
use redis::AsyncCommands;
use serde_json::json;

const RESET_TOKEN_TTL_SECS: usize = 60 * 30; // 30 minutes

/// Processes a password reset link request.
pub async fn process_password_reset_request(
    app_state: &AppState,
    email: &str,
) -> (StatusCode, serde_json::Value) {
    // Check Redis availability
    let redis_client = match &app_state.redis_client {
        Some(c) => c,
        None => {
            log_error!("PasswordReset", "Missing Redis client", "system_error");
            AUTH_PASSWORD_RESETS.with_label_values(&["request", "system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Redis unavailable"
                }),
            );
        }
    };

    // Check database
    let mut db_conn = match app_state.pool.get() {
        Ok(c) => c,
        Err(e) => {
            log_error!("PasswordReset", &format!("DB connection failed: {}", e), "system_error");
            AUTH_PASSWORD_RESETS.with_label_values(&["request", "system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Database unavailable"
                }),
            );
        }
    };

    // Lookup user by email; do not reveal existence
    if let Ok(user) = User::find_by_email(&mut db_conn, email) {
        // Generate secure random token
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let redis_key = format!("pwreset:{}", &token);

        // Store token in Redis (async)
        if let Ok(mut redis_conn) = redis_client.get_async_connection().await {
            if let Err(e) = redis_conn
                .set_ex::<_, _, ()>(&redis_key, &user.email, RESET_TOKEN_TTL_SECS)
                .await
            {
                log_error!("PasswordReset", &format!("Failed to store reset token: {}", e), "failure");
                AUTH_PASSWORD_RESETS.with_label_values(&["request", "failure"]).inc();
            } else if let Some(cfg) = &app_state.email_config {
                // Send email (non-fatal)
                if let Err(e) = send_password_reset_email(cfg, &user.email, &token).await {
                    log_warn!("PasswordReset", &format!("Failed to send reset email: {}", e), "failure");
                    AUTH_PASSWORD_RESETS.with_label_values(&["request", "failure"]).inc();
                } else {
                    log_info!("PasswordReset", "Reset email sent", "success");
                    AUTH_PASSWORD_RESETS.with_label_values(&["request", "success"]).inc();
                }
            }
        } else {
            log_error!("PasswordReset", "Redis connection failed", "failure");
            AUTH_PASSWORD_RESETS.with_label_values(&["request", "failure"]).inc();
        }
    }

    // Always return 200 to prevent email enumeration
    (
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "If the email exists, a password reset link has been sent."
        }),
    )
}

/// Processes a password reset confirmation.
pub async fn process_password_reset_confirm(
    app_state: &AppState,
    token: &str,
    new_password: &str,
) -> (StatusCode, serde_json::Value) {
    // Check Redis availability
    let redis_client = match &app_state.redis_client {
        Some(c) => c,
        None => {
            log_error!("PasswordReset", "Missing Redis client", "system_error");
            AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Redis unavailable"
                }),
            );
        }
    };

    // Build Redis key and get async connection
    let redis_key = format!("pwreset:{}", token);
    let mut redis_conn = match redis_client.get_async_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            log_error!("PasswordReset", &format!("Redis connection failed: {}", e), "system_error");
            AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Redis unavailable"
                }),
            );
        }
    };

    // Retrieve stored email
    let email_opt = match redis_conn.get::<_, Option<String>>(&redis_key).await {
        Ok(opt) => opt,
        Err(e) => {
            log_error!("PasswordReset", &format!("Redis get failed: {}", e), "system_error");
            AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Redis unavailable"
                }),
            );
        }
    };

    let email = match email_opt {
        Some(e) => e,
        None => {
            log_warn!("PasswordReset", "Invalid or expired reset token", "invalid_token");
            AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "invalid_token"]).inc();
            return (
                StatusCode::BAD_REQUEST,
                json!({
                    "status": "error",
                    "message": "Invalid or expired reset token"
                }),
            );
        }
    };

    // Validate new password
    if let Err(e) = validate_password(new_password) {
        log_warn!("PasswordReset", &format!("Password validation failed: {}", e), "validation_failed");
        AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "validation_failed"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": e.to_string()
            }),
        );
    }

    // Update password in DB
    let mut db_conn = match app_state.pool.get() {
        Ok(c) => c,
        Err(e) => {
            log_error!("PasswordReset", &format!("DB connection failed: {}", e), "system_error");
            AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Database unavailable"
                }),
            );
        }
    };

    let mut user = match User::find_by_email(&mut db_conn, &email) {
        Ok(u) => u,
        Err(e) => {
            log_warn!("PasswordReset", &format!("User not found: {}", e), "user_not_found");
            AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "user_not_found"]).inc();
            return (
                StatusCode::BAD_REQUEST,
                json!({
                    "status": "error",
                    "message": "Invalid reset token"
                }),
            );
        }
    };

    if let Err(e) = user.set_password_and_update(&mut db_conn, new_password) {
        log_error!("PasswordReset", &format!("Password update failed: {}", e), "failure");
        AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "failure"]).inc();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "status": "error",
                "message": "Failed to update password"
            }),
        );
    }

    // Delete token in Redis (async, non-fatal)
    if let Ok(mut redis_conn) = redis_client.get_async_connection().await {
        let _: Result<(), _> = redis_conn.del(&redis_key).await;
    }

    log_info!("PasswordReset", "Password has been reset successfully", "success");
    AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "success"]).inc();
    (
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "Password has been reset successfully."
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{init_jwt_secret, state_no_redis, state_with_redis};
    use axum::http::StatusCode;
    use serde_json::json;
    use redis::cmd;

    #[tokio::test]
    async fn missing_redis_request_returns_500() {
        init_jwt_secret();
        let state = state_no_redis();
        let (status, body) = process_password_reset_request(&state, "user@example.com").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({
            "status":"error",
            "message":"Redis unavailable"
        }));
    }

    #[tokio::test]
    async fn request_nonexistent_email_returns_200() {
        init_jwt_secret();
        let state = state_with_redis();
        let (status, body) =
            process_password_reset_request(&state, "no-user@domain").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({
            "status":"success",
            "message":"If the email exists, a password reset link has been sent."
        }));
    }

    #[tokio::test]
    async fn missing_redis_confirm_returns_500() {
        init_jwt_secret();
        let state = state_no_redis();
        let (status, body) =
            process_password_reset_confirm(&state, "some-token", "NewPass1!").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({
            "status":"error",
            "message":"Redis unavailable"
        }));
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn invalid_token_confirm_returns_400() {
        init_jwt_secret();
        let state = state_with_redis();
        // no such token in Redis
        let (status, body) =
            process_password_reset_confirm(&state, "bad-token", "NewPass1!").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({
            "status":"error",
            "message":"Invalid or expired reset token"
        }));
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn validation_error_confirm_returns_400() {
        init_jwt_secret();
        let state = state_with_redis();
        // seed Redis so token is recognized
        let mut redis_conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let email = "u@d.com";
        let token = "tok123";
        let key = format!("pwreset:{}", token);
        redis_conn.set_ex::<_, _, ()>(&key, email, RESET_TOKEN_TTL_SECS).await.unwrap();

        // invalid new password
        let (status, body) =
            process_password_reset_confirm(&state, token, "short").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.get("message").unwrap().as_str().unwrap().contains("password"));
    }

    #[tokio::test]
    #[ignore] // requires Redis + real DB + JWT_SECRET
    async fn successful_confirm_resets_password() {
        init_jwt_secret();
        let state = state_with_redis();

        // flush redis
        let mut redis_conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut redis_conn).await.unwrap();

        // prepare DB user
        let mut conn = state.pool.get().unwrap();
        let mut user = User::new("alice", "a@b.com", "OldPass1!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();

        // seed Redis token→email
        let token = "tok456";
        let key = format!("pwreset:{}", token);
        redis_conn.set_ex::<_, _, ()>(&key, &user.email, RESET_TOKEN_TTL_SECS).await.unwrap();

        // confirm with new valid password
        let new_pw = "NewStrong1!";
        let (status, body) =
            process_password_reset_confirm(&state, token, new_pw).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({
            "status":"success",
            "message":"Password has been reset successfully."
        }));

        // verify DB update
        let mut conn2 = state.pool.get().unwrap();
        let updated = User::find_by_email(&mut conn2, &user.email).unwrap();
        assert!(updated.verify_password(new_pw).unwrap());
    }
}