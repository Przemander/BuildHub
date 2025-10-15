//! # DEBUG ENDPOINTS - FOR DEVELOPMENT & TESTING ONLY
//!
//! ## WARNING:
//! This module provides powerful, potentially destructive endpoints.
//! It is secured by a `TEST_SECRET` and an `APP_ENV` check, but it should
//! IDEALLY be conditionally compiled and **NEVER** included in a production build.
//!
//! This code is "portfolio-ready" because it demonstrates how to build
//! safe, efficient, and ergonomic developer tools.

use crate::{
    app::AppState,
    db::users::User,
    handlers::password_reset_logic::REDIS_KEY_PREFIX,
    utils::errors::AuthServiceError,
};
use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

/// Registers all debug routes.
/// These routes are protected by `verify_test_secret`.
pub fn debug_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/debug/clean-user", post(clean_test_user))
        .route("/debug/reset-rate-limiter", post(reset_rate_limiter))
        .route("/debug/activate-account", post(activate_account))
        .route("/debug/verify-user", post(verify_user))
        .route("/debug/create-reset-token", post(create_reset_token))
}

#[derive(Deserialize)]
pub struct TestRequest {
    test_secret: String,
}
#[derive(Deserialize)]
pub struct TestUserRequest {
    username: String,
    test_secret: String,
}
#[derive(Deserialize)]
pub struct TestEmailRequest {
    email: String,
    test_secret: String,
}

/// Verifies the test secret and ensures the environment is not production.
/// This is the primary security gate for all debug endpoints.
fn verify_test_secret(secret: &str) -> Result<(), AuthServiceError> {
    let expected_secret = std::env::var("TEST_SECRET").unwrap_or_default();
    if secret.is_empty() || expected_secret.is_empty() || secret != expected_secret {
        return Err(AuthServiceError::validation(
            "test_secret",
            "Invalid or missing test secret",
        ));
    }

    let environment = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
    if environment == "production" {
        warn!("Attempted to use debug endpoint in production environment!");
        return Err(AuthServiceError::configuration(
            "Debug endpoints are disabled in production",
        ));
    }

    Ok(())
}

/// Removes a test user from the database.
async fn clean_test_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;
    info!(username = %payload.username, "Cleaning test user");

    let username = payload.username.clone();
    let deleted = tokio::task::spawn_blocking(move || {
        let mut conn = state.pool.get()?;
        diesel::delete(
            crate::db::schema::users::table.filter(crate::db::schema::users::username.eq(&username)),
        )
        .execute(&mut conn)
        .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|e| AuthServiceError::internal(&format!("Task execution error: {}", e)))??;

    info!(deleted, "Test user(s) deleted");
    Ok(Json(json!({ "status": "success", "deleted": deleted })))
}

/// Resets rate limiter keys in Redis using the non-blocking `SCAN` command.
async fn reset_rate_limiter(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;
    info!("Resetting rate limiter keys using SCAN");

    let redis_client = state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis not configured"))?;
    let mut conn = redis_client.get_async_connection().await?;

    let patterns = [
        "ratelimit:*",
        "rate_limit:*",
        "rate:*",
        "rate:login:*",
    ];
    let mut total_deleted = 0;

    for pattern in patterns {
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;

            if !keys.is_empty() {
                let deleted: i64 = redis::cmd("DEL").arg(&keys).query_async(&mut conn).await?;
                total_deleted += deleted as usize;
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
    }

    info!(deleted = total_deleted, "Rate limiter keys deleted");
    Ok(Json(json!({ "status": "success", "deleted_keys": total_deleted })))
}

/// Activates a user account for testing.
async fn activate_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;
    info!(username = %payload.username, "Activating test account");

    let username = payload.username.clone();
    let updated = tokio::task::spawn_blocking(move || {
        let mut conn = state.pool.get()?;
        diesel::update(
            crate::db::schema::users::table.filter(crate::db::schema::users::username.eq(&username)),
        )
        .set(crate::db::schema::users::is_active.eq(true))
        .execute(&mut conn)
        .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|e| AuthServiceError::internal(&format!("Task execution error: {}", e)))??;

    if updated > 0 {
        info!("Account activated successfully");
        Ok(Json(json!({ "status": "success", "updated_users": updated })))
    } else {
        Err(AuthServiceError::validation("username", "User not found"))
    }
}

/// Verifies user account details.
async fn verify_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;
    info!(username = %payload.username, "Verifying user");

    let username = payload.username.clone();
    let user = tokio::task::spawn_blocking(move || {
        let mut conn = state.pool.get()?;
        User::find_by_username(&mut conn, &username)
    })
    .await
    .map_err(|e| AuthServiceError::internal(&format!("Task execution error: {}", e)))??;

    info!(user_id = user.id, is_active = user.is_active, "User verified");
    Ok(Json(user.to_safe_info()))
}

/// Creates a password reset token for testing.
async fn create_reset_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestEmailRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;
    info!(email = %payload.email, "Creating test reset token");

    let redis_client = state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis unavailable"))?;

    let email_for_db = payload.email.clone();
    let state_for_db = state.clone();

    let user = tokio::task::spawn_blocking(move || {
        let mut conn = state_for_db.pool.get()?;
        User::find_by_email(&mut conn, &email_for_db)
    })
    .await
    .map_err(|e| AuthServiceError::internal(&format!("Task execution error: {}", e)))??;

    let token = {
        use base64::{engine::general_purpose, Engine as _};
        use rand::{thread_rng, Rng};
        let mut bytes = [0u8; 32];
        thread_rng().fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };

    let token_key = format!("{}{}", REDIS_KEY_PREFIX, &token);
    let token_ttl = 30 * 60; // 30 minutes

    let mut redis_conn = redis_client.get_async_connection().await?;
    let _: () = redis::cmd("SET")
        .arg(&token_key)
        .arg(&user.email)
        .arg("EX")
        .arg(token_ttl)
        .query_async(&mut redis_conn)
        .await?;

    info!(user_id = user.id, "Reset token created");
    Ok(Json(json!({
        "status": "success",
        "token": token,
        "expires_in_seconds": token_ttl
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to prevent race conditions when setting environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn run_test_with_env<F>(test: F)
    where
        F: FnOnce(),
    {
        let _guard = ENV_MUTEX.lock().unwrap();
        test();
        // Cleanup env vars after test
        std::env::remove_var("TEST_SECRET");
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_verify_secret_flow() {
        run_test_with_env(|| {
            std::env::set_var("TEST_SECRET", "super-secret-test-key");
            std::env::set_var("APP_ENV", "development");

            // Valid secret and environment
            assert!(verify_test_secret("super-secret-test-key").is_ok());

            // Invalid secret
            assert!(verify_test_secret("wrong-key").is_err());
            assert!(verify_test_secret("").is_err());

            // Production environment should always fail
            std::env::set_var("APP_ENV", "production");
            assert!(verify_test_secret("super-secret-test-key").is_err());
        });
    }
}