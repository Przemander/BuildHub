//! Debug endpoints for development and testing.
//!
//! Portfolio-ready with security checks and minimal overhead.

use axum::routing::post;
use axum::{extract::State, response::IntoResponse, Json, Router};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

use crate::app::AppState;
use crate::db::users::User;
use crate::handlers::password_reset_logic::REDIS_KEY_PREFIX;
use crate::utils::errors::AuthServiceError;

/// Registers all debug routes with security checks
pub fn debug_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/debug/clean-user", post(clean_test_user))
        .route("/debug/reset-rate-limiter", post(reset_rate_limiter))
        .route("/debug/activate-account", post(activate_account))
        .route("/debug/verify-user", post(verify_user))
        .route("/debug/create-reset-token", post(create_reset_token))
}

/// Request for operations that only need a test secret
#[derive(Deserialize)]
pub struct TestRequest {
    test_secret: String,
}

/// Request for operations that need a username and test secret
#[derive(Deserialize)]
pub struct TestUserRequest {
    username: String,
    test_secret: String,
}

/// Request for operations that need an email and test secret
#[derive(Deserialize)]
pub struct TestEmailRequest {
    email: String,
    test_secret: String,
}

/// Verifies the test secret is valid and that we're not in production
fn verify_test_secret(secret: &str) -> Result<(), AuthServiceError> {
    // Check if TEST_SECRET is set and matches
    let expected_secret = std::env::var("TEST_SECRET").unwrap_or_default();
    if secret != expected_secret || expected_secret.is_empty() {
        return Err(AuthServiceError::validation("test_secret", "Invalid test secret"));
    }

    // Verify we're not in production
    let environment = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
    if environment == "production" {
        return Err(AuthServiceError::configuration(
            "Debug endpoints disabled in production",
        ));
    }

    Ok(())
}

/// Removes a test user from the database
async fn clean_test_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    let username = payload.username.clone();
    info!(username = %username, "Cleaning test user");

    let state_clone = Arc::clone(&state);
    let deleted = tokio::task::spawn_blocking(move || -> Result<usize, AuthServiceError> {
        use crate::db::schema::users::dsl;
        let mut conn = state_clone.pool.get()?;
        diesel::delete(dsl::users.filter(dsl::username.eq(username)))
            .execute(&mut conn)
            .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|_| AuthServiceError::configuration("Task execution error"))??;

    info!(deleted = deleted, "Test user(s) deleted");

    Ok(Json(json!({
        "status": "success",
        "message": "User deleted successfully",
        "deleted": deleted
    })))
}

/// Resets rate limiter keys in Redis
async fn reset_rate_limiter(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    info!("Resetting rate limiter keys");

    let redis_client = state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis not configured"))?;

    let mut conn = redis_client.get_async_connection().await?;

    let patterns = vec![
        "ratelimit:*",
        "rate_limit:*",
        "rate:*",
        "rate:/auth/register:*",
        "rate:/auth/login:*",
        "rate:/auth/password-reset*",
        "rate:login:*",
    ];

    let mut total_deleted = 0;

    for pattern in patterns {
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut conn)
            .await?;

        if !keys.is_empty() {
            let deleted: i64 = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut conn)
                .await?;
            total_deleted += deleted as usize;
        }
    }

    info!(deleted = total_deleted, "Rate limiter keys deleted");

    Ok(Json(json!({
        "status": "success",
        "message": format!("Rate limiter reset successfully, deleted {} keys", total_deleted)
    })))
}

/// Activates a user account for testing
async fn activate_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    let username = payload.username.clone();
    info!(username = %username, "Activating test account");

    let state_clone = Arc::clone(&state);
    let updated = tokio::task::spawn_blocking(move || -> Result<usize, AuthServiceError> {
        use crate::db::schema::users::dsl;
        let mut conn = state_clone.pool.get()?;
        diesel::update(dsl::users.filter(dsl::username.eq(username)))
            .set(dsl::is_active.eq(true))
            .execute(&mut conn)
            .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|_| AuthServiceError::configuration("Task execution error"))??;

    if updated > 0 {
        info!("Account activated successfully");
        Ok(Json(json!({
            "status": "success",
            "message": "Account activated successfully"
        })))
    } else {
        warn!("User not found for activation");
        Err(AuthServiceError::validation("username", "User not found"))
    }
}

/// Verifies user account details
async fn verify_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    info!(username = %payload.username, "Verifying user");

    let username = payload.username.clone();
    let state_clone = Arc::clone(&state);
    
    let user = tokio::task::spawn_blocking(move || -> Result<User, AuthServiceError> {
        use crate::db::schema::users::dsl;
        let mut conn = state_clone.pool.get()?;
        dsl::users
            .filter(dsl::username.eq(username))
            .first::<User>(&mut conn)
            .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|_| AuthServiceError::configuration("Task execution error"))??;

    info!(user_id = user.id, is_active = user.is_active, "User verified");

    Ok(Json(json!({
        "status": "success",
        "message": "User found",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active
        }
    })))
}

/// Creates a password reset token for testing
async fn create_reset_token(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<TestEmailRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    info!(email = %payload.email, "Creating test reset token");

    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis unavailable"))?;

    let mut conn = app_state.pool.get()?;

    // Verify user exists
    let user = User::find_by_email(&mut conn, &payload.email)?;
    
    // Generate secure token
    let token = {
        use base64::{engine::general_purpose, Engine as _};
        use rand::{thread_rng, Rng};
        let mut bytes = [0u8; 32];
        thread_rng().fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };

    let token_key = format!("{}{}", REDIS_KEY_PREFIX, token);
    let token_ttl = 30 * 60; // 30 minutes

    let mut redis_conn = redis_client.get_async_connection().await?;

    // Store token in Redis
    let _: () = redis::cmd("SET")
        .arg(&token_key)
        .arg(&payload.email)
        .arg("EX")
        .arg(token_ttl)
        .query_async(&mut redis_conn)
        .await?;

    info!(user_id = user.id, "Reset token created");

    Ok(Json(json!({
        "status": "success",
        "message": "Password reset token created",
        "token": token,
        "expires_in_seconds": token_ttl
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use std::env;
    use tower::ServiceExt;
    use crate::utils::email::EmailConfig;

    fn setup_test_env() {
        env::set_var("TEST_SECRET", "test_secret_value");
        env::set_var("APP_ENV", "development");
    }

    #[test]
    fn test_verify_test_secret_valid() {
        setup_test_env();
        let result = verify_test_secret("test_secret_value");
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_test_secret_invalid() {
        setup_test_env();
        let result = verify_test_secret("wrong_secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_test_secret_production() {
        setup_test_env();
        env::set_var("APP_ENV", "production");
        let result = verify_test_secret("test_secret_value");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_clean_user_endpoint_invalid_secret() {
        setup_test_env();
        
        let app_state = Arc::new(AppState {
            pool: crate::config::database::init_pool(),
            redis_client: None,
            email_config: Some(EmailConfig::dummy()),
        });
        
        let app = Router::new()
            .route("/debug/clean-user", post(clean_test_user))
            .with_state(app_state);
            
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/clean-user")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"test","test_secret":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}