//! Debug endpoints for development and testing purposes.
//!
//! This module provides secure debugging endpoints that are only available
//! in non-production environments and require a test secret for authentication.
//!
//! All endpoints use unified error handling with automatic HTTP response conversion.

use std::sync::Arc;
use axum::{extract::State, response::IntoResponse, Json, Router};
use axum::routing::post;
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::{
    app::AppState, 
    log_info,
    utils::error_new::AuthServiceError,
};
use crate::db::users::User;
use crate::handlers::password_reset_logic::REDIS_KEY_PREFIX;

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

// Funkcja do weryfikacji klucza testowego - updated to use unified errors
fn verify_test_secret(secret: &str) -> Result<(), AuthServiceError> {
    let expected_secret = std::env::var("TEST_SECRET").unwrap_or_default();
    if secret != expected_secret || expected_secret.is_empty() {
        return Err(AuthServiceError::validation("test_secret", "Invalid test secret"));
    }

    // Sprawdź czy jesteśmy w środowisku testowym
    if std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) == "production" {
        return Err(AuthServiceError::configuration("Debug endpoints disabled in production"));
    }

    Ok(())
}

/// Cleans up test user from database
async fn clean_test_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    let username = payload.username.clone();
    log_info!("Test", &format!("Cleaning test user: {}", username), "debug");

    let username_for_closure = username.clone();
    let state_clone = Arc::clone(&state);
    
    let result = tokio::task::spawn_blocking(move || -> Result<usize, AuthServiceError> {
        use crate::db::schema::users::dsl;
        
        let mut conn = state_clone.pool.get()?;
        
        diesel::delete(dsl::users.filter(dsl::username.eq(username_for_closure)))
            .execute(&mut conn)
            .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|_| AuthServiceError::configuration("Task execution error"))?;

    let deleted = result?;

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

    log_info!("Test", "Resetting rate limiter", "debug");

    let redis_client = state.redis_client.as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis not configured"))?;

    let mut conn = redis_client.get_connection()?;

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
        log_info!("Test", &format!("Searching for pattern: {}", pattern), "debug");
        
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query(&mut conn)?;

        if !keys.is_empty() {
            log_info!("Test", &format!("Found keys: {:?}", keys), "debug");
            
            let _: () = redis::cmd("DEL")
                .arg(&keys)
                .query(&mut conn)?;
                
            log_info!("Test", &format!("Deleted {} rate limit keys with pattern {}", keys.len(), pattern), "debug");
            total_deleted += keys.len();
        } else {
            log_info!("Test", &format!("No keys found for pattern: {}", pattern), "debug");
        }
    }

    log_info!("Test", "Listing all keys in Redis for diagnosis", "debug");
    let all_keys: Vec<String> = redis::cmd("KEYS")
        .arg("*")
        .query(&mut conn)?;

    if !all_keys.is_empty() {
        log_info!("Test", &format!("All keys in Redis: {:?}", all_keys), "debug");
    } else {
        log_info!("Test", "Redis database is empty", "debug");
    }

    if total_deleted > 0 {
        log_info!("Test", &format!("Deleted a total of {} rate limit keys", total_deleted), "debug");
    } else {
        log_info!("Test", "No rate limit keys found", "debug");
    }

    Ok(Json(json!({
        "status": "success",
        "message": format!("Rate limiter reset successfully, deleted {} keys", total_deleted)
    })))
}

/// Activates a user account
async fn activate_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    let username = payload.username.clone();
    log_info!("Test", &format!("Activating account: {}", username), "debug");

    let username_for_closure = username.clone();
    let state_clone = Arc::clone(&state);
    
    let result = tokio::task::spawn_blocking(move || -> Result<usize, AuthServiceError> {
        use crate::db::schema::users::dsl;
        
        let mut conn = state_clone.pool.get()?;
        
        diesel::update(dsl::users.filter(dsl::username.eq(username_for_closure)))
            .set(dsl::is_active.eq(true))
            .execute(&mut conn)
            .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|_| AuthServiceError::configuration("Task execution error"))?;

    let updated = result?;

    if updated > 0 {
        Ok(Json(json!({
            "status": "success", 
            "message": "Account activated successfully"
        })))
    } else {
        Err(AuthServiceError::validation("username", "User not found"))
    }
}

/// Verifies user account status
async fn verify_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    log_info!("Test", &format!("Verifying user status: {}", payload.username), "debug");

    let username = payload.username.clone();
    let state_clone = Arc::clone(&state);
    
    let result = tokio::task::spawn_blocking(move || -> Result<User, AuthServiceError> {
        use crate::db::schema::users::dsl;
        
        let mut conn = state_clone.pool.get()?;
        
        dsl::users.filter(dsl::username.eq(username))
            .first::<User>(&mut conn)
            .map_err(AuthServiceError::from)
    })
    .await
    .map_err(|_| AuthServiceError::configuration("Task execution error"))?;

    let user = result?;

    Ok(Json(json!({
        "status": "success", 
        "message": "User found",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active.unwrap_or(false)
        }
    })))
}

/// Creates a password reset token for testing purposes
async fn create_reset_token(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<TestEmailRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    verify_test_secret(&payload.test_secret)?;

    log_info!("PasswordReset", &format!("Creating password reset token for testing: {}", payload.email), "debug");

    let redis_client = app_state.redis_client.as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis unavailable for token creation"))?;

    let mut conn = app_state.pool.get()?;

    // Fix: Najprostrze rozwiązanie - bez custom NotFound handling
    let _user = User::find_by_email(&mut conn, &payload.email)?;

    // Wygeneruj token
    let token = {
        use rand::{thread_rng, Rng};
        use base64::{engine::general_purpose, Engine as _};
        
        let mut bytes = [0u8; 32];
        thread_rng().fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    
    let token_key = format!("{}{}", REDIS_KEY_PREFIX, token);
    let token_ttl = 30 * 60;

    let mut redis_conn = redis_client.get_connection()?;

    let _: () = redis::cmd("SET")
        .arg(&token_key)
        .arg(&payload.email)
        .arg("EX")
        .arg(token_ttl)
        .query(&mut redis_conn)?;

    Ok(Json(json!({
        "status": "success",
        "message": "Password reset token created",
        "token": token
    })))
}