//! # Debug Endpoints for Development and Testing
//!
//! This module provides secure debugging endpoints for development and testing environments.
//! All endpoints require a test secret for authentication and are disabled in production.
//!
//! ## Security Features
//!
//! - All endpoints require a valid test secret
//! - Automatically disabled in production environments
//! - Rate limiter reset for testing authentication flows
//! - Limited exposure of sensitive data
//!
//! ## Available Endpoints
//!
//! - `/debug/clean-user` - Remove test users from the database
//! - `/debug/reset-rate-limiter` - Clear rate limiting keys from Redis
//! - `/debug/activate-account` - Manually activate a user account
//! - `/debug/verify-user` - Check user account details
//! - `/debug/create-reset-token` - Generate password reset tokens for testing
//!
//! ## Usage
//!
//! All endpoints expect a `test_secret` field in the request body that must match
//! the value in the `TEST_SECRET` environment variable.

use axum::routing::post;
use axum::{extract::State, response::IntoResponse, Json, Router};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::Instrument;

use crate::db::users::User;
use crate::handlers::password_reset_logic::REDIS_KEY_PREFIX;
use crate::utils::error_new::AuthServiceError;
use crate::utils::log_new::Log;
use crate::utils::telemetry::business_operation_span;
use crate::app::AppState;

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
///
/// This function provides a security layer to prevent debug endpoints
/// from being used in production or by unauthorized clients.
///
/// # Arguments
///
/// * `secret` - The test secret provided in the request
///
/// # Returns
///
/// * `Ok(())` - If the secret is valid and environment is appropriate
/// * `Err(AuthServiceError)` - If validation fails or we're in production
fn verify_test_secret(secret: &str) -> Result<(), AuthServiceError> {
    let span = business_operation_span("verify_test_secret");
    
    span.in_scope(|| {
        // Check if TEST_SECRET is set and matches
        let expected_secret = std::env::var("TEST_SECRET").unwrap_or_default();
        if secret != expected_secret || expected_secret.is_empty() {
            span.record("result", &"invalid_secret");
            return Err(AuthServiceError::validation(
                "test_secret",
                "Invalid test secret",
            ));
        }

        // Verify we're not in production
        let environment = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        if environment == "production" {
            span.record("result", &"production_disabled");
            return Err(AuthServiceError::configuration(
                "Debug endpoints disabled in production",
            ));
        }

        span.record("result", &"success");
        Ok(())
    })
}

/// Removes a test user from the database
///
/// This endpoint allows test suites to clean up after tests by removing
/// test users from the database.
///
/// # Request Body
///
/// ```json
/// {
///   "username": "test_user",
///   "test_secret": "your_test_secret"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - User was successfully deleted or didn't exist
/// * `400 Bad Request` - Invalid test secret
/// * `500 Internal Server Error` - Database error
async fn clean_test_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = business_operation_span("clean_test_user");
    span.record("username", &payload.username);
    
    let span_clone = span.clone();
    
    async move {
        verify_test_secret(&payload.test_secret)?;

        let username = payload.username.clone();
        Log::event(
            "INFO",
            "Debug Operations",
            &format!("Cleaning test user: {}", username),
            "clean_user_attempt",
            "clean_test_user",
        );

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
        span.record("deleted_count", &(deleted as i64));

        Log::event(
            "INFO",
            "Debug Operations",
            &format!("Successfully deleted {} user(s) with username: {}", deleted, username),
            "clean_user_success",
            "clean_test_user",
        );

        Ok(Json(json!({
            "status": "success",
            "message": "User deleted successfully",
            "deleted": deleted
        })))
    }
    .instrument(span_clone)
    .await
}

/// Resets rate limiter keys in Redis
///
/// This endpoint allows test suites to reset rate limiting between tests,
/// ensuring that rate limits from one test don't affect subsequent tests.
///
/// # Request Body
///
/// ```json
/// {
///   "test_secret": "your_test_secret"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - Rate limiter was reset successfully
/// * `400 Bad Request` - Invalid test secret
/// * `500 Internal Server Error` - Redis error
async fn reset_rate_limiter(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = business_operation_span("reset_rate_limiter");
    let span_clone = span.clone();
    
    async move {
        verify_test_secret(&payload.test_secret)?;

        Log::event(
            "INFO",
            "Debug Operations",
            "Resetting rate limiter keys in Redis",
            "reset_rate_limiter_attempt",
            "reset_rate_limiter",
        );

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
            Log::event(
                "DEBUG",
                "Debug Operations",
                &format!("Searching for rate limit keys with pattern: {}", pattern),
                "rate_limiter_search",
                "reset_rate_limiter",
            );

            let keys: Vec<String> = redis::cmd("KEYS").arg(pattern).query_async(&mut conn).await?;

            if !keys.is_empty() {
                Log::event(
                    "DEBUG",
                    "Debug Operations",
                    &format!("Found {} keys with pattern: {}", keys.len(), pattern),
                    "rate_limiter_keys_found",
                    "reset_rate_limiter",
                );

                let deleted: i64 = redis::cmd("DEL").arg(&keys).query_async(&mut conn).await?;
                total_deleted += deleted as usize;

                Log::event(
                    "INFO",
                    "Debug Operations",
                    &format!(
                        "Deleted {} rate limit keys with pattern {}",
                        deleted,
                        pattern
                    ),
                    "rate_limiter_keys_deleted",
                    "reset_rate_limiter",
                );
            }
        }

        span.record("deleted_count", &(total_deleted as i64));

        Log::event(
            "INFO",
            "Debug Operations",
            &format!("Reset rate limiter completed, deleted {} keys", total_deleted),
            "reset_rate_limiter_success",
            "reset_rate_limiter",
        );

        Ok(Json(json!({
            "status": "success",
            "message": format!("Rate limiter reset successfully, deleted {} keys", total_deleted)
        })))
    }
    .instrument(span_clone)
    .await
}

/// Activates a user account for testing
///
/// This endpoint allows test suites to activate user accounts without
/// going through the email verification flow.
///
/// # Request Body
///
/// ```json
/// {
///   "username": "test_user",
///   "test_secret": "your_test_secret"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - Account was activated successfully
/// * `400 Bad Request` - Invalid test secret or user not found
/// * `500 Internal Server Error` - Database error
async fn activate_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = business_operation_span("activate_test_account");
    span.record("username", &payload.username);
    
    let span_clone = span.clone();
    
    async move {
        verify_test_secret(&payload.test_secret)?;

        let username = payload.username.clone();
        Log::event(
            "INFO",
            "Debug Operations",
            &format!("Activating test account: {}", username),
            "activate_account_attempt",
            "activate_account",
        );

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
        span.record("updated_count", &(updated as i64));

        if updated > 0 {
            Log::event(
                "INFO",
                "Debug Operations",
                &format!("Successfully activated account for: {}", username),
                "activate_account_success",
                "activate_account",
            );
            
            Ok(Json(json!({
                "status": "success",
                "message": "Account activated successfully"
            })))
        } else {
            span.record("result", &"user_not_found");
            
            Log::event(
                "WARN",
                "Debug Operations",
                &format!("Account activation failed: user not found: {}", username),
                "activate_account_not_found",
                "activate_account",
            );
            
            Err(AuthServiceError::validation("username", "User not found"))
        }
    }
    .instrument(span_clone)
    .await
}

/// Verifies user account details
///
/// This endpoint allows test suites to check if a user exists and
/// retrieve details about their account status.
///
/// # Request Body
///
/// ```json
/// {
///   "username": "test_user",
///   "test_secret": "your_test_secret"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - User found, details included in response
/// * `400 Bad Request` - Invalid test secret
/// * `404 Not Found` - User not found
/// * `500 Internal Server Error` - Database error
async fn verify_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = business_operation_span("verify_test_user");
    span.record("username", &payload.username);
    
    let span_clone = span.clone();
    
    async move {
        verify_test_secret(&payload.test_secret)?;

        Log::event(
            "INFO",
            "Debug Operations",
            &format!("Verifying user status: {}", payload.username),
            "verify_user_attempt",
            "verify_user",
        );

        let username = payload.username.clone();
        let state_clone = Arc::clone(&state);

        let result = tokio::task::spawn_blocking(move || -> Result<User, AuthServiceError> {
            use crate::db::schema::users::dsl;

            let mut conn = state_clone.pool.get()?;

            dsl::users
                .filter(dsl::username.eq(username))
                .first::<User>(&mut conn)
                .map_err(AuthServiceError::from)
        })
        .await
        .map_err(|_| AuthServiceError::configuration("Task execution error"))?;

        let user = result?;
        
        span.record("user_id", &user.id);
        span.record("is_active", &user.is_active);
        span.record("result", &"success");

        Log::event(
            "INFO",
            "Debug Operations",
            &format!(
                "Successfully verified user: {} (ID: {}, Active: {})",
                user.username, user.id, user.is_active
            ),
            "verify_user_success",
            "verify_user",
        );

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
    .instrument(span_clone)
    .await
}

/// Creates a password reset token for testing
///
/// This endpoint allows test suites to create password reset tokens
/// without going through the email sending flow.
///
/// # Request Body
///
/// ```json
/// {
///   "email": "test@example.com",
///   "test_secret": "your_test_secret"
/// }
/// ```
///
/// # Responses
///
/// * `200 OK` - Token created successfully, included in response
/// * `400 Bad Request` - Invalid test secret
/// * `404 Not Found` - User not found
/// * `500 Internal Server Error` - Database or Redis error
async fn create_reset_token(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<TestEmailRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = business_operation_span("create_test_reset_token");
    span.record(
        "email_domain", 
        &payload.email.split('@').nth(1).unwrap_or("invalid")
    );
    
    let span_clone = span.clone();
    
    async move {
        verify_test_secret(&payload.test_secret)?;

        Log::event(
            "INFO",
            "Debug Operations",
            &format!(
                "Creating password reset token for testing: {}",
                payload.email
            ),
            "create_reset_token_attempt",
            "create_reset_token",
        );

        let redis_client = app_state
            .redis_client
            .as_ref()
            .ok_or_else(|| AuthServiceError::configuration("Redis unavailable for token creation"))?;

        let mut conn = app_state.pool.get()?;

        // First verify the user exists
        let user = User::find_by_email(&mut conn, &payload.email)?;
        span.record("user_id", &user.id);

        // Generate a secure token
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

        // Store token in Redis with expiration
        let _: () = redis::cmd("SET")
            .arg(&token_key)
            .arg(&payload.email)
            .arg("EX")
            .arg(token_ttl)
            .query_async(&mut redis_conn)
            .await?;

        span.record("token_length", &token.len());
        span.record("ttl_seconds", &token_ttl);
        span.record("result", &"success");

        Log::event(
            "INFO",
            "Debug Operations",
            &format!(
                "Successfully created reset token for {} (expires in 30 minutes)",
                payload.email
            ),
            "create_reset_token_success",
            "create_reset_token",
        );

        Ok(Json(json!({
            "status": "success",
            "message": "Password reset token created",
            "token": token,
            "expires_in_seconds": token_ttl
        })))
    }
    .instrument(span_clone)
    .await
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