//! User login business logic.
//!
//! Implements secure authentication with JWT token generation,
//! rate limiting, and comprehensive observability.

use crate::{
    app::AppState,
    db::users::User,
    utils::{
        errors::AuthServiceError,
        jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
        metrics,  // Fixed: correct import path
        validators::{validate_email, validate_username},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{error, info, span, warn, Instrument, Level};

/// Maximum login attempts before rate limiting.
const MAX_LOGIN_ATTEMPTS: usize = 5;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: usize = 900; // 15 minutes

/// Process user login request.
///
/// # Flow
/// 1. Validate input format (email OR username)
/// 2. Check rate limiting (if Redis available)
/// 3. Find user by email or username
/// 4. Verify password
/// 5. Check account status
/// 6. Generate JWT tokens
/// 7. Return tokens
///
/// # Security
/// - Rate limiting to prevent brute force
/// - Constant-time password comparison
/// - Account status verification
/// - Secure token generation
/// - Supports both email and username login
pub async fn process_login(
    app_state: &AppState,
    login: &str,  // Changed parameter name to be more generic
    password: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create root span for the operation
    let login_type = if login.contains('@') { "email" } else { "username" };
    let span = span!(Level::INFO, "user_login",
        login_type = login_type,
        domain = login.split('@').nth(1).unwrap_or("n/a")
    );
    let span_for_instrument = span.clone();
    
    async move {
        info!("Starting login process with {}", login_type);

        // ===== 1. INPUT VALIDATION =====
        // Validate based on whether it's an email or username
        if login.contains('@') {
            // It's an email, validate email format
            validate_email(login).map_err(|e| {
                warn!("Invalid email format: {}", e);
                metrics::auth::login_failure();
                AuthServiceError::validation("login", "Invalid email format")
            })?;
        } else {
            // It's a username, validate username format
            validate_username(login).map_err(|e| {
                warn!("Invalid username format: {}", e);
                metrics::auth::login_failure();
                AuthServiceError::validation("login", "Invalid username format")
            })?;
        }

        if password.is_empty() {
            warn!("Empty password provided");
            metrics::auth::login_failure();
            return Err(AuthServiceError::validation("password", "Password is required"));
        }

        // ===== 2. RATE LIMITING (BEST EFFORT) =====
        if let Some(redis_client) = &app_state.redis_client {
            let rate_limit_span = span!(Level::INFO, "rate_limit_check");
            let should_continue = async {
                check_rate_limit(redis_client, login).await
            }
            .instrument(rate_limit_span)
            .await;

            if !should_continue {
                warn!("Login rate limit exceeded for {}", login_type);
                metrics::auth::login_failure();
                return Err(AuthServiceError::validation(
                    "rate_limit",
                    "Too many login attempts. Please try again in 15 minutes."
                ));
            }
        }

        // ===== 3. USER LOOKUP =====
        let db_span = span!(Level::INFO, "db_lookup");
        let user = async {
            let mut conn = app_state.pool.get().map_err(|e| {
                error!("Failed to get database connection: {}", e);
                metrics::db::connection_failed();
                AuthServiceError::database("Failed to get database connection")
            })?;
            metrics::db::connection_acquired();

            // Try to find user by email or username based on login format
            let user_result = if login.contains('@') {
                User::find_by_email(&mut conn, login)
            } else {
                User::find_by_username(&mut conn, login)
            };

            user_result.map_err(|_| {
                info!("User not found or database error for {}", login_type);
                metrics::db::query_failure(&format!("find_user_by_{}", login_type));
                
                // Record failed attempt if Redis available
                if let Some(redis) = &app_state.redis_client {
                    tokio::spawn(record_failed_attempt(redis.clone(), login.to_string()));
                }
                
                metrics::auth::login_failure();
                // Return a generic validation error to prevent user enumeration
                AuthServiceError::validation("credentials", "Invalid email or password")
            })
        }
        .instrument(db_span)
        .await?;
        
        metrics::db::query_success(&format!("find_user_by_{}", login_type));
        span.record("user_id", &user.id.to_string());
        info!(user_id = %user.id, "User found");

        // ===== 4. PASSWORD VERIFICATION =====
        let password_span = span!(Level::INFO, "password_verification");
        async {
            // verify_password returns Result<bool, AuthServiceError>
            let is_valid = user.verify_password(password).map_err(|e| {
                error!(user_id = %user.id, "Password verification failed: {}", e);
                metrics::auth::login_failure();
                AuthServiceError::validation("credentials", "Invalid email or password")
            })?;

            if !is_valid {
                warn!(user_id = %user.id, "Invalid password");
                
                // Record failed attempt if Redis available
                if let Some(redis) = &app_state.redis_client {
                    tokio::spawn(record_failed_attempt(redis.clone(), login.to_string()));
                }
                
                metrics::auth::login_failure();
                return Err(AuthServiceError::validation("credentials", "Invalid email or password"));
            }
            
            info!(user_id = %user.id, "Password verified");
            Ok::<_, AuthServiceError>(())
        }
        .instrument(password_span)
        .await?;

        // ===== 5. ACCOUNT STATUS CHECK =====
        if !user.is_active {
            warn!(user_id = %user.id, "Login attempt for inactive account");
            metrics::auth::login_failure();
            return Err(AuthServiceError::validation(
                "account",
                "Account is not activated. Please check your email for activation instructions."
            ));
        }

        // ===== 6. GENERATE TOKENS =====
        let token_span = span!(Level::INFO, "token_generation");
        let (access_token, refresh_token) = async {
            let access = generate_token(&user.username, TOKEN_TYPE_ACCESS, None).map_err(|e| {
                error!(user_id = %user.id, "Failed to generate access token: {}", e);
                AuthServiceError::configuration("Failed to generate access token")
            })?;

            let refresh = generate_token(&user.username, TOKEN_TYPE_REFRESH, None).map_err(|e| {
                error!(user_id = %user.id, "Failed to generate refresh token: {}", e);
                AuthServiceError::configuration("Failed to generate refresh token")
            })?;

            info!(user_id = %user.id, "Tokens generated successfully");
            Ok::<_, AuthServiceError>((access, refresh))
        }
        .instrument(token_span)
        .await?;

        // ===== 7. CLEAR RATE LIMIT ON SUCCESS =====
        if let Some(redis_client) = &app_state.redis_client {
            tokio::spawn(clear_failed_attempts(redis_client.clone(), login.to_string()));
        }

        // ===== 8. SUCCESS RESPONSE =====
        metrics::auth::login_success();
        info!(user_id = %user.id, "Login successful");

        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Login successful",
                "data": {
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                    },
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "Bearer"
                    }
                }
            })),
        ))
    }
    .instrument(span_for_instrument)
    .await
}

/// Check rate limit for login attempts.
async fn check_rate_limit(redis_client: &redis::Client, login: &str) -> bool {
    let key = format!("login_attempts:{}", login_hash(login));
    
    let mut conn = match redis_client.get_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to connect to Redis for rate limiting: {}", e);
            return true; // Allow login if Redis is down
        }
    };

    use redis::AsyncCommands;
    let attempts: Option<usize> = conn.get(&key).await.unwrap_or(None);
    
    if let Some(count) = attempts {
        if count >= MAX_LOGIN_ATTEMPTS {
            metrics::external::redis_success("rate_limit_check");
            return false;
        }
    }
    
    true
}

/// Record failed login attempt.
async fn record_failed_attempt(redis_client: redis::Client, login: String) {
    let key = format!("login_attempts:{}", login_hash(&login));
    
    let mut conn = match redis_client.get_async_connection().await {
        Ok(c) => c,
        Err(_) => return, // Ignore Redis errors
    };

    use redis::AsyncCommands;
    let _: Result<(), _> = conn.incr(&key, 1).await;
    let _: Result<(), _> = conn.expire(&key, RATE_LIMIT_WINDOW_SECS).await;
    
    metrics::external::redis_success("record_failed_attempt");
}

/// Clear failed login attempts after successful login.
async fn clear_failed_attempts(redis_client: redis::Client, login: String) {
    let key = format!("login_attempts:{}", login_hash(&login));
    
    let mut conn = match redis_client.get_async_connection().await {
        Ok(c) => c,
        Err(_) => return, // Ignore Redis errors
    };

    use redis::AsyncCommands;
    let _: Result<(), _> = conn.del(&key).await;
    
    metrics::external::redis_success("clear_failed_attempts");
}

/// Hash login for rate limiting (privacy-preserving).
#[inline]
fn login_hash(login: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    login.to_lowercase().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{state_no_redis, state_with_redis};

    fn create_test_user(app_state: &AppState) -> User {
        let mut conn = app_state.pool.get().unwrap();
        let new_user = User::new_for_insert("testuser", "test@example.com", "TestPass123!");
        let mut user = User::save_new(new_user, &mut conn).unwrap();
        user.is_active = true; // Activate for testing
        user.update(&mut conn).unwrap();
        user
    }

    #[tokio::test]
    async fn test_invalid_email_format() {
        let state = state_with_redis();
        let result = process_login(&state, "not-an-email", "password").await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_empty_password() {
        let state = state_with_redis();
        let result = process_login(&state, "test@example.com", "").await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let state = state_with_redis();
        let result = process_login(&state, "nonexistent@example.com", "password").await;
        // Should return validation error to prevent user enumeration
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_invalid_password() {
        let state = state_with_redis();
        create_test_user(&state);
        let result = process_login(&state, "test@example.com", "WrongPassword").await;
        // Should return validation error to prevent user enumeration
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_inactive_account() {
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        let new_user = User::new_for_insert("inactive", "inactive@example.com", "TestPass123!");
        User::save_new(new_user, &mut conn).unwrap();
        // Don't activate the user
        
        let result = process_login(&state, "inactive@example.com", "TestPass123!").await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_successful_login() {
        let state = state_with_redis();
        create_test_user(&state);
        
        let result = process_login(&state, "test@example.com", "TestPass123!").await;
        assert!(result.is_ok());
        
        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_without_redis() {
        let state = state_no_redis();
        let mut conn = state.pool.get().unwrap();
        let new_user = User::new_for_insert("noredis", "noredis@example.com", "TestPass123!");
        let mut user = User::save_new(new_user, &mut conn).unwrap();
        user.is_active = true;
        user.update(&mut conn).unwrap();
        
        // Should still work without Redis
        let result = process_login(&state, "noredis@example.com", "TestPass123!").await;
        assert!(result.is_ok());
    }
}