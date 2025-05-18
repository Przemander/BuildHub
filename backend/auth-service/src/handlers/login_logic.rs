//! Business logic for user authentication.
//!
//! This module implements a secure authentication flow with:
//! - Username or email-based authentication
//! - Secure password verification using constant-time comparison
//! - Protection against timing attacks with consistent response delays
//! - JWT token generation for both access and refresh tokens
//! - Comprehensive metrics and structured logging
//! - Rate-limiting compatibility (enforced at middleware level)

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
    log_error, log_info, 
    utils::{
        errors::ApiError, 
        jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH}, 
        metrics::RequestTimer
    }
};

/// Processes a login request. Assumes lockout and rate limiting are enforced by middleware.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `req` - Login request containing username/email and password
///
/// # Returns
///
/// On success, returns a tuple of `(StatusCode, JSON body)` with authentication tokens
/// On failure, returns an `ApiError` with appropriate status code and message
///
/// # Flow
///
/// 1. Look up the user by username or email
/// 2. Verify the password (or perform dummy hash if user not found)
/// 3. Check if the account is active
/// 4. Generate access and refresh tokens
/// 5. Return tokens with user information
///
/// # Security Features
///
/// - Constant-time password comparison to prevent timing attacks
/// - Consistent response timing regardless of error type
/// - Dummy password hashing for non-existent users
/// - Generic error messages that don't leak user existence
pub async fn process_login(
    pool: &DbPool,
    req: &LoginRequest,
) -> Result<(StatusCode, Value), ApiError> {
    // Start the request timer for metrics
    let mut timer = RequestTimer::start("/auth/login", "POST");

    // Log authentication attempt (without revealing password)
    log_info!("Auth", &format!("Login attempt for {}", req.login), "attempt");

    // Get configured delay for invalid credentials (default: 100ms)
    // This helps prevent timing attacks by keeping response time consistent
    let delay_ms = env::var("INVALID_CREDENTIAL_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // Step 1: Get database connection and look up user
    let mut conn = pool
        .get()
        .map_err(|e| {
            log_error!("Auth", &format!("DB error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            timer.set_status("500"); // Set status for system error
            ApiError::internal("Database connection error")
        })?;

    // Try to find user by email if login contains @, otherwise by username
    let user_opt = if req.login.contains('@') {
        User::find_by_email(&mut conn, &req.login).ok()
    } else {
        User::find_by_username(&mut conn, &req.login).ok()
    };

    // Step 2: Verify password or perform dummy hash
    // We always perform a hash operation whether user exists or not
    // to prevent timing attacks that could reveal user existence
    let password_good = if let Some(u) = &user_opt {
        u.verify_password(&req.password).unwrap_or(false)
    } else {
        // Perform dummy hash to maintain consistent timing
        let _ = User::hash_password(&req.password);
        false
    };

    // If password doesn't match or user doesn't exist, return error
    if !password_good {
        // Add delay to prevent timing attacks
        sleep(Duration::from_millis(delay_ms)).await;
        log_error!("Auth", &format!("Bad password for {}", req.login), "failure");
        counter!("auth_login_attempts_total", 1, "result" => "failure");
        timer.set_status("401"); // Set status for unauthorized
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    // At this point we know user exists and password is correct
    let user = user_opt.unwrap();

    // Step 3: Check if account is active
    if !user.is_active.unwrap_or(false) {
        // Add delay to prevent timing attacks
        sleep(Duration::from_millis(delay_ms)).await;
        log_error!("Auth", &format!("Inactive account for {}", req.login), "inactive");
        counter!("auth_login_attempts_total", 1, "result" => "inactive");
        timer.set_status("401"); // Set status for unauthorized
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    // Step 4: Generate access and refresh JWTs
    let access = generate_token(&user.username, TOKEN_TYPE_ACCESS, None)
        .map_err(|e| {
            log_error!("Auth", &format!("Token error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            timer.set_status("500"); // Set status for system error
            ApiError::internal("Token generation error")
        })?;
        
    let refresh = generate_token(&user.username, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            log_error!("Auth", &format!("Token error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            timer.set_status("500"); // Set status for system error
            ApiError::internal("Token generation error")
        })?;

    // Log successful authentication
    log_info!("Auth", &format!("Login success for {}", req.login), "success");
    counter!("auth_login_attempts_total", 1, "result" => "success");

    // Build OAuth2-compatible response with tokens and user info
    let body = json!({
        "status": "success",
        "message": "Authentication successful",
        "data": {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "username": user.username,
            "email": user.email
        }
    });

    // Record metrics and return success response
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
    use crate::utils::errors::ApiStatus;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn nonexistent_user_returns_unauthorized() {
        // Arrange
        init_jwt_secret();
        let pool = make_pool();
        let req = LoginRequest {
            login: "no-such-user".into(),
            password: "whatever".into(),
        };
        
        // Act
        let result = process_login(&pool, &req).await;
        
        // Assert
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, ApiStatus::Unauthorized);
        assert_eq!(err.message, "Invalid credentials");
    }

    #[tokio::test]
    async fn wrong_password_returns_unauthorized() {
        // Arrange
        init_jwt_secret();
        let pool = make_pool();
        let mut conn = pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("carol", "carol@example.com", "C@rol123!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        // Try with wrong password
        let req = LoginRequest {
            login: "carol".into(),
            password: "wrong-password".into(),
        };
        
        // Act
        let result = process_login(&pool, &req).await;
        
        // Assert
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, ApiStatus::Unauthorized);
        assert_eq!(err.message, "Invalid credentials");
    }

    #[tokio::test]
    async fn inactive_account_returns_unauthorized() {
        // Arrange
        init_jwt_secret();
        let pool = make_pool();
        let mut conn = pool.get().unwrap();
        
        // Create inactive user
        let mut user = User::new("bob", "bob@example.com", "B0bSecret!");
        user.is_active = Some(false);
        user.save(&mut conn).unwrap();

        let req = LoginRequest {
            login: "bob".into(),
            password: "B0bSecret!".into(),
        };
        
        // Act
        let result = process_login(&pool, &req).await;
        
        // Assert
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, ApiStatus::Unauthorized);
        assert_eq!(err.message, "Invalid credentials");
    }

    #[tokio::test]
    async fn successful_login_returns_tokens_and_user() {
        // Arrange
        init_jwt_secret();
        let pool = make_pool();
        let mut conn = pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("alice", "alice@example.com", "Al1cePwd!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();

        let req = LoginRequest {
            login: "alice".into(),
            password: "Al1cePwd!".into(),
        };
        
        // Act
        let result = process_login(&pool, &req).await;
        
        // Assert
        assert!(result.is_ok());
        let (status, body) = result.unwrap();
        
        // Verify response structure
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "success");
        
        // Verify tokens exist and are non-empty
        let access = body["data"]["access_token"].as_str().unwrap();
        let refresh = body["data"]["refresh_token"].as_str().unwrap();
        assert!(!access.is_empty(), "Access token should not be empty");
        assert!(!refresh.is_empty(), "Refresh token should not be empty");
        
        // Verify user data is correct
        assert_eq!(body["data"]["username"], "alice");
        assert_eq!(body["data"]["email"], "alice@example.com");
        assert_eq!(body["data"]["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn login_with_email_works() {
        // Arrange
        init_jwt_secret();
        let pool = make_pool();
        let mut conn = pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("dave", "dave@example.com", "D@ve456!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();

        // Login with email instead of username
        let req = LoginRequest {
            login: "dave@example.com".into(), // Using email
            password: "D@ve456!".into(),
        };
        
        // Act
        let result = process_login(&pool, &req).await;
        
        // Assert
        assert!(result.is_ok());
        let (status, body) = result.unwrap();
        
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["username"], "dave");
        assert_eq!(body["data"]["email"], "dave@example.com");
    }
    
    #[tokio::test]
    async fn generic_errors_prevent_user_enumeration() {
        // Arrange
        init_jwt_secret();
        let pool = make_pool();
        
        // Create two requests - one for nonexistent user, one for wrong password
        let req1 = LoginRequest {
            login: "nonexistent".into(),
            password: "whatever".into(),
        };
        
        let mut conn = pool.get().unwrap();
        let mut user = User::new("eve", "eve@example.com", "Ev3Secret!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        let req2 = LoginRequest {
            login: "eve".into(),
            password: "wrong-password".into(),
        };
        
        // Act
        let err1 = process_login(&pool, &req1).await.unwrap_err();
        let err2 = process_login(&pool, &req2).await.unwrap_err();
        
        // Assert - both errors should be identical to prevent user enumeration
        assert_eq!(err1.message, err2.message);
        assert_eq!(err1.status, err2.status);
    }
}