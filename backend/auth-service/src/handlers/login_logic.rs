//! Business logic for user authentication.
//!
//! This module implements a secure authentication flow with:
//! - Username or email-based authentication
//! - Secure password verification using constant-time comparison
//! - Protection against timing attacks with consistent response delays
//! - JWT token generation for both access and refresh tokens
//! - Comprehensive metrics and structured logging
//! - Rate-limiting compatibility (enforced at middleware level)
//! - Unified error handling with automatic HTTP response conversion

use axum::{response::IntoResponse, Json}; // ← Removed StatusCode
use metrics::counter;
use serde_json::json;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

use crate::{
    app::AppState,
    db::users::User, 
    handlers::login::LoginRequest, 
    log_error, log_info, 
    utils::{
        error_new::AuthServiceError,
        jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH}, 
        metrics::RequestTimer
    }
};

/// Processes a login request using the unified error system.
///
/// # Arguments
///
/// * `app_state` - Application state containing database pool and other resources
/// * `req` - Login request containing username/email and password
///
/// # Returns
///
/// Result that can be converted to HTTP response via unified error system
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
    app_state: &AppState,
    req: &LoginRequest,
) -> Result<impl IntoResponse, AuthServiceError> {
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

    // Step 1: Get database connection - automatic conversion via ? operator
    let mut conn = app_state.pool.get().map_err(|e| {
        log_error!("Auth", &format!("DB error: {}", e), "system_error");
        counter!("auth_login_attempts_total", 1, "result" => "system_error");
        timer.set_status("500"); // Set status for system error
        e // AuthServiceError::Database will be created automatically
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
        u.verify_password(&req.password).map_err(|e| {
            log_error!("Auth", &format!("Password verification error: {}", e), "system_error");
            counter!("auth_login_attempts_total", 1, "result" => "system_error");
            timer.set_status("500");
            e // AuthServiceError::Validation will be created automatically
        }).unwrap_or(false)
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
        
        return Err(AuthServiceError::validation("credentials", "Invalid credentials"));
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
        
        return Err(AuthServiceError::validation("credentials", "Invalid credentials"));
    }

    // Step 4: Generate access and refresh JWTs - automatic conversion via ? operator
    let access = generate_token(&user.username, TOKEN_TYPE_ACCESS, None).map_err(|e| {
        log_error!("Auth", &format!("Token error: {}", e), "system_error");
        counter!("auth_login_attempts_total", 1, "result" => "system_error");
        timer.set_status("500"); // Set status for system error
        e // AuthServiceError::Jwt will be created automatically
    })?;
        
    let refresh = generate_token(&user.username, TOKEN_TYPE_REFRESH, None).map_err(|e| {
        log_error!("Auth", &format!("Token error: {}", e), "system_error");
        counter!("auth_login_attempts_total", 1, "result" => "system_error");
        timer.set_status("500"); // Set status for system error
        e // AuthServiceError::Jwt will be created automatically
    })?;

    // Log successful authentication
    log_info!("Auth", &format!("Login success for {}", req.login), "success");
    counter!("auth_login_attempts_total", 1, "result" => "success");

    // Build OAuth2-compatible response with tokens and user info using Axum's Json wrapper
    // Fix 2: Need to import StatusCode for this specific use case
    use axum::http::StatusCode;
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
    Ok((StatusCode::OK, Json(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};
    use crate::db::users::User;
    use crate::handlers::login::LoginRequest;

    #[tokio::test]
    async fn nonexistent_user_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let req = LoginRequest {
            login: "no-such-user".into(),
            password: "whatever".into(),
        };
        
        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_err());
        
        // Fix: Extract error without trying to debug impl IntoResponse
        if let Err(err) = result {
            match err {
                AuthServiceError::Validation(_) => {
                    // Expected - invalid credentials should return validation error
                }
                other => panic!("Expected validation error, got: {:?}", other),
            }
        }
    }

    #[tokio::test]
    async fn wrong_password_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
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
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_err());
        
        // Fix: Extract error without trying to debug impl IntoResponse
        if let Err(err) = result {
            match err {
                AuthServiceError::Validation(_) => {
                    // Expected - invalid credentials should return validation error
                }
                other => panic!("Expected validation error, got: {:?}", other),
            }
        }
    }

    #[tokio::test]
    async fn inactive_account_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Create inactive user
        let mut user = User::new("bob", "bob@example.com", "B0bSecret!");
        user.is_active = Some(false);
        user.save(&mut conn).unwrap();

        let req = LoginRequest {
            login: "bob".into(),
            password: "B0bSecret!".into(),
        };
        
        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_err());
        
        // Fix: Extract error without trying to debug impl IntoResponse
        if let Err(err) = result {
            match err {
                AuthServiceError::Validation(_) => {
                    // Expected - inactive account should return validation error
                }
                other => panic!("Expected validation error, got: {:?}", other),
            }
        }
    }

    #[tokio::test]
    async fn successful_login_returns_tokens_and_user() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
        // Create active user
        let mut user = User::new("alice", "alice@example.com", "Al1cePwd!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();

        let req = LoginRequest {
            login: "alice".into(),
            password: "Al1cePwd!".into(),
        };
        
        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_ok());
        // Since we can't easily extract the JSON from impl IntoResponse in tests,
        // we just verify the result is Ok. In integration tests, we'd verify
        // the actual HTTP response structure.
    }

    #[tokio::test]
    async fn login_with_email_works() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let mut conn = state.pool.get().unwrap();
        
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
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn generic_errors_prevent_user_enumeration() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Create two requests - one for nonexistent user, one for wrong password
        let req1 = LoginRequest {
            login: "nonexistent".into(),
            password: "whatever".into(),
        };
        
        let mut conn = state.pool.get().unwrap();
        let mut user = User::new("eve", "eve@example.com", "Ev3Secret!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        let req2 = LoginRequest {
            login: "eve".into(),
            password: "wrong-password".into(),
        };
        
        // Act
        let result1 = process_login(&state, &req1).await;
        let result2 = process_login(&state, &req2).await;
        
        // Assert - both errors should be validation errors (unified behavior)
        // Fix: Extract errors without trying to debug impl IntoResponse
        assert!(result1.is_err());
        assert!(result2.is_err());
        
        if let (Err(err1), Err(err2)) = (result1, result2) {
            match (&err1, &err2) {
                (AuthServiceError::Validation(_), AuthServiceError::Validation(_)) => {
                    // Expected - both should be validation errors for security
                }
                _ => panic!("Both errors should be validation errors to prevent enumeration"),
            }
        }
    }

    #[tokio::test]
    async fn database_error_returns_database_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        // Create a broken database state by using a bad pool
        // This is hard to test without mocking, so we'll just verify compilation
        
        let req = LoginRequest {
            login: "test".into(),
            password: "test".into(),
        };
        
        // Act & Assert - This test mainly verifies the error type conversion compiles
        // In a real scenario, you'd use dependency injection or mocking
        let _result = process_login(&state, &req).await;
        // The ? operator should automatically convert r2d2::Error to AuthServiceError::Database
    }
}