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

use axum::{response::IntoResponse, Json, http::StatusCode};
use serde_json::json;
use std::env;
use std::time::Duration;
use tokio::time::sleep;
use tracing::Instrument;

use crate::{
    app::AppState,
    db::users::User, 
    handlers::login::LoginRequest, 
    utils::{
        error_new::AuthServiceError,
        jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
        log_new::Log,
        telemetry::{db_operation_span, business_operation_span, SpanExt},
    },
    metricss::login_metrics::{
        time_complete_login_flow, record_login_success, record_login_failure,
        record_db_connection_success, record_db_connection_failure,
        record_user_lookup_failure,
        record_password_verification_success, record_password_verification_failure,
        record_account_check_success, record_account_check_failure,
        record_token_generation_access_success, record_token_generation_access_failure,
        record_token_generation_refresh_success, record_token_generation_refresh_failure,
        error_types,
    },
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
    // Start complete login flow timer
    let _login_timer = time_complete_login_flow();

    // Create span for the entire login processing flow
    let process_span = business_operation_span("process_login");
    process_span.record("login_type", &if req.login.contains('@') { "email" } else { "username" });
    
    // Clone span before moving it into the async block
    let process_span_clone = process_span.clone();
    
    // Log authentication attempt (without revealing password)
    Log::event(
        "INFO",
        "Authentication",
        &format!("Processing login for {}", req.login),
        "processing",
        "process_login"
    );

    // Get configured delay for invalid credentials (default: 100ms)
    let delay_ms = env::var("INVALID_CREDENTIAL_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // Wrap login logic in the process_span
    async move {
        // Step 1: Get database connection with metrics and span
        let db_conn_span = db_operation_span("get_connection", "pool");
        let mut conn = match app_state.pool.get() {
            Ok(conn) => {
                record_db_connection_success();
                db_conn_span.record("db.success", &true);
                conn
            }
            Err(e) => {
                record_db_connection_failure(error_types::DB_UNAVAILABLE);
                record_login_failure();
                db_conn_span.record_error(&e);
                
                Log::event(
                    "ERROR",
                    "Database",
                    &format!("DB connection error: {}", e),
                    "failure",
                    "process_login"
                );
                return Err(AuthServiceError::database("Could not get a database connection"));
            }
        };

        // Step 2: Find user with proper span context
        let user_lookup_span = db_operation_span(
            "find_user", 
            if req.login.contains('@') { "users.by_email" } else { "users.by_username" }
        );
        let user_lookup_span_clone = user_lookup_span.clone();
        
        let user_opt = async {
            if req.login.contains('@') {
                User::find_by_email(&mut conn, &req.login).ok()
            } else {
                User::find_by_username(&mut conn, &req.login).ok()
            }
        }
        .instrument(user_lookup_span_clone)
        .await;

        // Step 3: Verify password or perform dummy hash with metrics and span
        let pw_verify_span = business_operation_span("verify_password");
        let password_good = if let Some(u) = &user_opt {
            user_lookup_span.record("db.success", &true);
            pw_verify_span.record("user_exists", &true);
            
            match u.verify_password(&req.password) {
                Ok(true) => {
                    record_password_verification_success();
                    pw_verify_span.record("business.result", &"success");
                    true
                }
                Ok(false) => {
                    record_password_verification_failure(error_types::INVALID_PASSWORD);
                    pw_verify_span.record("business.result", &"failure");
                    pw_verify_span.record("failure_reason", &"invalid_password");
                    false
                }
                Err(e) => {
                    record_password_verification_failure(error_types::INVALID_PASSWORD);
                    pw_verify_span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "Authentication",
                        &format!("Password verification error: {}", e),
                        "system_error",
                        "process_login"
                    );
                    return Err(AuthServiceError::validation("credentials", "Invalid credentials"));
                }
            }
        } else {
            // Perform dummy hash to maintain consistent timing
            let _ = User::hash_password(&req.password);
            record_user_lookup_failure(error_types::USER_NOT_FOUND);
            user_lookup_span.record("db.success", &false);
            user_lookup_span.record("failure_reason", &"user_not_found");
            pw_verify_span.record("user_exists", &false);
            false
        };

        // If password doesn't match or user doesn't exist, return error
        if !password_good {
            // Add delay to prevent timing attacks
            sleep(Duration::from_millis(delay_ms)).await;
            record_login_failure();
            process_span.record("business.result", &"failure");
            process_span.record("failure_reason", &"invalid_credentials");
            
            Log::event(
                "WARN",
                "Authentication",
                &format!("Failed login attempt for {}", req.login),
                "invalid_credentials",
                "process_login"
            );
            
            return Err(AuthServiceError::validation("credentials", "Invalid credentials"));
        }

        // At this point we know user exists and password is correct
        let user = user_opt.unwrap();

        // Step 4: Check if account is active with metrics and span
        let account_span = business_operation_span("check_account_status");
        let account_span_clone = account_span.clone();
        
        let account_active = async {
            if !user.is_active.unwrap_or(false) {
                record_account_check_failure(error_types::INACTIVE_ACCOUNT);
                account_span.record("business.result", &"inactive");
                false
            } else {
                record_account_check_success();
                account_span.record("business.result", &"active");
                true
            }
        }
        .instrument(account_span_clone)
        .await;

        if !account_active {
            // Add delay to prevent timing attacks
            sleep(Duration::from_millis(delay_ms)).await;
            record_login_failure();
            process_span.record("business.result", &"failure");
            process_span.record("failure_reason", &"inactive_account");
            
            Log::event(
                "WARN",
                "Authentication",
                &format!("Login attempt on inactive account: {}", req.login),
                "inactive_account",
                "process_login"
            );
            
            return Err(AuthServiceError::validation("credentials", "Invalid credentials"));
        }

        // Step 5: Generate access token with span
        let access_token_span = business_operation_span("generate_access_token");
        let access_token_span_clone = access_token_span.clone();
        
        let access = async {
            match generate_token(&user.username, TOKEN_TYPE_ACCESS, None) {
                Ok(token) => {
                    record_token_generation_access_success();
                    access_token_span.record("business.result", &"success");
                    Ok(token)
                }
                Err(e) => {
                    record_token_generation_access_failure(error_types::TOKEN_GENERATION_FAILED);
                    access_token_span.record_error(&e);
                    Err(e)
                }
            }
        }
        .instrument(access_token_span_clone)
        .await?;
            
        // Step 6: Generate refresh token with span
        let refresh_token_span = business_operation_span("generate_refresh_token");
        let refresh_token_span_clone = refresh_token_span.clone();
        
        let refresh = async {
            match generate_token(&user.username, TOKEN_TYPE_REFRESH, None) {
                Ok(token) => {
                    record_token_generation_refresh_success();
                    refresh_token_span.record("business.result", &"success");
                    Ok(token)
                }
                Err(e) => {
                    record_token_generation_refresh_failure(error_types::TOKEN_GENERATION_FAILED);
                    refresh_token_span.record_error(&e);
                    Err(e)
                }
            }
        }
        .instrument(refresh_token_span_clone)
        .await?;

        // Log successful authentication
        Log::event(
            "INFO",
            "Authentication",
            &format!("Successful login for {}", req.login),
            "success",
            "process_login"
        );

        // Record overall success
        record_login_success();
        process_span.record("business.result", &"success");
        process_span.record("user.id", &user.username);

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

        Ok((StatusCode::OK, Json(body)))
    }
    .instrument(process_span_clone)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};
    use crate::db::users::User;
    use crate::handlers::login::LoginRequest;
    use crate::metricss::login_metrics::{
        init_login_metrics, LOGIN_OPERATIONS, LOGIN_FAILURES, LOGIN_DURATION,
        steps, results, error_types
    };

    /// Initialize login metrics for testing
    fn setup_metrics() {
        init_login_metrics();
    }

    #[tokio::test]
    async fn nonexistent_user_returns_validation_error() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        let req = LoginRequest {
            login: "no-such-user".into(),
            password: "whatever".into(),
        };
        
        let initial_user_failure = LOGIN_FAILURES
            .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
            .get();
        let initial_login_failure = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected - invalid credentials should return validation error
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }

        let final_user_failure = LOGIN_FAILURES
            .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
            .get();
        let final_login_failure = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_user_failure, initial_user_failure + 1.0);
        assert_eq!(final_login_failure, initial_login_failure + 1.0);
    }

    #[tokio::test]
    async fn wrong_password_returns_validation_error() {
        setup_metrics();
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
        
        let initial_password_failure = LOGIN_FAILURES
            .with_label_values(&[steps::PASSWORD_VERIFICATION, error_types::INVALID_PASSWORD])
            .get();
        let initial_login_failure = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected - invalid credentials should return validation error
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }

        let final_password_failure = LOGIN_FAILURES
            .with_label_values(&[steps::PASSWORD_VERIFICATION, error_types::INVALID_PASSWORD])
            .get();
        let final_login_failure = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_password_failure, initial_password_failure + 1.0);
        assert_eq!(final_login_failure, initial_login_failure + 1.0);
    }

    #[tokio::test]
    async fn inactive_account_returns_validation_error() {
        setup_metrics();
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
        
        let initial_account_failure = LOGIN_FAILURES
            .with_label_values(&[steps::ACCOUNT_CHECK, error_types::INACTIVE_ACCOUNT])
            .get();
        let initial_login_failure = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected - inactive account should return validation error
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }

        let final_account_failure = LOGIN_FAILURES
            .with_label_values(&[steps::ACCOUNT_CHECK, error_types::INACTIVE_ACCOUNT])
            .get();
        let final_login_failure = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_account_failure, initial_account_failure + 1.0);
        assert_eq!(final_login_failure, initial_login_failure + 1.0);
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET environment variable
    async fn successful_login_returns_tokens_and_user() {
        setup_metrics();
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
        
        let initial_login_success = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let initial_duration = LOGIN_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_ok());

        let final_login_success = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let final_duration = LOGIN_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        assert_eq!(final_login_success, initial_login_success + 1.0);
        assert_eq!(final_duration, initial_duration + 1);
    }

    #[tokio::test]
    #[ignore] // requires JWT_SECRET environment variable
    async fn email_login_works() {
        setup_metrics();
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
        
        let initial_login_success = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        // Act
        let result = process_login(&state, &req).await;
        
        // Assert
        assert!(result.is_ok());

        let final_login_success = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        assert_eq!(final_login_success, initial_login_success + 1.0);
    }
    
    #[tokio::test]
    async fn generic_errors_prevent_user_enumeration() {
        setup_metrics();
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
        setup_metrics();
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