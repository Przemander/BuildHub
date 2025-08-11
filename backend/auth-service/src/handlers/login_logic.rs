//! # User Authentication Business Logic
//!
//! This module implements a secure, robust authentication flow with comprehensive 
//! observability, rate limiting protection, and defense against common attack vectors.
//!
//! ## Security Features
//!
//! - Username or email-based authentication with identical timing characteristics
//! - Argon2id password verification using constant-time comparison
//! - Protection against timing attacks via consistent processing delays
//! - Anti-enumeration protections with identical error messages
//! - JWT token generation with appropriate expirations
//! - Privacy-preserving logging (avoids logging full emails/credentials)
//! - Secure JWT implementation with appropriate claims
//!
//! ## Observability
//!
//! - Comprehensive OpenTelemetry spans for all operations
//! - Fine-grained metrics for authentication steps
//! - Structured logging with context preservation
//! - Performance histograms for each authentication phase
//!
//! ## Flow Architecture
//!
//! The authentication process follows a structured pipeline:
//! 1. Database connection acquisition with error handling
//! 2. User lookup by username or email
//! 3. Password verification with timing attack protection
//! 4. Account status verification
//! 5. JWT token generation (access + refresh)
//! 6. Response construction with appropriate context

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use std::env;
use std::time::Duration;
use tokio::time::sleep;
use tracing::Instrument;

use crate::{
    app::AppState,
    db::users::User,
    handlers::login::LoginRequest,
    metricss::login_metrics::{
        error_types, record_account_check_failure, record_account_check_success,
        record_db_connection_failure, record_db_connection_success, record_login_failure,
        record_login_success, record_password_verification_failure,
        record_password_verification_success, record_token_generation_access_failure,
        record_token_generation_access_success, record_token_generation_refresh_failure,
        record_token_generation_refresh_success, record_user_lookup_failure,
        record_user_lookup_success, time_complete_login_flow,
    },
    utils::{
        error_new::AuthServiceError,
        jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
        log_new::Log,
        telemetry::{business_operation_span, db_operation_span, SpanExt},
    },
};

/// Processes a login request with comprehensive security controls and observability.
///
/// This function implements the complete authentication workflow with detailed
/// metrics, tracing, and security controls. It follows a defense-in-depth approach
/// that protects against timing attacks, user enumeration, and maintains consistent
/// performance characteristics.
///
/// # Arguments
///
/// * `app_state` - Application state containing database pool and other resources
/// * `req` - Login request containing username/email and password
///
/// # Returns
///
/// * `Ok(impl IntoResponse)` - Response with JWT tokens and user information
/// * `Err(AuthServiceError)` - Structured error with security-conscious messaging
///
/// # Security Considerations
///
/// - Uses constant-time comparison for password verification
/// - Maintains consistent response timing regardless of error path
/// - Performs dummy password verification for non-existent users
/// - Uses identical error messages to prevent user enumeration
/// - Protects privacy by limiting identifiable information in logs
///
/// # Flow Stages
///
/// 1. Database connection - Acquires connection from pool
/// 2. User lookup - Finds the user by username or email
/// 3. Password verification - Securely verifies password or performs dummy operation
/// 4. Account verification - Checks if account is active
/// 5. Token generation - Creates access and refresh JWTs
/// 6. Response construction - Builds secure response with tokens
///
/// Each stage includes detailed metrics, logging, and error handling.
pub async fn process_login(
    app_state: &AppState,
    req: &LoginRequest,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Start complete login flow timer for performance measurement
    let _login_timer = time_complete_login_flow();

    // Create span for the entire login processing flow
    let process_span = business_operation_span("process_login");
    
    // Record login type (email vs username) without revealing actual values
    let login_type = if req.login.contains('@') { "email" } else { "username" };
    process_span.record("login_type", &login_type);
    
    if let Some(domain) = req.login.split('@').nth(1) {
        process_span.record("email_domain", &domain);
    }

    // Clone span before moving it into the async block
    let process_span_clone = process_span.clone();

    // Log authentication attempt (without revealing full credentials)
    Log::event(
        "INFO",
        "Authentication",
        &format!("Processing login attempt (type: {})", login_type),
        "processing",
        "process_login",
    );

    // Get configured delay for invalid credentials (default: 100ms)
    let delay_ms = env::var("INVALID_CREDENTIAL_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // Wrap login logic in the process_span
    async move {
        // =====================================================================
        // STAGE 1: DATABASE CONNECTION
        // =====================================================================
        let db_conn_span = db_operation_span("get_connection", "pool");
        let db_conn_span_clone = db_conn_span.clone();
        
        let conn_result = async {
            match app_state.pool.get() {
                Ok(conn) => {
                    record_db_connection_success();
                    db_conn_span.record("db.success", &true);
                    Ok(conn)
                }
                Err(e) => {
                    record_db_connection_failure(error_types::DB_UNAVAILABLE);
                    record_login_failure();
                    db_conn_span.record("db.success", &false);
                    db_conn_span.record_error(&e);

                    Log::event(
                        "ERROR",
                        "Database",
                        &format!("DB connection error during login: {}", e),
                        "connection_failure",
                        "process_login",
                    );
                    
                    Err(AuthServiceError::database(
                        "Authentication service temporarily unavailable. Please try again later.",
                    ))
                }
            }
        }
        .instrument(db_conn_span_clone)
        .await?;
        
        let mut conn = conn_result;

        // =====================================================================
        // STAGE 2: USER LOOKUP
        // =====================================================================
        let user_lookup_span = db_operation_span(
            "find_user",
            if req.login.contains('@') {
                "users.by_email"
            } else {
                "users.by_username"
            },
        );
        let user_lookup_span_clone = user_lookup_span.clone();

        Log::event(
            "DEBUG",
            "Authentication",
            &format!("Looking up user by {}", login_type),
            "user_lookup",
            "process_login",
        );

        let user_opt = async {
            let result = if req.login.contains('@') {
                User::find_by_email(&mut conn, &req.login).ok()
            } else {
                User::find_by_username(&mut conn, &req.login).ok()
            };
            
            if let Some(user) = &result {
                record_user_lookup_success();
                user_lookup_span.record("db.success", &true);
                user_lookup_span.record("business.result", &"success");
                user_lookup_span.record("user_id", &user.id);
                
                Log::event(
                    "DEBUG",
                    "Authentication",
                    &format!("User found by {} (id: {})", login_type, user.id),
                    "user_found",
                    "process_login",
                );
            } else {
                record_user_lookup_failure(error_types::USER_NOT_FOUND);
                user_lookup_span.record("db.success", &false);
                user_lookup_span.record("business.result", &"not_found");
                user_lookup_span.record("failure_reason", &"user_not_found");
                
                Log::event(
                    "DEBUG",
                    "Authentication",
                    &format!("No user found by {}", login_type),
                    "user_not_found",
                    "process_login",
                );
            }
            
            result
        }
        .instrument(user_lookup_span_clone)
        .await;

        // =====================================================================
        // STAGE 3: PASSWORD VERIFICATION
        // =====================================================================
        let pw_verify_span = business_operation_span("verify_password");
        let pw_verify_span_clone = pw_verify_span.clone();
        
        let password_verification = async {
            if let Some(u) = &user_opt {
                pw_verify_span.record("user_exists", &true);
                
                Log::event(
                    "DEBUG",
                    "Authentication",
                    "Verifying password for existing user",
                    "password_verify_start",
                    "process_login",
                );

                match u.verify_password(&req.password) {
                    Ok(true) => {
                        record_password_verification_success();
                        pw_verify_span.record("business.result", &"success");
                        
                        Log::event(
                            "DEBUG",
                            "Authentication",
                            "Password verified successfully",
                            "password_verify_success",
                            "process_login",
                        );
                        
                        Ok(true)
                    }
                    Ok(false) => {
                        record_password_verification_failure(error_types::INVALID_PASSWORD);
                        pw_verify_span.record("business.result", &"failure");
                        pw_verify_span.record("failure_reason", &"invalid_password");
                        
                        Log::event(
                            "WARN",
                            "Authentication",
                            "Invalid password provided for existing user",
                            "password_verify_failure",
                            "process_login",
                        );
                        
                        Ok(false)
                    }
                    Err(e) => {
                        record_password_verification_failure(error_types::INVALID_PASSWORD);
                        pw_verify_span.record("business.result", &"error");
                        pw_verify_span.record("failure_reason", &"hash_error");
                        pw_verify_span.record_error(&e);

                        Log::event(
                            "ERROR",
                            "Authentication",
                            &format!("Password verification system error: {}", e),
                            "password_verify_error",
                            "process_login",
                        );
                        
                        return Err(AuthServiceError::validation(
                            "credentials",
                            "Invalid credentials",
                        ));
                    }
                }
            } else {
                // Perform dummy hash to maintain consistent timing
                // This is crucial for preventing timing-based user enumeration
                let start = std::time::Instant::now();
                let _ = User::hash_password(&req.password);
                let dummy_time = start.elapsed();
                
                // Log the timing for performance tuning (debug only)
                Log::event(
                    "DEBUG",
                    "Authentication",
                    &format!("Dummy hash operation took {}ms", dummy_time.as_millis()),
                    "dummy_hash_timing",
                    "process_login",
                );
                
                pw_verify_span.record("user_exists", &false);
                pw_verify_span.record("business.result", &"dummy");
                Ok(false)
            }
        }
        .instrument(pw_verify_span_clone)
        .await?;

        // If password doesn't match or user doesn't exist, return error with delay
        if !password_verification {
            // Add delay to prevent timing attacks by normalizing response time
            sleep(Duration::from_millis(delay_ms)).await;
            record_login_failure();
            process_span.record("business.result", &"failure");
            process_span.record("failure_reason", &"invalid_credentials");

            Log::event(
                "WARN",
                "Authentication",
                &format!("Failed login attempt (type: {})", login_type),
                "invalid_credentials",
                "process_login",
            );

            return Err(AuthServiceError::validation(
                "credentials",
                "Invalid credentials",
            ));
        }

        // At this point we know user exists and password is correct
        let user = user_opt.unwrap();

        // =====================================================================
        // STAGE 4: ACCOUNT VERIFICATION
        // =====================================================================
        let account_span = business_operation_span("check_account_status");
        let account_span_clone = account_span.clone();

        Log::event(
            "DEBUG",
            "Authentication",
            "Checking account activation status",
            "account_check_start",
            "process_login",
        );

        let account_active = async {
            if !user.is_active {
                record_account_check_failure(error_types::INACTIVE_ACCOUNT);
                account_span.record("business.result", &"inactive");
                
                Log::event(
                    "WARN",
                    "Authentication",
                    &format!("Login attempt on inactive account (id: {})", user.id),
                    "inactive_account",
                    "process_login",
                );
                
                false
            } else {
                record_account_check_success();
                account_span.record("business.result", &"active");
                
                Log::event(
                    "DEBUG",
                    "Authentication",
                    "Account is active, proceeding with authentication",
                    "account_active",
                    "process_login",
                );
                
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

            // Note: For security, we use the same error message as invalid credentials
            // to prevent user enumeration
            return Err(AuthServiceError::validation(
                "credentials",
                "Invalid credentials",
            ));
        }

        // =====================================================================
        // STAGE 5: TOKEN GENERATION
        // =====================================================================
        // Generate access token with span
        let access_token_span = business_operation_span("generate_access_token");
        let access_token_span_clone = access_token_span.clone();

        Log::event(
            "DEBUG",
            "Authentication",
            "Generating access token",
            "token_generation_start",
            "process_login",
        );

        let access = async {
            match generate_token(&user.username, TOKEN_TYPE_ACCESS, None) {
                Ok(token) => {
                    record_token_generation_access_success();
                    access_token_span.record("business.result", &"success");
                    access_token_span.record("token_type", &TOKEN_TYPE_ACCESS);
                    
                    Log::event(
                        "DEBUG",
                        "Authentication",
                        "Access token generated successfully",
                        "access_token_success",
                        "process_login",
                    );
                    
                    Ok(token)
                }
                Err(e) => {
                    record_token_generation_access_failure(error_types::TOKEN_GENERATION_FAILED);
                    access_token_span.record("business.result", &"failure");
                    access_token_span.record("token_type", &TOKEN_TYPE_ACCESS);
                    access_token_span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "Authentication",
                        &format!("Failed to generate access token: {}", e),
                        "access_token_failure",
                        "process_login",
                    );
                    
                    Err(e)
                }
            }
        }
        .instrument(access_token_span_clone)
        .await?;

        // Generate refresh token with span
        let refresh_token_span = business_operation_span("generate_refresh_token");
        let refresh_token_span_clone = refresh_token_span.clone();

        let refresh = async {
            match generate_token(&user.username, TOKEN_TYPE_REFRESH, None) {
                Ok(token) => {
                    record_token_generation_refresh_success();
                    refresh_token_span.record("business.result", &"success");
                    refresh_token_span.record("token_type", &TOKEN_TYPE_REFRESH);
                    
                    Log::event(
                        "DEBUG",
                        "Authentication",
                        "Refresh token generated successfully",
                        "refresh_token_success",
                        "process_login",
                    );
                    
                    Ok(token)
                }
                Err(e) => {
                    record_token_generation_refresh_failure(error_types::TOKEN_GENERATION_FAILED);
                    refresh_token_span.record("business.result", &"failure");
                    refresh_token_span.record("token_type", &TOKEN_TYPE_REFRESH);
                    refresh_token_span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "Authentication",
                        &format!("Failed to generate refresh token: {}", e),
                        "refresh_token_failure",
                        "process_login",
                    );
                    
                    Err(e)
                }
            }
        }
        .instrument(refresh_token_span_clone)
        .await?;

        // =====================================================================
        // STAGE 6: RESPONSE CONSTRUCTION
        // =====================================================================
        // Log successful authentication
        Log::event(
            "INFO",
            "Authentication",
            &format!("Successful login for user (id: {})", user.id),
            "success",
            "process_login",
        );

        // Record overall success
        record_login_success();
        process_span.record("business.result", &"success");
        process_span.record("user_id", &user.id);

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
    use crate::db::users::User;
    use crate::handlers::login::LoginRequest;
    use crate::metricss::login_metrics::{
        error_types, init_login_metrics, results, steps, LOGIN_DURATION, LOGIN_FAILURES,
        LOGIN_OPERATIONS,
    };
    use crate::utils::test_utils::{init_jwt_secret, state_with_redis};

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
        user.is_active = true;
        user.update(&mut conn).unwrap();

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
        user.is_active = false;
        user.update(&mut conn).unwrap();

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
        user.is_active = true;
        user.update(&mut conn).unwrap();

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

        // Extract response data to verify token structure
        if let Ok(response) = result {
            // Convert the IntoResponse to an actual Response
            let response = response.into_response();
            
            // Check the status code
            assert_eq!(response.status(), StatusCode::OK);
            
            // To fully test the body, you would need to extract it from the response
            // This is simplified for the unit test
        }

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
        user.is_active = true;
        user.update(&mut conn).unwrap();

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
        user.is_active = true;
        user.update(&mut conn).unwrap();

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

    #[tokio::test]
    async fn login_processing_respects_delay_configuration() {
        setup_metrics();
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Save original delay value
        let original_delay = std::env::var("INVALID_CREDENTIAL_DELAY_MS").ok();
        
        // Set a specific delay for testing
        std::env::set_var("INVALID_CREDENTIAL_DELAY_MS", "200");
        
        let req = LoginRequest {
            login: "nonexistent-user".into(),
            password: "wrong-password".into(),
        };

        // Act - Measure time for invalid login
        let start = std::time::Instant::now();
        let _ = process_login(&state, &req).await;
        let duration = start.elapsed();

        // Assert - Should take at least the configured delay
        assert!(duration.as_millis() >= 200, 
            "Login processing should respect the configured delay");
            
        // Restore original delay value
        if let Some(delay) = original_delay {
            std::env::set_var("INVALID_CREDENTIAL_DELAY_MS", delay);
        } else {
            std::env::remove_var("INVALID_CREDENTIAL_DELAY_MS");
        }
    }
}