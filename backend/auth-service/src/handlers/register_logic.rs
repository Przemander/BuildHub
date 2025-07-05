//! Business logic for user registration.
//!
//! This module implements a comprehensive registration flow with:
//! - Input validation for username, email, and password
//! - Uniqueness checks to prevent duplicate accounts
//! - User creation with secure password hashing
//! - Activation code generation and storage in Redis
//! - Email delivery for account activation
//! - Unified error handling with structured observability
//! - Full observability through metrics and structured logging

use crate::{
    app::AppState,
    config::redis::store_activation_code, // ← POPRAWKA: Z config/redis.rs
    db::users::{RegisterData, User},
    log_info, log_warn,
    utils::{
        email::{generate_activation_code, EmailConfig}, // ← POPRAWKA: Tylko generate_activation_code z email
        error_new::AuthServiceError,
        metrics::AUTH_REGISTRATIONS,
        validators::{validate_email, validate_password, validate_username},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use redis::Client as RedisClient;
use serde_json::json;

/// Processes registration using the unified error system.
///
/// # Parameters
/// * `app_state` - Application state containing DB pool, Redis client, and email config
/// * `data` - Registration data from the client request
///
/// # Returns
/// Result that can be converted to HTTP response via unified error system
///
/// # Flow
/// 1. Validate dependencies (Email config, Redis)
/// 2. Validate input fields (username, email, password)
/// 3. Check uniqueness (email, username)
/// 4. Create inactive user in database
/// 5. Generate and store activation code
/// 6. Send activation email
/// 7. Return success response
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Record registration attempt
    AUTH_REGISTRATIONS.with_label_values(&["attempt"]).inc();
    
    log_info!(
        "Registration", 
        &format!("Starting registration for username: {}, email: {}", data.username, data.email), 
        "registration_start"
    );

    // Check required dependencies
    let email_cfg = app_state
        .email_config
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Email configuration not available"))?
        .clone();

    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis client not available"))?;

    // Obtain a DB connection - automatic conversion via ? operator
    let mut conn = app_state.pool.get()?;

    // Validate input fields - automatic conversion via ? operator
    validate_username(&data.username)?;
    validate_email(&data.email)?;
    validate_password(&data.password)?;

    // Check uniqueness
    if User::find_by_email(&mut conn, &data.email).is_ok() {
        AUTH_REGISTRATIONS.with_label_values(&["email_exists"]).inc();
        log_warn!(
            "Registration", 
            &format!("Registration attempt with existing email: {}", data.email), 
            "email_already_exists"
        );
        
        return Err(AuthServiceError::validation("email", "Email address is already registered"));
    }

    if User::find_by_username(&mut conn, &data.username).is_ok() {
        AUTH_REGISTRATIONS.with_label_values(&["username_exists"]).inc();
        log_warn!(
            "Registration", 
            &format!("Registration attempt with existing username: {}", data.username), 
            "username_already_exists"
        );
        
        return Err(AuthServiceError::validation("username", "Username is already taken"));
    }

    // Create inactive user - automatic conversion via ? operator
    let mut user = User::new(&data.username, &data.email, &data.password);
    user.is_active = Some(false);
    user.save(&mut conn)?;

    log_info!(
        "Registration", 
        &format!("User created successfully: {}", data.username), 
        "user_created"
    );

    // Generate and store activation code
    create_and_send_activation(&user, redis_client, &email_cfg).await?;

    // Record success
    AUTH_REGISTRATIONS.with_label_values(&["success"]).inc();
    log_info!(
        "Registration", 
        &format!("Registration completed successfully for: {}", data.username), 
        "registration_success"
    );

    // Return success response
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "status": "success",
            "message": "Registration successful! Please check your email to activate your account."
        })),
    ))
}

/// Helper function to generate activation code, store it, and send email using unified errors.
async fn create_and_send_activation(
    user: &User,
    redis_client: &RedisClient,
    email_cfg: &EmailConfig,
) -> Result<(), AuthServiceError> {
    // Generate activation code - from utils/email.rs
    let code = generate_activation_code();
    
    log_info!(
        "Registration", 
        &format!("Generated activation code for user: {}", user.email), 
        "activation_code_generated"
    );

    // Store activation code - from config/redis.rs, automatic conversion via ? operator
    store_activation_code(redis_client, &user.email, &code).await?;

    log_info!(
        "Registration", 
        &format!("Activation code stored for user: {}", user.email), 
        "activation_code_stored"
    );

    // Send activation email (non-fatal - log but don't fail registration)
    if let Err(e) = email_cfg.send_activation_email(&user.email, &code, redis_client).await {
        log_warn!(
            "Registration", 
            &format!("Failed to send activation email to {}: {}", user.email, e), 
            "activation_email_failed"
        );
        AUTH_REGISTRATIONS.with_label_values(&["email_failed"]).inc();
        // Continue without failing - user is registered, they can resend activation
    } else {
        log_info!(
            "Registration", 
            &format!("Activation email sent successfully to: {}", user.email), 
            "activation_email_sent"
        );
        AUTH_REGISTRATIONS.with_label_values(&["email_sent"]).inc();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::db::users::{RegisterData, User};
    use crate::utils::email::EmailConfig;
    use crate::utils::test_utils::state_with_redis;

    /// Build a state with in-memory DB + Redis + dummy EmailConfig
    fn make_state() -> AppState {
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        state
    }

    #[tokio::test]
    async fn missing_email_config_returns_configuration_error() {
        let mut state = make_state();
        state.email_config = None;
        let data = RegisterData {
            username: "user".into(),
            email: "user@ex.com".into(),
            password: "Valid1!".into(),
        };
        
        let result = process_registration(&state, data).await;
        assert!(result.is_err());
        
        // Check that it's a configuration error
        if let Err(AuthServiceError::Configuration(msg)) = result {
            assert!(msg.contains("Email configuration"));
        } else {
            panic!("Expected configuration error");
        }
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        let mut state = make_state();
        state.redis_client = None;
        let data = RegisterData {
            username: "user".into(),
            email: "user@ex.com".into(),
            password: "Valid1!".into(),
        };
        
        let result = process_registration(&state, data).await;
        assert!(result.is_err());
        
        // Check that it's a configuration error
        if let Err(AuthServiceError::Configuration(msg)) = result {
            assert!(msg.contains("Redis client"));
        } else {
            panic!("Expected configuration error");
        }
    }

    #[tokio::test]
    async fn missing_username_returns_validation_error() {
        let state = make_state();
        let data = RegisterData {
            username: "".into(),
            email: "user@example.com".into(),
            password: "Valid1!".into(),
        };
        
        let result = process_registration(&state, data).await;
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn invalid_email_returns_validation_error() {
        let state = make_state();
        let data = RegisterData {
            username: "testuser".into(),
            email: "not-an-email".into(),
            password: "Valid1!".into(),
        };
        
        let result = process_registration(&state, data).await;
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn weak_password_returns_validation_error() {
        let state = make_state();
        let data = RegisterData {
            username: "testuser".into(),
            email: "user@example.com".into(),
            password: "short".into(),
        };
        
        let result = process_registration(&state, data).await;
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn duplicate_email_returns_validation_error() {
        let state = make_state();
        let data1 = RegisterData {
            username: "first".into(),
            email: "dup@ex.com".into(),
            password: "Valid12!".into(),
        };
        let result1 = process_registration(&state, data1.clone()).await;
        assert!(result1.is_ok());

        let data2 = RegisterData {
            username: "second".into(),
            email: data1.email.clone(),
            password: "Valid12!".into(),
        };
        let result2 = process_registration(&state, data2).await;
        assert!(result2.is_err());
        
        // Check that it's a validation error
        match result2.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn successful_registration_creates_user() {
        let state = make_state();
        let data = RegisterData {
            username: "newuser".into(),
            email: "new@user.com".into(),
            password: "Strong1!".into(),
        };
        
        let result = process_registration(&state, data.clone()).await;
        assert!(result.is_ok());

        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
        assert_eq!(user.is_active, Some(false)); // Should be inactive by default
    }
}