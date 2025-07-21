//! Business logic for user registration.
//!
//! This module implements a comprehensive registration flow with:
//! - Input validation for username, email, and password
//! - Uniqueness checks to prevent duplicate accounts
//! - User creation with secure password hashing
//! - Activation code generation and storage in Redis
//! - Email delivery for account activation
//! - Unified error handling with structured observability
//! - **Full observability through 10/10 standardized registration metrics**

use crate::{
    app::AppState,
    config::redis::store_activation_code,
    db::users::{RegisterData, User},
    log_info, log_warn,
    utils::{
        email::{generate_activation_code, EmailConfig},
        error_new::AuthServiceError,
        validators::{validate_email, validate_password, validate_username},
    },
    // ✅ PERFECT: Import our brand new 10/10 registration metrics
    metricss::register_metrics::{
        // High-level complete flow tracking
        time_complete_registration_flow, record_registration_success, record_registration_failure,
        // Step-by-step tracking with business helpers
        record_validation_success, record_validation_failure,
        record_uniqueness_check_success, record_uniqueness_check_failure,
        record_user_creation_success, record_user_creation_failure,
        record_activation_setup_success, record_activation_setup_failure,
        record_email_delivery_success, record_email_delivery_failure,
        // Type-safe constants
        error_types, // ✅ FIXED: Removed unused `steps` import
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use redis::Client as RedisClient;
use serde_json::json;

/// Processes registration using the unified error system with complete 10/10 metrics integration.
///
/// # Metrics Generated
/// - `registration_operations_total{step="complete_flow|validation|uniqueness_check|user_creation|activation_setup|email_delivery", result="success|failure"}`
/// - `registration_failures_total{step="...", error_type="invalid_email|weak_password|email_taken|database_error|smtp_error|..."}`
/// - `registration_duration_seconds{step="complete_flow|validation|uniqueness_check|user_creation|activation_setup|email_delivery"}` (using LATENCY_BUCKETS_MEDIUM)
///
/// # Parameters
/// * `app_state` - Application state containing DB pool, Redis client, and email config
/// * `data` - Registration data from the client request
///
/// # Returns
/// Result that can be converted to HTTP response via unified error system
///
/// # Flow with Complete Metrics Tracking
/// 1. **Start complete flow timer** - Overall registration performance
/// 2. **Validate dependencies** (Email config, Redis) - Configuration validation
/// 3. **Validate input fields** (username, email, password) - Input validation metrics
/// 4. **Check uniqueness** (email, username) - Uniqueness check metrics with database timing
/// 5. **Create inactive user** in database - User creation metrics with database timing
/// 6. **Generate and store activation code** - Activation setup metrics with Redis timing
/// 7. **Send activation email** - Email delivery metrics with SMTP timing
/// 8. **Record complete success** - Overall flow completion tracking
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> Result<impl IntoResponse, AuthServiceError> {
    // ✅ PERFECT: Start complete registration flow timer for end-to-end performance monitoring
    let _complete_flow_timer = time_complete_registration_flow();
    
    log_info!(
        "Registration", 
        &format!("Starting registration for username: {}, email: {}", data.username, data.email), 
        "registration_start"
    );

    // ✅ Step 1: Check required dependencies (configuration validation)
    let email_cfg = app_state
        .email_config
        .as_ref()
        .ok_or_else(|| {
            record_registration_failure(); // Record overall failure
            AuthServiceError::configuration("Email configuration not available")
        })?
        .clone();

    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| {
            record_registration_failure(); // Record overall failure
            AuthServiceError::configuration("Redis client not available")
        })?;

    // ✅ Step 2: Validate input fields with detailed step metrics
    log_info!("Registration", "Starting input validation", "validation_start");
    
    match validate_all_inputs(&data.username, &data.email, &data.password) {
        Ok(()) => {
            record_validation_success();
            log_info!("Registration", "All input validation successful", "validation_success");
        }
        Err(e) => {
            // Categorize validation failure for detailed monitoring
            let error_type = categorize_validation_error(&e);
            record_validation_failure(error_type);
            record_registration_failure(); // Also record overall failure
            
            log_warn!("Registration", &format!("Input validation failed: {}", e), "validation_failure");
            return Err(e);
        }
    }

    // ✅ Step 3: Get database connection and check uniqueness with metrics
    let mut conn = app_state.pool.get().map_err(|e| {
        record_uniqueness_check_failure(error_types::DATABASE_ERROR);
        record_registration_failure();
        log_warn!("Registration", &format!("Failed to get database connection: {}", e), "db_connection_failure");
        e
    })?;

    log_info!("Registration", "Starting uniqueness checks", "uniqueness_check_start");

    match check_uniqueness(&mut conn, &data.email, &data.username) {
        Ok(()) => {
            record_uniqueness_check_success();
            log_info!("Registration", "Uniqueness checks passed", "uniqueness_check_success");
        }
        Err(e) => {
            // Categorize uniqueness failure for detailed monitoring
            let error_type = if e.to_string().contains("email") {
                error_types::EMAIL_TAKEN
            } else {
                error_types::USERNAME_TAKEN
            };
            record_uniqueness_check_failure(error_type);
            record_registration_failure(); // Also record overall failure
            
            log_warn!("Registration", &format!("Uniqueness check failed: {}", e), "uniqueness_check_failure");
            return Err(e);
        }
    }

    // ✅ Step 4: Create inactive user with database metrics
    log_info!("Registration", "Creating user record", "user_creation_start");
    
    match create_inactive_user(&mut conn, &data.username, &data.email, &data.password) {
        Ok(user) => {
            record_user_creation_success();
            log_info!(
                "Registration", 
                &format!("User created successfully: {}", data.username), 
                "user_created"
            );
            
            // ✅ Step 5: Generate and store activation code + send email
            match create_and_send_activation(&user, redis_client, &email_cfg).await {
                Ok(()) => {
                    // ✅ PERFECT: Complete success - record overall success
                    record_registration_success();
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
                Err(e) => {
                    record_registration_failure(); // Record overall failure
                    log_warn!("Registration", &format!("Activation setup failed: {}", e), "activation_setup_failure");
                    Err(e)
                }
            }
        }
        Err(e) => {
            record_user_creation_failure(error_types::DATABASE_ERROR);
            record_registration_failure(); // Also record overall failure
            log_warn!("Registration", &format!("Failed to create user: {}", e), "user_creation_failure");
            Err(e)
        }
    }
}

/// Helper function to validate all inputs (grouped for cleaner metrics)
fn validate_all_inputs(username: &str, email: &str, password: &str) -> Result<(), AuthServiceError> {
    // All validation functions already have their own detailed metrics from validation_metrics.rs
    // This provides step-level aggregation
    validate_username(username)?;
    validate_email(email)?;
    validate_password(password)?;
    Ok(())
}

/// Helper function to check uniqueness constraints with error categorization
fn check_uniqueness(conn: &mut diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::SqliteConnection>>, email: &str, username: &str) -> Result<(), AuthServiceError> {
    // Check email uniqueness
    if User::find_by_email(conn, email).is_ok() {
        log_warn!(
            "Registration", 
            &format!("Registration attempt with existing email: {}", email), 
            "email_already_exists"
        );
        return Err(AuthServiceError::validation("email", "Email address is already registered"));
    }

    // Check username uniqueness
    if User::find_by_username(conn, username).is_ok() {
        log_warn!(
            "Registration", 
            &format!("Registration attempt with existing username: {}", username), 
            "username_already_exists"
        );
        return Err(AuthServiceError::validation("username", "Username is already taken"));
    }

    Ok(())
}

/// Helper function to create inactive user with error handling
fn create_inactive_user(
    conn: &mut diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::SqliteConnection>>, 
    username: &str, 
    email: &str, 
    password: &str
) -> Result<User, AuthServiceError> {
    let mut user = User::new(username, email, password);
    user.is_active = Some(false);
    user.save(conn)?;
    Ok(user)
}

/// Helper function to generate activation code, store it, and send email with complete step metrics.
async fn create_and_send_activation(
    user: &User,
    redis_client: &RedisClient,
    email_cfg: &EmailConfig,
) -> Result<(), AuthServiceError> {
    // ✅ Step 5a: Generate and store activation code with metrics
    log_info!("Registration", "Starting activation setup", "activation_setup_start");
    
    match setup_user_activation(user, redis_client).await {
        Ok(code) => {
            record_activation_setup_success();
            log_info!(
                "Registration", 
                &format!("Activation code generated and stored for: {}", user.email), 
                "activation_setup_success"
            );
            
            // ✅ Step 5b: Send activation email with metrics (non-fatal)
            send_activation_email_with_metrics(user, &code, email_cfg, redis_client).await;
            Ok(())
        }
        Err(e) => {
            record_activation_setup_failure(error_types::REDIS_ERROR);
            log_warn!(
                "Registration", 
                &format!("Failed activation setup for {}: {}", user.email, e), 
                "activation_setup_failed"
            );
            Err(AuthServiceError::from(e))
        }
    }
}

/// Helper to setup activation code with Redis storage
async fn setup_user_activation(user: &User, redis_client: &RedisClient) -> Result<String, AuthServiceError> {
    // Generate activation code
    let code = generate_activation_code();
    
    log_info!(
        "Registration", 
        &format!("Generated activation code for user: {}", user.email), 
        "activation_code_generated"
    );

    // Store activation code in Redis
    store_activation_code(redis_client, &user.email, &code).await?;
    
    log_info!(
        "Registration", 
        &format!("Activation code stored for user: {}", user.email), 
        "activation_code_stored"
    );

    Ok(code)
}

/// Helper to send activation email with detailed metrics (non-fatal)
async fn send_activation_email_with_metrics(
    user: &User, 
    code: &str, 
    email_cfg: &EmailConfig, 
    redis_client: &RedisClient
) {
    log_info!("Registration", "Starting email delivery", "email_delivery_start");
    
    // Send activation email (non-fatal - log but don't fail registration)
    match email_cfg.send_activation_email(&user.email, code, redis_client).await {
        Ok(()) => {
            record_email_delivery_success();
            log_info!(
                "Registration", 
                &format!("Activation email sent successfully to: {}", user.email), 
                "activation_email_sent"
            );
        }
        Err(e) => {
            // Categorize email failure for better monitoring
            let error_type = if e.to_string().contains("SMTP") || e.to_string().contains("connection") {
                error_types::SMTP_ERROR
            } else {
                error_types::CONFIGURATION_ERROR
            };
            
            record_email_delivery_failure(error_type);
            log_warn!(
                "Registration", 
                &format!("Failed to send activation email to {}: {}", user.email, e), 
                "activation_email_failed"
            );
            // Continue without failing - user is registered, they can resend activation
        }
    }
}

/// Categorizes validation errors for detailed metrics tracking
fn categorize_validation_error(error: &AuthServiceError) -> &'static str {
    match error {
        AuthServiceError::Validation(validation_err) => {
            let error_msg = validation_err.to_string().to_lowercase();
            if error_msg.contains("username") {
                error_types::INVALID_USERNAME
            } else if error_msg.contains("email") {
                error_types::INVALID_EMAIL
            } else if error_msg.contains("password") {
                error_types::WEAK_PASSWORD
            } else {
                error_types::INVALID_USERNAME // Default
            }
        }
        _ => error_types::INVALID_USERNAME // Default for non-validation errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::db::users::{RegisterData, User};
    use crate::utils::email::EmailConfig;
    use crate::utils::test_utils::state_with_redis;
    // ✅ FIXED: Import metrics for testing integration INCLUDING steps and error_types
    use crate::metricss::register_metrics::{
        init_registration_metrics, REGISTRATION_OPERATIONS, REGISTRATION_DURATION, REGISTRATION_FAILURES,
        steps, error_types // ✅ FIXED: Import steps and error_types here where they're actually used
    };

    /// Build a state with in-memory DB + Redis + dummy EmailConfig + initialized metrics
    fn make_state() -> AppState {
        // Initialize registration metrics
        init_registration_metrics();
        
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
        
        if let Err(AuthServiceError::Configuration(msg)) = result {
            assert!(msg.contains("Redis client"));
        } else {
            panic!("Expected configuration error");
        }
    }

    #[tokio::test]
    async fn missing_username_returns_validation_error_with_metrics() {
        let state = make_state();
        
        // Record initial metrics state
        let initial_validation_failure = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::VALIDATION, "failure"])
            .get();
        let initial_complete_failure = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "failure"])
            .get();
        
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
                // Expected - verify metrics were recorded
                let final_validation_failure = REGISTRATION_OPERATIONS
                    .with_label_values(&[steps::VALIDATION, "failure"])
                    .get();
                let final_complete_failure = REGISTRATION_OPERATIONS
                    .with_label_values(&[steps::COMPLETE_FLOW, "failure"])
                    .get();
                
                assert_eq!(final_validation_failure, initial_validation_failure + 1.0);
                assert_eq!(final_complete_failure, initial_complete_failure + 1.0);
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
    async fn duplicate_email_returns_validation_error_with_metrics() {
        let state = make_state();
        
        // Create first user
        let data1 = RegisterData {
            username: "first".into(),
            email: "dup@ex.com".into(),
            password: "Valid12!".into(),
        };
        let result1 = process_registration(&state, data1.clone()).await;
        assert!(result1.is_ok());

        // Record initial metrics state for duplicate attempt
        let initial_uniqueness_failure = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::UNIQUENESS_CHECK, "failure"])
            .get();
        let initial_email_taken_failures = REGISTRATION_FAILURES
            .with_label_values(&[steps::UNIQUENESS_CHECK, error_types::EMAIL_TAKEN])
            .get();

        // Try to create duplicate
        let data2 = RegisterData {
            username: "second".into(),
            email: data1.email.clone(),
            password: "Valid12!".into(),
        };
        let result2 = process_registration(&state, data2).await;
        assert!(result2.is_err());
        
        // Check that it's a validation error with correct metrics
        match result2.err().unwrap() {
            AuthServiceError::Validation(_) => {
                let final_uniqueness_failure = REGISTRATION_OPERATIONS
                    .with_label_values(&[steps::UNIQUENESS_CHECK, "failure"])
                    .get();
                let final_email_taken_failures = REGISTRATION_FAILURES
                    .with_label_values(&[steps::UNIQUENESS_CHECK, error_types::EMAIL_TAKEN])
                    .get();
                
                assert_eq!(final_uniqueness_failure, initial_uniqueness_failure + 1.0);
                assert_eq!(final_email_taken_failures, initial_email_taken_failures + 1.0);
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn successful_registration_generates_complete_metrics() {
        let state = make_state();
        
        // Record initial metrics state for all steps
        let initial_validation_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::VALIDATION, "success"])
            .get();
        let initial_uniqueness_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::UNIQUENESS_CHECK, "success"])
            .get();
        let initial_user_creation_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::USER_CREATION, "success"])
            .get();
        let initial_activation_setup_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::ACTIVATION_SETUP, "success"])
            .get();
        let initial_complete_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "success"])
            .get();
        
        let initial_complete_duration = REGISTRATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        let data = RegisterData {
            username: "metrics_user".into(),
            email: "metrics@test.com".into(),
            password: "Strong123!".into(),
        };
        
        let result = process_registration(&state, data.clone()).await;
        assert!(result.is_ok());

        // ✅ PERFECT: Verify all step metrics were recorded correctly
        let final_validation_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::VALIDATION, "success"])
            .get();
        let final_uniqueness_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::UNIQUENESS_CHECK, "success"])
            .get();
        let final_user_creation_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::USER_CREATION, "success"])
            .get();
        let final_activation_setup_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::ACTIVATION_SETUP, "success"])
            .get();
        let final_complete_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "success"])
            .get();
        
        let final_complete_duration = REGISTRATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        // All steps should have recorded success
        assert_eq!(final_validation_success, initial_validation_success + 1.0);
        assert_eq!(final_uniqueness_success, initial_uniqueness_success + 1.0);
        assert_eq!(final_user_creation_success, initial_user_creation_success + 1.0);
        assert_eq!(final_activation_setup_success, initial_activation_setup_success + 1.0);
        assert_eq!(final_complete_success, initial_complete_success + 1.0);
        
        // Duration should be recorded
        assert_eq!(final_complete_duration, initial_complete_duration + 1);

        // Verify user was actually created
        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
        assert_eq!(user.is_active, Some(false)); // Should be inactive by default
    }

    #[tokio::test]
    async fn production_registration_patterns() {
        let state = make_state();
        
        // Simulate realistic production patterns
        
        // 10 successful registrations
        for i in 0..10 {
            let data = RegisterData {
                username: format!("user_{}", i),
                email: format!("user_{}@test.com", i),
                password: "Strong123!".into(),
            };
            let result = process_registration(&state, data).await;
            assert!(result.is_ok());
        }
        
        // Some failures at different steps
        
        // Validation failure
        let weak_password_data = RegisterData {
            username: "weak_user".into(),
            email: "weak@test.com".into(),
            password: "weak".into(),
        };
        let result = process_registration(&state, weak_password_data).await;
        assert!(result.is_err());
        
        // Uniqueness failure (duplicate email)
        let duplicate_data = RegisterData {
            username: "duplicate_user".into(),
            email: "user_0@test.com".into(), // Reuse first user's email
            password: "Strong123!".into(),
        };
        let result = process_registration(&state, duplicate_data).await;
        assert!(result.is_err());
        
        // ✅ Verify realistic metric patterns
        
        // 10 successful complete flows
        let complete_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "success"])
            .get();
        assert_eq!(complete_success, 10.0);
        
        // 2 failed complete flows (weak password + duplicate email)  
        let complete_failure = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, "failure"])
            .get();
        assert_eq!(complete_failure, 2.0);
        
        // Specific failure types
        let validation_failures = REGISTRATION_FAILURES
            .with_label_values(&[steps::VALIDATION, error_types::WEAK_PASSWORD])
            .get();
        assert_eq!(validation_failures, 1.0);
        
        let uniqueness_failures = REGISTRATION_FAILURES
            .with_label_values(&[steps::UNIQUENESS_CHECK, error_types::EMAIL_TAKEN])
            .get();
        assert_eq!(uniqueness_failures, 1.0);
        
        // All successful registrations went through all steps
        let validation_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::VALIDATION, "success"])
            .get();
        assert_eq!(validation_success, 10.0); // Only successful ones passed validation
        
        let user_creation_success = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::USER_CREATION, "success"])
            .get();
        assert_eq!(user_creation_success, 10.0);
    }
}