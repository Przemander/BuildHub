//! Business logic for user registration.
//!
//! This module implements a comprehensive registration flow with:
//! - Input validation for username, email, and password
//! - Uniqueness checks to prevent duplicate accounts
//! - User creation with secure password hashing
//! - Activation code generation and storage in Redis
//! - Email delivery for account activation
//! - Unified error handling with structured observability
//! - Full OpenTelemetry integrated tracing with hierarchical spans

use crate::{
    app::AppState,
    config::redis::store_activation_code,
    db::users::{RegisterData, User},
    metricss::register_metrics::{
        // Type-safe constants
        error_types,
        record_activation_setup_failure,
        record_activation_setup_success,
        record_email_delivery_failure,
        record_email_delivery_success,
        record_registration_failure,
        record_registration_success,
        record_uniqueness_check_failure,
        record_uniqueness_check_success,
        record_user_creation_failure,
        record_user_creation_success,
        record_validation_failure,
        // Step-by-step tracking with business helpers
        record_validation_success,
        // High-level complete flow tracking
        time_complete_registration_flow,
    },
    utils::{
        email::generate_activation_code,
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, db_operation_span, SpanExt},
        validators::{validate_email, validate_password, validate_username},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use redis::Client as RedisClient;
use serde_json::json;
use tracing::Instrument;

/// Processes registration using the unified error system with complete tracing integration.
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Start complete registration flow timer for end-to-end performance monitoring
    let _complete_flow_timer = time_complete_registration_flow();

    // Create span for the entire registration processing flow
    let process_span = business_operation_span("process_registration");
    process_span.record("username", &data.username);
    process_span.record(
        "email_domain",
        &data.email.split('@').nth(1).unwrap_or("invalid"),
    );

    // Clone span before moving it into the async block
    let process_span_clone = process_span.clone();

    Log::event(
        "INFO",
        "Registration",
        &format!(
            "Starting registration for username: {}, email: {}",
            data.username, data.email
        ),
        "registration_start",
        "process_registration",
    );

    // Wrap registration logic in the process_span
    async move {
        // Step 1: Check required dependencies (configuration validation)
        let email_cfg = app_state
            .email_config
            .as_ref()
            .ok_or_else(|| {
                record_registration_failure();
                process_span.record("business.result", &"failure");
                process_span.record("failure_reason", &"missing_email_config");
                
                Log::event(
                    "ERROR",
                    "Registration",
                    "Email configuration not available",
                    "configuration_error",
                    "process_registration"
                );
                
                AuthServiceError::configuration("Email configuration not available")
            })?
            .clone();

        let redis_client = app_state
            .redis_client
            .as_ref()
            .ok_or_else(|| {
                record_registration_failure();
                process_span.record("business.result", &"failure");
                process_span.record("failure_reason", &"missing_redis_client");
                
                Log::event(
                    "ERROR",
                    "Registration",
                    "Redis client not available",
                    "configuration_error",
                    "process_registration"
                );
                
                AuthServiceError::configuration("Redis client not available")
            })?;

        // Step 2: Validate input fields with spans and metrics
        let validation_span = business_operation_span("input_validation");
        let validation_span_clone = validation_span.clone();
        
        Log::event(
            "INFO",
            "Registration", 
            "Starting input validation", 
            "validation_start",
            "process_registration"
        );
        
        let validation_result = async {
            match validate_all_inputs(&data.username, &data.email, &data.password) {
                Ok(()) => {
                    record_validation_success();
                    validation_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Registration", 
                        "All input validation successful", 
                        "validation_success",
                        "process_registration"
                    );
                    
                    Ok(())
                }
                Err(e) => {
                    // Categorize validation failure for detailed monitoring
                    let error_type = categorize_validation_error(&e);
                    record_validation_failure(error_type);
                    record_registration_failure();
                    validation_span.record("business.result", &"failure");
                    validation_span.record("failure_reason", &error_type);
                    validation_span.record_error(&e);
                    
                    Log::event(
                        "WARN",
                        "Registration", 
                        &format!("Input validation failed: {}", e), 
                        "validation_failure",
                        "process_registration"
                    );
                    
                    Err(e)
                }
            }
        }.instrument(validation_span_clone).await;
        
        // Early return on validation failure
        validation_result?;

        // Step 3: Get database connection for further operations
        let db_conn_span = db_operation_span("get_connection", "pool");
        let db_conn_span_clone = db_conn_span.clone();
        
        let conn_result = async {
            match app_state.pool.get() {
                Ok(conn) => {
                    db_conn_span.record("db.success", &true);
                    Ok(conn)
                }
                Err(e) => {
                    record_uniqueness_check_failure(error_types::DATABASE_ERROR);
                    record_registration_failure();
                    db_conn_span.record("db.success", &false);
                    db_conn_span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "Registration", 
                        &format!("Failed to get database connection: {}", e), 
                        "db_connection_failure",
                        "process_registration"
                    );
                    
                    Err(AuthServiceError::database("Database connection failed"))
                }
            }
        }.instrument(db_conn_span_clone).await?;
        
        let mut conn = conn_result;

        // Step 4: Check uniqueness with proper span context
        let uniqueness_span = db_operation_span("check_uniqueness", "users");
        let uniqueness_span_clone = uniqueness_span.clone();
        
        Log::event(
            "INFO",
            "Registration", 
            "Starting uniqueness checks", 
            "uniqueness_check_start",
            "process_registration"
        );
        
        let uniqueness_result = async {
            match check_uniqueness(&mut conn, &data.email, &data.username) {
                Ok(()) => {
                    record_uniqueness_check_success();
                    uniqueness_span.record("db.success", &true);
                    uniqueness_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Registration", 
                        "Uniqueness checks passed", 
                        "uniqueness_check_success",
                        "process_registration"
                    );
                    
                    Ok(())
                }
                Err(e) => {
                    // Categorize uniqueness failure for detailed monitoring
                    let error_type = if e.to_string().contains("email") {
                        error_types::EMAIL_TAKEN
                    } else {
                        error_types::USERNAME_TAKEN
                    };
                    
                    record_uniqueness_check_failure(error_type);
                    record_registration_failure();
                    uniqueness_span.record("db.success", &false);
                    uniqueness_span.record("business.result", &"failure");
                    uniqueness_span.record("failure_reason", &error_type);
                    uniqueness_span.record_error(&e);
                    
                    Log::event(
                        "WARN",
                        "Registration", 
                        &format!("Uniqueness check failed: {}", e), 
                        "uniqueness_check_failure",
                        "process_registration"
                    );
                    
                    Err(e)
                }
            }
        }.instrument(uniqueness_span_clone).await;
        
        // Early return on uniqueness check failure
        uniqueness_result?;

        // Step 5: Create inactive user with database span
        let user_creation_span = db_operation_span("create_user", "users");
        let user_creation_span_clone = user_creation_span.clone();
        
        Log::event(
            "INFO",
            "Registration", 
            "Creating user record", 
            "user_creation_start",
            "process_registration"
        );
        
        let user_result = async {
            // Instead of creating and saving a User, use the new approach:
            let new_user = User::new_for_insert(&data.username, &data.email, &data.password);
            
            // Save and get the user with ID
            let saved_user = match User::save_new(new_user, &mut conn) {
                Ok(user) => user,
                Err(e) => {
                    record_user_creation_failure(error_types::DATABASE_ERROR);
                    record_registration_failure();
                    user_creation_span.record("db.success", &false);
                    user_creation_span.record("business.result", &"failure");
                    user_creation_span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "Registration", 
                        &format!("Failed to create user: {}", e), 
                        "user_creation_failure",
                        "process_registration"
                    );
                    
                    return Err(e);
                }
            };

            record_user_creation_success();
            user_creation_span.record("db.success", &true);
            user_creation_span.record("business.result", &"success");
            
            Log::event(
                "INFO",
                "Registration", 
                &format!("User created successfully: {}", data.username), 
                "user_created",
                "process_registration"
            );
            
            Ok(saved_user)
        }.instrument(user_creation_span_clone).await?;
        
        let user = user_result;

        // Step 6: Generate and store activation code + send email
        let activation_span = business_operation_span("activation_setup");
        let activation_span_clone = activation_span.clone();
        
        Log::event(
            "INFO",
            "Registration", 
            "Starting activation setup", 
            "activation_setup_start",
            "process_registration"
        );
        
        let activation_result = async {
            match setup_user_activation(&user, redis_client).await {
                Ok(code) => {
                    record_activation_setup_success();
                    activation_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Registration", 
                        &format!("Activation code generated and stored for: {}", user.email), 
                        "activation_setup_success",
                        "process_registration"
                    );
                    
                    // Step 7: Send activation email (non-fatal)
                    let email_span = business_operation_span("email_delivery");
                    let email_span_clone = email_span.clone();
                    
                    async {
                        Log::event(
                            "INFO",
                            "Registration", 
                            "Starting email delivery", 
                            "email_delivery_start",
                            "process_registration"
                        );
                        
                        match email_cfg.send_activation_email(&user.email, &code, redis_client).await {
                            Ok(()) => {
                                record_email_delivery_success();
                                email_span.record("business.result", &"success");
                                
                                Log::event(
                                    "INFO",
                                    "Registration", 
                                    &format!("Activation email sent successfully to: {}", user.email), 
                                    "activation_email_sent",
                                    "process_registration"
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
                                email_span.record("business.result", &"failure");
                                email_span.record("failure_reason", &error_type);
                                email_span.record_error(&e);
                                
                                Log::event(
                                    "WARN",
                                    "Registration", 
                                    &format!("Failed to send activation email to {}: {}", user.email, e), 
                                    "activation_email_failed",
                                    "process_registration"
                                );
                                // Continue without failing - user is registered, they can resend activation
                            }
                        }
                    }.instrument(email_span_clone).await;
                    
                    Ok(())
                }
                Err(e) => {
                    record_activation_setup_failure(error_types::REDIS_ERROR);
                    record_registration_failure();
                    activation_span.record("business.result", &"failure");
                    activation_span.record("failure_reason", &"redis_error");
                    activation_span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "Registration", 
                        &format!("Failed activation setup for {}: {}", user.email, e), 
                        "activation_setup_failed",
                        "process_registration"
                    );
                    
                    Err(AuthServiceError::from(e))
                }
            }
        }.instrument(activation_span_clone).await;
        
        // Handle activation setup result
        activation_result?;

        // Success - record final success metrics
        record_registration_success();
        process_span.record("business.result", &"success");
        process_span.record("user.id", &user.username);
        
        Log::event(
            "INFO",
            "Registration", 
            &format!("Registration completed successfully for: {}", data.username), 
            "registration_success",
            "process_registration"
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
    .instrument(process_span_clone)
    .await
}

// Pozostałe funkcje pomocnicze - bez większych zmian, poza usunięciem log_info! i log_warn!
/// Helper function to validate all inputs (grouped for cleaner metrics)
fn validate_all_inputs(
    username: &str,
    email: &str,
    password: &str,
) -> Result<(), AuthServiceError> {
    validate_username(username)?;
    validate_email(email)?;
    validate_password(password)?;
    Ok(())
}

/// Helper function to check uniqueness constraints with error categorization
fn check_uniqueness(
    conn: &mut diesel::PgConnection,
    email: &str,
    username: &str,
) -> Result<(), AuthServiceError> {
    // Check email uniqueness
    if User::find_by_email(conn, email).is_ok() {
        return Err(AuthServiceError::validation(
            "email",
            "Email address is already registered",
        ));
    }

    // Check username uniqueness
    if User::find_by_username(conn, username).is_ok() {
        return Err(AuthServiceError::validation(
            "username",
            "Username is already taken",
        ));
    }

    Ok(())
}


/// Helper to setup activation code with Redis storage
async fn setup_user_activation(
    user: &User,
    redis_client: &RedisClient,
) -> Result<String, AuthServiceError> {
    // Generate activation code
    let code = generate_activation_code();

    // Store activation code in Redis
    store_activation_code(redis_client, &user.email, &code).await?;

    Ok(code)
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
        _ => error_types::INVALID_USERNAME, // Default for non-validation errors
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
        error_types, // ✅ FIXED: Import steps and error_types here where they're actually used
        init_registration_metrics,
        steps,
        REGISTRATION_DURATION,
        REGISTRATION_FAILURES,
        REGISTRATION_OPERATIONS,
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
                assert_eq!(
                    final_email_taken_failures,
                    initial_email_taken_failures + 1.0
                );
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
        assert_eq!(
            final_user_creation_success,
            initial_user_creation_success + 1.0
        );
        assert_eq!(
            final_activation_setup_success,
            initial_activation_setup_success + 1.0
        );
        assert_eq!(final_complete_success, initial_complete_success + 1.0);

        // Duration should be recorded
        assert_eq!(final_complete_duration, initial_complete_duration + 1);

        // Verify user was actually created
        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
        assert_eq!(user.is_active, false); // Should be inactive by default
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
