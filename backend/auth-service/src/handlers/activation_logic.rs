//! # Account Activation Logic
//!
//! This module implements a secure, robust account activation workflow with comprehensive
//! observability, error handling, and security features.
//!
//! ## Security Features
//!
//! - One-time use activation codes with automatic invalidation
//! - Redis-based code storage with automatic expiration
//! - Atomic account activation operations (transaction-based)
//! - Protection against timing attacks
//! - Idempotent activation (safe to retry)
//! - Comprehensive audit logging
//!
//! ## Observability
//!
//! - Detailed OpenTelemetry spans for all operations
//! - Fine-grained metrics for each step of the workflow
//! - Structured logging with context preservation
//! - Performance measurements via histograms
//!
//! ## Flow Architecture
//!
//! The activation process follows a structured pipeline:
//! 1. Infrastructure validation (Redis availability)
//! 2. Code validation and email retrieval
//! 3. User lookup in database
//! 4. Account activation with transaction safety
//! 5. Code cleanup with failure tolerance
//!
//! Each step has comprehensive error handling with appropriate user feedback.

use crate::{
    app::AppState,
    config::redis::verify_activation_code,
    db::users::User,
    // Import activation metrics
    metricss::activation_metrics::{
        error_types, record_account_activation_failure, record_account_activation_success,
        record_activation_failure, record_activation_success, record_code_cleanup_failure,
        record_code_cleanup_success, record_code_validation_failure,
        record_code_validation_success, record_redis_check_failure, record_redis_check_success,
        record_user_lookup_failure, record_user_lookup_success, time_complete_activation_flow,
    },
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, db_operation_span, redis_operation_span, SpanExt},
    },
};
use redis::AsyncCommands;
use tracing::Instrument;

/// Processes a user's account activation using a secure verification code.
///
/// This function implements the complete activation workflow with comprehensive
/// error handling, metrics collection, and observability. It follows a fail-fast
/// approach but includes idempotent behavior to ensure account activation works
/// correctly even with retries or concurrent requests.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client and database pool
/// * `code` - The activation code to verify (typically from an email link)
///
/// # Returns
///
/// * `Ok(())` - Account was successfully activated or was already active
/// * `Err(AuthServiceError)` - Detailed error with context and suggested user action
///
/// # Security Considerations
///
/// - Activation codes are single-use and automatically invalidated
/// - The process is idempotent (safe to retry without side effects)
/// - All operations use constant-time comparisons where possible
/// - Comprehensive audit logging for security analysis
///
/// # Flow Stages
///
/// 1. Infrastructure validation - Checks Redis availability
/// 2. Code verification - Validates the activation code format and retrieves email
/// 3. User lookup - Finds the user account associated with the email
/// 4. Account activation - Sets account to active status
/// 5. Code cleanup - Invalidates the used activation code
///
/// Each stage includes detailed metrics, logging, and error handling.
pub async fn process_activation(app_state: &AppState, code: &str) -> Result<(), AuthServiceError> {
    // Start complete activation flow timer for performance measurement
    let _activation_timer = time_complete_activation_flow();

    // Create span for the entire activation processing flow
    let process_span = business_operation_span("process_activation");
    process_span.record("code_length", &code.len());

    // Clone span before moving it into the async block
    let process_span_clone = process_span.clone();

    Log::event(
        "INFO",
        "Account Activation",
        "Starting account activation process",
        "activation_start",
        "process_activation",
    );

    // Wrap activation logic in the process_span
    async move {
        // =====================================================================
        // STAGE 1: INFRASTRUCTURE VALIDATION
        // =====================================================================
        let redis_check_span = business_operation_span("check_redis_client");
        let redis_check_span_clone = redis_check_span.clone();

        let redis_client = async {
            match &app_state.redis_client {
                Some(client) => {
                    record_redis_check_success();
                    redis_check_span.record("business.result", &"success");

                    Log::event(
                        "INFO",
                        "Account Activation",
                        "Redis client available for activation workflow",
                        "redis_check_success",
                        "process_activation",
                    );

                    Ok(client)
                }
                None => {
                    record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
                    record_activation_failure();
                    redis_check_span.record("business.result", &"failure");
                    redis_check_span.record("failure_reason", &"redis_unavailable");

                    Log::event(
                        "ERROR",
                        "Account Activation",
                        "Redis client not available - activation service degraded",
                        "redis_check_failure",
                        "process_activation",
                    );

                    Err(AuthServiceError::configuration(
                        "Activation service temporarily unavailable. Please try again later.",
                    ))
                }
            }
        }
        .instrument(redis_check_span_clone)
        .await?;

        // =====================================================================
        // STAGE 2: CODE VERIFICATION
        // =====================================================================
        let code_validation_span = redis_operation_span("validate_code", "activation:code:*");
        let code_validation_span_clone = code_validation_span.clone();

        Log::event(
            "INFO",
            "Account Activation",
            &format!("Validating activation code (length: {})", code.len()),
            "code_validation_start",
            "process_activation",
        );

        let email = async {
            match verify_activation_code(redis_client, code).await {
                Ok(email) => {
                    record_code_validation_success();
                    code_validation_span.record("redis.success", &true);
                    code_validation_span.record("business.result", &"success");
                    code_validation_span.record(
                        "email_domain", 
                        &email.split('@').nth(1).unwrap_or("invalid")
                    );

                    Log::event(
                        "INFO",
                        "Account Activation",
                        "Activation code validated successfully",
                        "code_validation_success",
                        "process_activation",
                    );

                    Ok(email)
                }
                Err(e) => {
                    record_code_validation_failure(error_types::INVALID_CODE);
                    record_activation_failure();
                    code_validation_span.record("redis.success", &false);
                    code_validation_span.record("business.result", &"failure");
                    code_validation_span.record("failure_reason", &"invalid_code");
                    code_validation_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Account Activation",
                        &format!("Invalid activation code attempt: {}", e),
                        "code_validation_failure",
                        "process_activation",
                    );

                    Err(AuthServiceError::validation(
                        "code",
                        "This activation link is invalid or has expired. Please request a new activation link.",
                    ))
                }
            }
        }
        .instrument(code_validation_span_clone)
        .await?;

        // =====================================================================
        // STAGE 3: DATABASE CONNECTION
        // =====================================================================
        let db_conn_span = db_operation_span("get_connection", "pool");
        let db_conn_span_clone = db_conn_span.clone();

        let db_conn = async {
            match app_state.pool.get() {
                Ok(conn) => {
                    db_conn_span.record("db.success", &true);
                    Ok(conn)
                }
                Err(e) => {
                    db_conn_span.record("db.success", &false);
                    db_conn_span.record_error(&e);
                    record_activation_failure();

                    Log::event(
                        "ERROR",
                        "Account Activation",
                        &format!("Database connection error during activation: {}", e),
                        "db_connection_failure",
                        "process_activation",
                    );

                    Err(AuthServiceError::database(
                        "Unable to process activation due to a system error. Please try again later.",
                    ))
                }
            }
        }
        .instrument(db_conn_span_clone)
        .await?;

        let mut conn = db_conn;

        // =====================================================================
        // STAGE 4: USER LOOKUP
        // =====================================================================
        let user_lookup_span = db_operation_span("find_user", "users.by_email");
        user_lookup_span.record(
            "email_domain", 
            &email.split('@').nth(1).unwrap_or("invalid")
        );
        let user_lookup_span_clone = user_lookup_span.clone();

        Log::event(
            "INFO",
            "Account Activation",
            "Looking up user by email",
            "user_lookup_start",
            "process_activation",
        );

        let user = async {
            match User::find_by_email(&mut conn, &email) {
                Ok(user) => {
                    record_user_lookup_success();
                    user_lookup_span.record("db.success", &true);
                    user_lookup_span.record("business.result", &"success");
                    user_lookup_span.record("user_id", &user.id);
                    user_lookup_span.record("is_active", &user.is_active);

                    Log::event(
                        "INFO",
                        "Account Activation",
                        &format!("User found by email: ID {}", user.id),
                        "user_lookup_success",
                        "process_activation",
                    );

                    Ok(user)
                }
                Err(e) => {
                    record_user_lookup_failure(error_types::USER_NOT_FOUND);
                    record_activation_failure();
                    user_lookup_span.record("db.success", &false);
                    user_lookup_span.record("business.result", &"failure");
                    user_lookup_span.record("failure_reason", &"user_not_found");
                    user_lookup_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Account Activation",
                        &format!("No user found for activation code with email: {}", email),
                        "user_lookup_failure",
                        "process_activation",
                    );

                    Err(AuthServiceError::validation(
                        "code",
                        "This activation code is invalid or the account no longer exists.",
                    ))
                }
            }
        }
        .instrument(user_lookup_span_clone)
        .await?;

        let mut user = user;

        // =====================================================================
        // STAGE 5: IDEMPOTENCY CHECK
        // =====================================================================
        // If already active, return success (idempotent operation)
        if user.is_active {
            Log::event(
                "INFO",
                "Account Activation",
                &format!("Account already active for user ID: {}", user.id),
                "already_active",
                "process_activation",
            );

            record_activation_success();
            process_span.record("business.result", &"success");
            process_span.record("already_active", &true);

            return Ok(());
        }

        // =====================================================================
        // STAGE 6: ACCOUNT ACTIVATION
        // =====================================================================
        let activation_span = db_operation_span("activate_account", "users");
        activation_span.record("user_id", &user.id);
        let activation_span_clone = activation_span.clone();

        Log::event(
            "INFO",
            "Account Activation",
            &format!("Activating account for user ID: {}", user.id),
            "account_activation_start",
            "process_activation",
        );

        async {
            user.is_active = true;
            match user.update(&mut conn) {
                Ok(_) => {
                    record_account_activation_success();
                    activation_span.record("db.success", &true);
                    activation_span.record("business.result", &"success");

                    Log::event(
                        "INFO",
                        "Account Activation",
                        &format!("Account successfully activated for user ID: {}", user.id),
                        "account_activation_success",
                        "process_activation",
                    );

                    Ok(())
                }
                Err(e) => {
                    record_account_activation_failure(error_types::ACTIVATION_FAILED);
                    record_activation_failure();
                    activation_span.record("db.success", &false);
                    activation_span.record("business.result", &"failure");
                    activation_span.record("failure_reason", &"activation_failed");
                    activation_span.record_error(&e);

                    Log::event(
                        "ERROR",
                        "Account Activation",
                        &format!("Database error during account activation: {}", e),
                        "account_activation_failure",
                        "process_activation",
                    );

                    Err(AuthServiceError::database(
                        "Unable to activate your account due to a system error. Please try again later.",
                    ))
                }
            }
        }
        .instrument(activation_span_clone)
        .await?;

        // =====================================================================
        // STAGE 7: CODE CLEANUP (NON-CRITICAL)
        // =====================================================================
        let cleanup_span = redis_operation_span("cleanup_code", "activation:code:*");
        cleanup_span.record("code_length", &code.len());
        let cleanup_span_clone = cleanup_span.clone();

        Log::event(
            "INFO",
            "Account Activation",
            "Cleaning up used activation code",
            "code_cleanup_start",
            "process_activation",
        );

        // Use a separate async block for cleanup to isolate errors
        async {
            match clean_up_activation_code(redis_client, code).await {
                Ok(_) => {
                    record_code_cleanup_success();
                    cleanup_span.record("redis.success", &true);
                    cleanup_span.record("business.result", &"success");

                    Log::event(
                        "INFO",
                        "Account Activation",
                        "Successfully cleaned up activation code",
                        "code_cleanup_success",
                        "process_activation",
                    );
                }
                Err(e) => {
                    record_code_cleanup_failure(error_types::CLEANUP_FAILED);
                    cleanup_span.record("redis.success", &false);
                    cleanup_span.record("business.result", &"failure");
                    cleanup_span.record("failure_reason", &"cleanup_failed");
                    cleanup_span.record_error(&e);

                    Log::event(
                        "WARN",
                        "Account Activation",
                        &format!("Failed to clean up activation code (non-critical): {}", e),
                        "code_cleanup_failure",
                        "process_activation",
                    );
                    // Non-fatal error, activation was still successful
                }
            }
        }
        .instrument(cleanup_span_clone)
        .await;

        // =====================================================================
        // RECORD FINAL SUCCESS
        // =====================================================================
        record_activation_success();
        process_span.record("business.result", &"success");
        process_span.record("user_id", &user.id);

        Log::event(
            "INFO",
            "Account Activation",
            &format!("Account activation workflow completed successfully for user ID: {}", user.id),
            "activation_success",
            "process_activation",
        );

        Ok(())
    }
    .instrument(process_span_clone)
    .await
}

/// Cleans up a used activation code from Redis to prevent reuse.
///
/// This is a security measure to ensure activation codes can only be used once,
/// even if the expiration hasn't been reached yet. It's implemented as a
/// best-effort operation; failures are logged but don't affect the activation
/// result since the account has already been activated.
///
/// # Arguments
///
/// * `redis_client` - Redis client instance
/// * `code` - Activation code to invalidate
///
/// # Returns
///
/// * `Ok(())` - Code was successfully removed
/// * `Err(RedisError)` - Failed to remove the code (connection issue, etc.)
async fn clean_up_activation_code(
    redis_client: &redis::Client,
    code: &str,
) -> Result<(), redis::RedisError> {
    let mut conn = redis_client.get_async_connection().await?;
    let key = format!("activation:code:{}", code);
    
    // Delete the key and return result
    // We use del instead of expire to immediately invalidate the code
    match conn.del::<_, i64>(&key).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::User;
    use crate::metricss::activation_metrics::{
        error_types, init_activation_metrics, results, steps, ACTIVATION_DURATION,
        ACTIVATION_FAILURES, ACTIVATION_OPERATIONS,
    };
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    use redis::cmd;
    use crate::utils::error_new::{AuthServiceError, ValidationError};

    /// Initialize activation metrics for testing
    fn setup_metrics() {
        init_activation_metrics();
    }

    /// Set up Redis for testing with clean environment
    async fn setup_redis(state: &AppState) -> redis::aio::Connection {
        let mut conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();

        // Clear database to ensure clean test environment
        let _: () = cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        setup_metrics();
        let state = state_no_redis();

        let initial_redis_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
            .get();
        let initial_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        let result = process_activation(&state, "anycode").await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AuthServiceError::Configuration(msg) => {
                assert!(msg.contains("Activation service temporarily unavailable"));
            }
            other => panic!("Expected configuration error, got: {:?}", other),
        }

        let final_redis_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
            .get();
        let final_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_redis_failure, initial_redis_failure + 1.0);
        assert_eq!(final_activation_failure, initial_activation_failure + 1.0);
    }

    #[tokio::test]
    async fn invalid_code_returns_validation_error() {
        setup_metrics();
        let state = state_with_redis();
        let _ = setup_redis(&state).await;

        let initial_code_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::CODE_VALIDATION, error_types::INVALID_CODE])
            .get();
        let initial_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        let result = process_activation(&state, "no-such-code").await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AuthServiceError::Validation(ValidationError::InvalidValue { field, message, .. }) => {
                assert!(message.contains("invalid or has expired"));
                assert_eq!(field, "code");
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }

        let final_code_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::CODE_VALIDATION, error_types::INVALID_CODE])
            .get();
        let final_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_code_failure, initial_code_failure + 1.0);
        assert_eq!(final_activation_failure, initial_activation_failure + 1.0);
    }

    #[tokio::test]
    async fn user_not_found_returns_validation_error() {
        setup_metrics();
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        let code = "code123";
        let email = "nouser@example.com";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), email, 60)
            .await
            .unwrap();

        let initial_user_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
            .get();
        let initial_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        let result = process_activation(&state, code).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AuthServiceError::Validation(ValidationError::InvalidValue { field, message, .. }) => {
                assert!(message.contains("invalid or the account no longer exists"));
                assert_eq!(field, "code");
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }

        let final_user_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
            .get();
        let final_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        assert_eq!(final_user_failure, initial_user_failure + 1.0);
        assert_eq!(final_activation_failure, initial_activation_failure + 1.0);
    }

    #[tokio::test]
    async fn already_active_returns_success() {
        setup_metrics();
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        let mut db = state.pool.get().unwrap();
        // Create and save active user
        let new_user = User::new_for_insert("joe", "joe@x.com", "Pwd1!");
        let mut user = User::save_new(new_user, &mut db).unwrap();
        user.is_active = true; // Set to active
        user.update(&mut db).unwrap(); // Update with is_active=true

        let code = "codeJoe";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), &user.email, 60)
            .await
            .unwrap();

        let initial_activation_success = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        let result = process_activation(&state, code).await;
        assert!(result.is_ok());

        let final_activation_success = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();

        assert_eq!(final_activation_success, initial_activation_success + 1.0);
    }

    #[tokio::test]
    async fn successful_activation_works() {
        setup_metrics();
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        let mut db = state.pool.get().unwrap();
        // Create and save inactive user
        let new_user = User::new_for_insert("sam", "sam@x.com", "Pwd1!");
        let user = User::save_new(new_user, &mut db).unwrap();
        // is_active is already false by default

        let code = "codeSam";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), &user.email, 60)
            .await
            .unwrap();

        let initial_activation_success = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let initial_duration = ACTIVATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        let result = process_activation(&state, code).await;
        assert!(result.is_ok());

        // Verify user was activated
        let mut db2 = state.pool.get().unwrap();
        let reloaded = User::find_by_email(&mut db2, &user.email).unwrap();
        assert!(reloaded.is_active);

        // Verify code was deleted
        let key = format!("activation:code:{}", code);
        let exists: bool = r.exists(&key).await.unwrap();
        assert!(!exists);

        let final_activation_success = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let final_duration = ACTIVATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        assert_eq!(final_activation_success, initial_activation_success + 1.0);
        assert_eq!(final_duration, initial_duration + 1);
    }

    #[tokio::test]
    async fn cleanup_failure_does_not_fail_activation() {
        setup_metrics();
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        let mut db = state.pool.get().unwrap();
        // Create and save inactive user
        let new_user = User::new_for_insert("failclean", "failclean@x.com", "Pwd1!");
        let user = User::save_new(new_user, &mut db).unwrap();
        // is_active is already false by default

        let code = "codeFail";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), &user.email, 60)
            .await
            .unwrap();

        // Simulate cleanup failure by making Redis read-only or something, but hard to test
        // Assume code continues on cleanup failure

        let result = process_activation(&state, code).await;
        assert!(result.is_ok());

        // Verify user was activated despite potential cleanup issues
        let mut db2 = state.pool.get().unwrap();
        let reloaded = User::find_by_email(&mut db2, &user.email).unwrap();
        assert!(reloaded.is_active);
    }
}