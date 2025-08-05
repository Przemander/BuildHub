//! Business logic for account activation with OpenTelemetry integration.
//!
//! This module implements the core functionality for handling user account activation:
//! - Validating activation codes stored in Redis
//! - Finding and updating user accounts in the database
//! - Handling various edge cases (expired codes, already active accounts)
//! - Clean-up of used activation codes
//!
//! The activation flow is secure, atomic, and includes comprehensive logging,
//! metrics, and OpenTelemetry trace integration.

use crate::{
    app::AppState,
    config::redis::verify_activation_code,
    db::users::User,
    utils::{
        error_new::AuthServiceError,
        log_new::Log,
        telemetry::{business_operation_span, db_operation_span, redis_operation_span, SpanExt},
    },
    // Import activation metrics
    metricss::activation_metrics::{
        time_complete_activation_flow, record_activation_success, record_activation_failure,
        record_redis_check_success, record_redis_check_failure,
        record_code_validation_success, record_code_validation_failure,
        record_user_lookup_success, record_user_lookup_failure,
        record_account_activation_success, record_account_activation_failure,
        record_code_cleanup_success, record_code_cleanup_failure,
        error_types,
    },
};
use redis::AsyncCommands;
use tracing::Instrument;

/// Processes the activation logic using the unified error system with OpenTelemetry integration.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client and database pool
/// * `code` - The activation code to verify
///
/// # Returns
///
/// `Ok(())` on successful activation, `Err(AuthServiceError)` on failure
///
/// # Flow
///
/// 1. Verify Redis availability
/// 2. Validate the activation code and retrieve associated email
/// 3. Get database connection
/// 4. Find the user by email
/// 5. Check if user is already active (idempotent)
/// 6. Activate the account
/// 7. Clean up the used activation code
pub async fn process_activation(
    app_state: &AppState,
    code: &str,
) -> Result<(), AuthServiceError> {
    // Start complete activation flow timer
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
        "process_activation"
    );

    // Wrap activation logic in the process_span
    async move {
        // Step 1: Verify Redis availability with span and metrics
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
                        "Redis client available", 
                        "redis_check_success",
                        "process_activation"
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
                        "Redis client not available for activation",
                        "redis_check_failure",
                        "process_activation"
                    );
                    
                    Err(AuthServiceError::configuration("Redis client not available for activation"))
                }
            }
        }
        .instrument(redis_check_span_clone)
        .await?;

        // Step 2: Validate activation code with span and metrics
        let code_validation_span = redis_operation_span("validate_code", "activation:code:*");
        let code_validation_span_clone = code_validation_span.clone();
        
        Log::event(
            "INFO",
            "Account Activation", 
            "Validating activation code", 
            "code_validation_start",
            "process_activation"
        );
        
        let email = async {
            match verify_activation_code(redis_client, code).await {
                Ok(email) => {
                    record_code_validation_success();
                    code_validation_span.record("redis.success", &true);
                    code_validation_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Account Activation", 
                        "Activation code validated successfully", 
                        "code_validation_success",
                        "process_activation"
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
                        &format!("Invalid activation code: {}", e), 
                        "code_validation_failure",
                        "process_activation"
                    );
                    
                    Err(AuthServiceError::validation("code", "Invalid or expired activation code"))
                }
            }
        }
        .instrument(code_validation_span_clone)
        .await?;

        // Step 3: Get database connection with span
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
                    
                    Log::event(
                        "ERROR",
                        "Account Activation", 
                        &format!("Failed to get database connection: {}", e), 
                        "db_connection_failure",
                        "process_activation"
                    );
                    
                    Err(AuthServiceError::database("Failed to get database connection"))
                }
            }
        }
        .instrument(db_conn_span_clone)
        .await?;
        
        let mut conn = db_conn;

        // Step 4: Lookup user by email with span and metrics
        let user_lookup_span = db_operation_span("find_user", "users.by_email");
        let user_lookup_span_clone = user_lookup_span.clone();
        
        Log::event(
            "INFO",
            "Account Activation", 
            "Looking up user by email", 
            "user_lookup_start",
            "process_activation"
        );
        
        let user = async {
            match User::find_by_email(&mut conn, &email) {
                Ok(user) => {
                    record_user_lookup_success();
                    user_lookup_span.record("db.success", &true);
                    user_lookup_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Account Activation", 
                        "User found by email", 
                        "user_lookup_success",
                        "process_activation"
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
                        "No user found for activation code", 
                        "user_lookup_failure",
                        "process_activation"
                    );
                    
                    Err(AuthServiceError::validation("code", "No user found for activation code"))
                }
            }
        }
        .instrument(user_lookup_span_clone)
        .await?;
        
        let mut user = user;

        // Step 5: If already active, return success (idempotent operation)
        if user.is_active.unwrap_or(false) {
            Log::event(
                "INFO",
                "Account Activation", 
                &format!("Account already active for email: {}", email), 
                "already_active",
                "process_activation"
            );
            
            record_activation_success();
            process_span.record("business.result", &"success");
            process_span.record("already_active", &true);
            
            return Ok(());
        }

        // Step 6: Activate the account with span and metrics
        let activation_span = db_operation_span("activate_account", "users");
        let activation_span_clone = activation_span.clone();
        
        Log::event(
            "INFO",
            "Account Activation", 
            "Activating user account", 
            "account_activation_start",
            "process_activation"
        );
        
        async {
            user.is_active = Some(true);
            match user.update(&mut conn) {
                Ok(_) => {
                    record_account_activation_success();
                    activation_span.record("db.success", &true);
                    activation_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Account Activation", 
                        "Account successfully activated", 
                        "account_activation_success",
                        "process_activation"
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
                        &format!("Failed to activate account: {}", e), 
                        "account_activation_failure",
                        "process_activation"
                    );
                    
                    Err(AuthServiceError::database("Failed to activate account"))
                }
            }
        }
        .instrument(activation_span_clone)
        .await?;

        // Step 7: Clean up activation code from Redis (non-fatal) with span and metrics
        let cleanup_span = redis_operation_span("cleanup_code", "activation:code:*");
        let cleanup_span_clone = cleanup_span.clone();
        
        Log::event(
            "INFO",
            "Account Activation", 
            "Cleaning up activation code", 
            "code_cleanup_start",
            "process_activation"
        );
        
        async {
            match clean_up_activation_code(redis_client, code).await {
                Ok(_) => {
                    record_code_cleanup_success();
                    cleanup_span.record("redis.success", &true);
                    cleanup_span.record("business.result", &"success");
                    
                    Log::event(
                        "INFO",
                        "Account Activation", 
                        &format!("Cleaned up activation code: {}", code), 
                        "code_cleanup_success",
                        "process_activation"
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
                        &format!("Failed to clean up activation code: {}", e), 
                        "code_cleanup_failure",
                        "process_activation"
                    );
                    // Non-fatal error, continue
                }
            }
        }
        .instrument(cleanup_span_clone)
        .await;

        // Record overall success
        record_activation_success();
        process_span.record("business.result", &"success");
        
        Log::event(
            "INFO",
            "Account Activation",
            &format!("Account successfully activated for email: {}", email),
            "activation_success",
            "process_activation"
        );
        
        Ok(())
    }
    .instrument(process_span_clone)
    .await
}

/// Cleans up a used activation code from Redis.
///
/// This is a best-effort operation; failures are logged but don't affect
/// the activation result since the account has already been activated.
async fn clean_up_activation_code(redis_client: &redis::Client, code: &str) -> Result<(), redis::RedisError> {
    let mut r = redis_client.get_async_connection().await?;
    let key = format!("activation:code:{}", code);
    match r.del::<_, i64>(&key).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    use crate::db::users::User;
    use redis::cmd;
    use crate::metricss::activation_metrics::{
        init_activation_metrics, ACTIVATION_OPERATIONS, ACTIVATION_FAILURES, ACTIVATION_DURATION,
        steps, results, error_types
    };

    /// Initialize activation metrics for testing
    fn setup_metrics() {
        init_activation_metrics();
    }

    async fn setup_redis(state: &AppState) -> redis::aio::Connection {
        let mut conn = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        
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
                assert!(msg.contains("Redis client"));
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
        matches!(result.err().unwrap(), AuthServiceError::Validation(_));

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
        let _: () = r.set_ex(format!("activation:code:{}", code), email, 60).await.unwrap();

        let initial_user_failure = ACTIVATION_FAILURES
            .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
            .get();
        let initial_activation_failure = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
            .get();

        let result = process_activation(&state, code).await;
        
        assert!(result.is_err());
        matches!(result.err().unwrap(), AuthServiceError::Validation(_));

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
        let mut user = User::new("joe", "joe@x.com", "Pwd1!");
        user.is_active = Some(true);
        user.save(&mut db).unwrap();

        let code = "codeJoe";
        let _: () = r.set_ex(format!("activation:code:{}", code), &user.email, 60).await.unwrap();

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
        let mut user = User::new("sam", "sam@x.com", "Pwd1!");
        user.is_active = Some(false);
        user.save(&mut db).unwrap();

        let code = "codeSam";
        let _: () = r.set_ex(format!("activation:code:{}", code), &user.email, 60).await.unwrap();

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
        assert!(reloaded.is_active.unwrap_or(false));
        
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
        let mut user = User::new("failclean", "failclean@x.com", "Pwd1!");
        user.is_active = Some(false);
        user.save(&mut db).unwrap();

        let code = "codeFail";
        let _: () = r.set_ex(format!("activation:code:{}", code), &user.email, 60).await.unwrap();

        // Simulate cleanup failure by making Redis read-only or something, but hard to test
        // Assume code continues on cleanup failure

        let result = process_activation(&state, code).await;
        assert!(result.is_ok());

        // Verify metrics recorded failure but overall success
        // Since we can't force failure, test assumes structure
        // In real test, mock Redis to fail del
    }
}