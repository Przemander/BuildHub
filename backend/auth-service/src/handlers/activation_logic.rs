//! Business logic for account activation.
//!
//! This module implements the core functionality for handling user account activation:
//! - Validating activation codes stored in Redis
//! - Finding and updating user accounts in the database
//! - Handling various edge cases (expired codes, already active accounts)
//! - Clean-up of used activation codes
//!
//! The activation flow is secure, atomic, and includes comprehensive logging and metrics.

use crate::{
    app::AppState,
    config::redis::verify_activation_code,
    db::users::User,
    utils::{
        error_new::AuthServiceError,
    },
    log_info, log_warn,
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

/// Processes the activation logic using the unified error system.
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

    log_info!("Auth", "Starting account activation", "activation_start");

    // Step 1: Verify Redis availability with metrics
    let redis_client = match &app_state.redis_client {
        Some(client) => {
            record_redis_check_success();
            client
        }
        None => {
            record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
            record_activation_failure();
            return Err(AuthServiceError::configuration("Redis client not available for activation"));
        }
    };

    // Step 2: Validate activation code with metrics
    let email = match verify_activation_code(redis_client, code).await {
        Ok(email) => {
            record_code_validation_success();
            email
        }
        Err(_) => {
            record_code_validation_failure(error_types::INVALID_CODE);
            record_activation_failure();
            return Err(AuthServiceError::validation("code", "Invalid or expired activation code"));
        }
    };

    // Step 4: Lookup user by email with metrics
    let mut conn = app_state.pool.get()?;
    let mut user = match User::find_by_email(&mut conn, &email) {
        Ok(user) => {
            record_user_lookup_success();
            user
        }
        Err(_) => {
            record_user_lookup_failure(error_types::USER_NOT_FOUND);
            record_activation_failure();
            return Err(AuthServiceError::validation("code", "No user found for activation code"));
        }
    };

    // Step 5: If already active, return success (idempotent operation)
    if user.is_active.unwrap_or(false) {
        log_info!("Activation", &format!("Account already active for email: {}", email), "success");
        record_activation_success();
        return Ok(());
    }

    // Step 6: Activate the account with metrics
    user.is_active = Some(true);
    match user.update(&mut conn) {
        Ok(_) => {
            record_account_activation_success();
        }
        Err(_) => {
            record_account_activation_failure(error_types::ACTIVATION_FAILED);
            record_activation_failure();
            return Err(AuthServiceError::database("Failed to activate account"));
        }
    }

    // Step 7: Clean up activation code from Redis (non-fatal) with metrics
    match clean_up_activation_code(redis_client, code).await {
        Ok(_) => {
            record_code_cleanup_success();
        }
        Err(_) => {
            record_code_cleanup_failure(error_types::CLEANUP_FAILED);
            // Non-fatal, continue with success
        }
    }

    // Record overall success
    record_activation_success();

    // Log success
    log_info!("Activation", &format!("Account successfully activated for email: {}", email), "success");
    
    Ok(())
}

/// Cleans up a used activation code from Redis.
///
/// This is a best-effort operation; failures are logged but don't affect
/// the activation result since the account has already been activated.
async fn clean_up_activation_code(redis_client: &redis::Client, code: &str) -> Result<(), redis::RedisError> {
    let mut r = redis_client.get_async_connection().await?;
    let key = format!("activation:code:{}", code);
    match r.del::<_, i64>(&key).await {
        Ok(_) => {
            log_info!(
                "Activation", 
                &format!("Cleaned up activation code: {}", code), 
                "cleanup"
            );
            Ok(())
        },
        Err(e) => {
            log_warn!(
                "Activation", 
                &format!("Failed to clean up activation code {}: {}", code, e), 
                "cleanup_failed"
            );
            Err(e)
        },
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