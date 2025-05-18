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
    db::users::User,
    utils::{
        email::verify_activation_code,
        metrics::AUTH_ACTIVATIONS,
    },
    log_info, log_error, log_warn,
};
use redis::AsyncCommands;
use std::fmt;

/// Result of the activation logic, for rendering appropriate responses.
///
/// Each variant represents a specific outcome of the activation process,
/// allowing the handler to render the appropriate UI response.
#[derive(Debug, PartialEq)]
pub enum ActivationLogicResult {
    /// Account was successfully activated
    Success,
    
    /// Account was already active
    AlreadyActive,
    
    /// Activation code was invalid or expired
    InvalidOrExpired,
    
    /// User account was not found for the given activation code
    NotFound,
    
    /// Redis service is unavailable
    ServiceUnavailable,
    
    /// Database is unavailable
    DatabaseUnavailable,
    
    /// Failed to update the user account
    ActivationFailed,
}

// Implement Display for better debugging and logging
impl fmt::Display for ActivationLogicResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivationLogicResult::Success => write!(f, "Success"),
            ActivationLogicResult::AlreadyActive => write!(f, "AlreadyActive"),
            ActivationLogicResult::InvalidOrExpired => write!(f, "InvalidOrExpired"),
            ActivationLogicResult::NotFound => write!(f, "NotFound"),
            ActivationLogicResult::ServiceUnavailable => write!(f, "ServiceUnavailable"),
            ActivationLogicResult::DatabaseUnavailable => write!(f, "DatabaseUnavailable"),
            ActivationLogicResult::ActivationFailed => write!(f, "ActivationFailed"),
        }
    }
}

/// Redis key prefix for storing activation codes
const ACTIVATION_CODE_PREFIX: &str = "activation:code:";

/// Processes the activation logic.
///
/// # Arguments
///
/// * `app_state` - Application state containing Redis client and database pool
/// * `code` - The activation code to verify
///
/// # Returns
///
/// An `ActivationLogicResult` enum describing the outcome of the activation attempt
///
/// # Flow
///
/// 1. Verify Redis availability
/// 2. Validate the activation code and retrieve associated email
/// 3. Get database connection
/// 4. Find the user by email
/// 5. Check if user is already active
/// 6. Activate the account
/// 7. Clean up the used activation code
pub async fn process_activation(
    app_state: &AppState,
    code: &str,
) -> ActivationLogicResult {
    // Step 1: Ensure Redis is configured
    let redis_client = if let Some(c) = &app_state.redis_client {
        c
    } else {
        log_error!("Activation", "Missing Redis client for activation", "failure");
        AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
        return ActivationLogicResult::ServiceUnavailable;
    };

    // Step 2: Verify activation code and get associated email
    let email = match verify_activation_code(redis_client, code).await {
        Ok(e) => e,
        Err(e) => {
            log_warn!(
                "Activation", 
                &format!("Invalid or expired activation code: {}, error: {}", code, e), 
                "failure"
            );
            AUTH_ACTIVATIONS.with_label_values(&["invalid_code"]).inc();
            return ActivationLogicResult::InvalidOrExpired;
        }
    };

    // Step 3: Get a database connection
    let mut conn = match app_state.pool.get() {
        Ok(c) => c,
        Err(e) => {
            log_error!("Activation", &format!("Database connection failed: {}", e), "failure");
            AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
            return ActivationLogicResult::DatabaseUnavailable;
        }
    };

    // Step 4: Lookup user by email
    let mut user = match User::find_by_email(&mut conn, &email) {
        Ok(u) => u,
        Err(e) => {
            log_warn!(
                "Activation", 
                &format!("No user found for email: {}, error: {}", email, e), 
                "failure"
            );
            AUTH_ACTIVATIONS.with_label_values(&["user_not_found"]).inc();
            return ActivationLogicResult::NotFound;
        }
    };

    // Step 5: If already active, inform the user
    if user.is_active.unwrap_or(false) {
        log_info!("Activation", &format!("Account already active for email: {}", email), "success");
        AUTH_ACTIVATIONS.with_label_values(&["already_active"]).inc();
        return ActivationLogicResult::AlreadyActive;
    }

    // Step 6: Activate the account
    user.is_active = Some(true);
    if let Err(e) = user.update(&mut conn) {
        log_error!(
            "Activation", 
            &format!("Failed to activate account for {}: {}", email, e), 
            "failure"
        );
        AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
        return ActivationLogicResult::ActivationFailed;
    }

    // Step 7: Clean up activation code from Redis (non-fatal)
    clean_up_activation_code(redis_client, code).await;

    // Log success and return success result
    log_info!("Activation", &format!("Account successfully activated for email: {}", email), "success");
    AUTH_ACTIVATIONS.with_label_values(&["success"]).inc();
    ActivationLogicResult::Success
}

/// Cleans up a used activation code from Redis.
///
/// This is a best-effort operation; failures are logged but don't affect
/// the activation result since the account has already been activated.
///
/// # Arguments
///
/// * `redis_client` - Redis client for accessing the database
/// * `code` - Activation code to remove
async fn clean_up_activation_code(redis_client: &redis::Client, code: &str) {
    if let Ok(mut r) = redis_client.get_async_connection().await {
        let key = format!("{}{}", ACTIVATION_CODE_PREFIX, code);
        match r.del::<_, i64>(&key).await {
            Ok(_) => log_info!(
                "Activation", 
                &format!("Cleaned up activation code: {}", code), 
                "cleanup"
            ),
            Err(e) => log_warn!(
                "Activation", 
                &format!("Failed to clean up activation code {}: {}", code, e), 
                "cleanup_failed"
            ),
        }
    } else {
        log_warn!(
            "Activation", 
            &format!("Could not connect to Redis to clean up code: {}", code), 
            "cleanup_failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    use crate::db::users::User;
    use redis::cmd;

    /// Test setup for Redis-related tests
    async fn setup_redis(state: &AppState) -> redis::aio::Connection {
        let mut conn = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        
        // Clear all Redis keys for a clean test environment
        let _: () = cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        
        conn
    }

    #[tokio::test]
    async fn missing_redis_returns_service_unavailable() {
        // Arrange
        let state = state_no_redis();
        
        // Act
        let res = process_activation(&state, "anycode").await;
        
        // Assert
        assert_eq!(res, ActivationLogicResult::ServiceUnavailable);
    }

    #[tokio::test]
    async fn invalid_code_returns_invalid_or_expired() {
        // Arrange
        let state = state_with_redis();
        let _ = setup_redis(&state).await;

        // Act - Use a code that doesn't exist in Redis
        let res = process_activation(&state, "no-such-code").await;
        
        // Assert
        assert_eq!(res, ActivationLogicResult::InvalidOrExpired);
    }

    #[tokio::test]
    async fn user_not_found_returns_not_found() {
        // Arrange
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;
        
        // Set up an activation code for a non-existent email
        let code = "code123";
        let email = "nouser@example.com";
        let _: () = r.set_ex(format!("{}{}", ACTIVATION_CODE_PREFIX, code), email, 60).await.unwrap();

        // Act
        let res = process_activation(&state, code).await;
        
        // Assert
        assert_eq!(res, ActivationLogicResult::NotFound);
    }

    #[tokio::test]
    async fn already_active_returns_already_active() {
        // Arrange
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        // Create and activate a user
        let mut db = state.pool.get().unwrap();
        let mut user = User::new("joe", "joe@x.com", "Pwd1!");
        user.is_active = Some(true);
        user.save(&mut db).unwrap();

        // Set up a valid activation code
        let code = "codeJoe";
        let _: () = r.set_ex(format!("{}{}", ACTIVATION_CODE_PREFIX, code), &user.email, 60).await.unwrap();

        // Act
        let res = process_activation(&state, code).await;
        
        // Assert
        assert_eq!(res, ActivationLogicResult::AlreadyActive);
    }

    #[tokio::test]
    async fn successful_activation_returns_success() {
        // Arrange
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        // Create an inactive user
        let mut db = state.pool.get().unwrap();
        let mut user = User::new("sam", "sam@x.com", "Pwd1!");
        user.is_active = Some(false);
        user.save(&mut db).unwrap();

        // Set up a valid activation code
        let code = "codeSam";
        let _: () = r.set_ex(format!("{}{}", ACTIVATION_CODE_PREFIX, code), &user.email, 60).await.unwrap();

        // Act
        let res = process_activation(&state, code).await;
        
        // Assert
        assert_eq!(res, ActivationLogicResult::Success);

        // Verify the user was activated in the database
        let mut db2 = state.pool.get().unwrap();
        let reloaded = User::find_by_email(&mut db2, &user.email).unwrap();
        assert!(reloaded.is_active.unwrap_or(false));
        
        // Verify the code was deleted from Redis
        let key = format!("{}{}", ACTIVATION_CODE_PREFIX, code);
        let exists: bool = r.exists(&key).await.unwrap();
        assert!(!exists, "Activation code should be deleted after successful activation");
    }
    
    #[tokio::test]
    async fn clean_up_activation_code_works() {
        // Arrange
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;
        
        // Set up a code in Redis
        let code = "cleanup-test-code";
        let key = format!("{}{}", ACTIVATION_CODE_PREFIX, code);
        let _: () = r.set_ex(&key, "test@example.com", 60).await.unwrap();
        
        // Verify it exists
        let exists_before: bool = r.exists(&key).await.unwrap();
        assert!(exists_before, "Key should exist before cleanup");
        
        // Act
        clean_up_activation_code(&state.redis_client.as_ref().unwrap(), code).await;
        
        // Assert
        let exists_after: bool = r.exists(&key).await.unwrap();
        assert!(!exists_after, "Key should not exist after cleanup");
    }
}