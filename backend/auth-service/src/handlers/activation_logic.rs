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
        metrics::AUTH_ACTIVATIONS,
    },
    log_info, log_warn,
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
    // Step 1: Ensure Redis is configured
    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis client not available for activation"))?;

    // Step 2: Verify activation code and get associated email
    let email = verify_activation_code(redis_client, code).await?;

    // Step 3: Get a database connection
    let mut conn = app_state.pool.get()?;

    // Step 4: Lookup user by email
    let mut user = User::find_by_email(&mut conn, &email)
        .map_err(|_| AuthServiceError::validation("code", "No user found for activation code"))?;

    // Step 5: If already active, return success (idempotent operation)
    if user.is_active.unwrap_or(false) {
        log_info!("Activation", &format!("Account already active for email: {}", email), "success");
        AUTH_ACTIVATIONS.with_label_values(&["already_active"]).inc();
        return Ok(());
    }

    // Step 6: Activate the account
    user.is_active = Some(true);
    user.update(&mut conn)?;

    // Step 7: Clean up activation code from Redis (non-fatal)
    clean_up_activation_code(redis_client, code).await;

    // Log success
    log_info!("Activation", &format!("Account successfully activated for email: {}", email), "success");
    AUTH_ACTIVATIONS.with_label_values(&["success"]).inc();
    
    Ok(())
}

/// Cleans up a used activation code from Redis.
///
/// This is a best-effort operation; failures are logged but don't affect
/// the activation result since the account has already been activated.
async fn clean_up_activation_code(redis_client: &redis::Client, code: &str) {
    if let Ok(mut r) = redis_client.get_async_connection().await {
        let key = format!("activation:code:{}", code);
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

    async fn setup_redis(state: &AppState) -> redis::aio::Connection {
        let mut conn = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        
        let _: () = cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn missing_redis_returns_configuration_error() {
        let state = state_no_redis();
        let result = process_activation(&state, "anycode").await;
        
        assert!(result.is_err());
        match result.err().unwrap() {
            AuthServiceError::Configuration(msg) => {
                assert!(msg.contains("Redis client"));
            }
            other => panic!("Expected configuration error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn invalid_code_returns_validation_error() {
        let state = state_with_redis();
        let _ = setup_redis(&state).await;

        let result = process_activation(&state, "no-such-code").await;
        
        assert!(result.is_err());
        matches!(result.err().unwrap(), AuthServiceError::Validation(_));
    }

    #[tokio::test]
    async fn user_not_found_returns_validation_error() {
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;
        
        let code = "code123";
        let email = "nouser@example.com";
        let _: () = r.set_ex(format!("activation:code:{}", code), email, 60).await.unwrap();

        let result = process_activation(&state, code).await;
        
        assert!(result.is_err());
        matches!(result.err().unwrap(), AuthServiceError::Validation(_));
    }

    #[tokio::test]
    async fn already_active_returns_success() {
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        let mut db = state.pool.get().unwrap();
        let mut user = User::new("joe", "joe@x.com", "Pwd1!");
        user.is_active = Some(true);
        user.save(&mut db).unwrap();

        let code = "codeJoe";
        let _: () = r.set_ex(format!("activation:code:{}", code), &user.email, 60).await.unwrap();

        let result = process_activation(&state, code).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn successful_activation_works() {
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        let mut db = state.pool.get().unwrap();
        let mut user = User::new("sam", "sam@x.com", "Pwd1!");
        user.is_active = Some(false);
        user.save(&mut db).unwrap();

        let code = "codeSam";
        let _: () = r.set_ex(format!("activation:code:{}", code), &user.email, 60).await.unwrap();

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
    }
}