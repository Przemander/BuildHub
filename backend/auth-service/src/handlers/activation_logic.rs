//! Account activation business logic.
//!
//! Implements secure account activation with Redis-backed verification codes,
//! idempotent operations, and comprehensive observability.

use crate::{
    app::AppState,
    config::redis::verify_activation_code,
    db::users::User,
    utils::{errors::AuthServiceError, metrics},
    
};
use redis::AsyncCommands;
use tracing::{error, info, span, warn, Instrument, Level};

/// Process account activation request.
///
/// # Flow
/// 1. Verify Redis availability
/// 2. Validate activation code
/// 3. Find user by email
/// 4. Check idempotency (already active?)
/// 5. Activate account
/// 6. Clean up activation code
/// 7. Return success
///
/// # Security
/// - One-time activation codes
/// - Automatic code cleanup
/// - Idempotent operations (safe to retry)
pub async fn process_activation(
    app_state: &AppState,
    code: &str,
) -> Result<(), AuthServiceError> {
    // Create root span for the operation
    let span = span!(Level::INFO, "account_activation",
        code_length = code.len()
    );

    let span_for_instrument = span.clone();

    async move {
        info!("Starting account activation");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::activation_failure();
            AuthServiceError::configuration("Activation service temporarily unavailable")
        })?;

        // ===== 2. CODE VALIDATION =====
        let validation_span = span!(Level::INFO, "code_validation");
        let email = async {
            verify_activation_code(redis_client, code).await.map_err(|e| {
                warn!("Invalid activation code: {}", e);
                metrics::auth::activation_failure();
                AuthServiceError::validation(
                    "code",
                    "This activation link is invalid or has expired"
                )
            })
        }
        .instrument(validation_span)
        .await?;
        
        info!("Activation code validated for email");
        metrics::external::redis_success("verify_activation_code");

        // ===== 3. USER LOOKUP =====
        let db_span = span!(Level::INFO, "db_lookup");
        let mut user = async {
            let mut conn = app_state.pool.get().map_err(|e| {
                error!("Failed to get database connection: {}", e);
                metrics::db::connection_failed();
                metrics::auth::activation_failure();
                AuthServiceError::database("Unable to process activation. Please try again later.")
            })?;
            metrics::db::connection_acquired();

            User::find_by_email(&mut conn, &email).map_err(|e| {
                warn!("User not found for activation email {}: {}", email, e);
                metrics::db::query_failure("find_user_by_email");
                metrics::auth::activation_failure();
                AuthServiceError::validation(
                    "code",
                    "This activation code is invalid or the account no longer exists"
                )
            })
        }
        .instrument(db_span)
        .await?;
        
        metrics::db::query_success("find_user_by_email");
        span.record("user_id", &user.id.to_string());
        info!(user_id = %user.id, "User found for activation");

        // ===== 4. IDEMPOTENCY CHECK =====
        if user.is_active {
            info!(user_id = %user.id, "Account already active - idempotent success");
            metrics::auth::activation_success();
            return Ok(());
        }

        // ===== 5. ACTIVATE ACCOUNT =====
        let activation_span = span!(Level::INFO, "account_activation");
        async {
            let mut conn = app_state.pool.get().map_err(|e| {
                error!("Failed to get database connection: {}", e);
                metrics::db::connection_failed();
                metrics::auth::activation_failure();
                AuthServiceError::database("Unable to activate account. Please try again later.")
            })?;
            metrics::db::connection_acquired();

            user.is_active = true;
            user.update(&mut conn).map_err(|e| {
                error!(user_id = %user.id, "Failed to update user activation status: {}", e);
                metrics::db::query_failure("update_user");
                metrics::auth::activation_failure();
                AuthServiceError::database("Unable to activate account. Please try again later.")
            })?;
            
            info!(user_id = %user.id, "Account activated successfully");
            metrics::db::query_success("update_user");
            Ok::<_, AuthServiceError>(())
        }
        .instrument(activation_span)
        .await?;

        // ===== 6. CODE CLEANUP (BEST EFFORT) =====
        let cleanup_span = span!(Level::INFO, "code_cleanup");
        async {
            if let Err(e) = clean_up_activation_code(redis_client, code).await {
                warn!("Failed to clean up activation code (non-critical): {}", e);
                metrics::external::redis_failure("delete_activation_code");
                // Continue - activation was successful
            } else {
                info!("Activation code cleaned up");
                metrics::external::redis_success("delete_activation_code");
            }
        }
        .instrument(cleanup_span)
        .await;

        // ===== 7. SUCCESS =====
        metrics::auth::activation_success();
        info!(user_id = %user.id, "Account activation completed successfully");

        Ok(())
    }
    .instrument(span_for_instrument)
    .await
}

/// Clean up used activation code from Redis.
async fn clean_up_activation_code(
    redis_client: &redis::Client,
    code: &str,
) -> Result<(), redis::RedisError> {
    let mut conn = redis_client.get_async_connection().await?;
    let key = format!("activation:code:{}", code);
    conn.del::<_, i64>(&key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    use redis::cmd;

    async fn setup_redis(state: &AppState) -> redis::aio::Connection {
        let mut conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn test_missing_redis_returns_configuration_error() {
        let state = state_no_redis();
        let result = process_activation(&state, "anycode").await;
        assert!(matches!(result, Err(AuthServiceError::Configuration(_))));
    }

    #[tokio::test]
    async fn test_invalid_code_returns_validation_error() {
        let state = state_with_redis();
        let _ = setup_redis(&state).await;

        let result = process_activation(&state, "no-such-code").await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_user_not_found_returns_validation_error() {
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;

        // Set up activation code for non-existent user
        let code = "code123";
        let email = "nouser@example.com";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), email, 60)
            .await
            .unwrap();

        let result = process_activation(&state, code).await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_already_active_is_idempotent() {
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;
        let mut db = state.pool.get().unwrap();

        // Create active user
        let new_user = User::new_for_insert("joe", "joe@example.com", "Password1!");
        let mut user = User::save_new(new_user, &mut db).unwrap();
        user.is_active = true;
        user.update(&mut db).unwrap();

        // Set up activation code
        let code = "codeJoe";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), &user.email, 60)
            .await
            .unwrap();

        // Should succeed without error
        let result = process_activation(&state, code).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_successful_activation() {
        let state = state_with_redis();
        let mut r = setup_redis(&state).await;
        let mut db = state.pool.get().unwrap();

        // Create inactive user
        let new_user = User::new_for_insert("sam", "sam@example.com", "Password1!");
        let user = User::save_new(new_user, &mut db).unwrap();
        assert!(!user.is_active);

        // Set up activation code
        let code = "codeSam";
        let _: () = r
            .set_ex(format!("activation:code:{}", code), &user.email, 60)
            .await
            .unwrap();

        // Activate
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
    }
}