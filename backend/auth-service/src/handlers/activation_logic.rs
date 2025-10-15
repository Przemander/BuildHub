//! # Account Activation Business Logic
//!
//! Implements a secure and idempotent account activation flow.
//!
//! ## Flow
//! 1.  **Configuration Check**: Verifies that the Redis client is available.
//! 2.  **Code Validation**: Verifies the activation code against Redis. The code is
//!     single-use and is deleted upon successful verification.
//! 3.  **User Lookup**: Finds the user associated with the email from the code.
//! 4.  **Idempotency Check**: If the user is already active, the operation succeeds
//!     without making any changes.
//! 5.  **Activation**: The user's `is_active` flag is set to `true` in the database.
//!
//! ## Security & Resilience
//! - **Single-Use Codes**: Activation codes are deleted from Redis immediately after
//!   successful verification to prevent reuse.
//! - **Idempotency**: Safely retrying the activation for an already-active account
//!   results in a success response without side effects.
//! - **Clean Architecture**: Clear separation between business logic, database
//!   operations (run in a blocking thread pool), and cache operations.

use crate::{
    app::AppState,
    config::{database::get_connection, redis::verify_activation_code},
    db::users::User,
    utils::{errors::AuthServiceError, metrics},
};
use tokio::task::spawn_blocking;
use tracing::{error, info, span, warn, Instrument, Level};

/// Processes an account activation request.
pub async fn process_activation(
    app_state: &AppState,
    code: &str,
) -> Result<(), AuthServiceError> {
    // Create the root span for the entire operation.
    let span = span!(Level::INFO, "account_activation", code_length = code.len());

    // This outer async block is instrumented with the span.
    async move {
        info!("Starting account activation process");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::activation_failure();
            AuthServiceError::configuration("Activation service temporarily unavailable")
        })?;

        // ===== 2. CODE VALIDATION =====
        let email = verify_activation_code(redis_client, code)
            .await
            .map_err(|e| {
                warn!("Invalid or expired activation code provided: {}", e);
                metrics::auth::activation_failure();
                AuthServiceError::validation("code", "This activation link is invalid or has expired.")
            })?;
        
        info!(email_domain = email.split('@').nth(1).unwrap_or("unknown"), "Activation code validated");

        // ===== 3. DATABASE OPERATIONS (LOOKUP & UPDATE) =====
        let pool = app_state.pool.clone();
        
        // Create a dedicated span for the database operations, for consistency and clarity.
        let db_span = span!(Level::INFO, "db_operations");

        spawn_blocking(move || {
            let mut conn = get_connection(&pool)?;

            let mut user = User::find_by_email(&mut conn, &email)?;
            
            info!(user_id = %user.id, "User found for activation");

            if user.is_active {
                info!(user_id = %user.id, "Account already active - idempotent success");
                return Ok::<(), AuthServiceError>(());
            }

            user.is_active = true;
            user.update(&mut conn)?;
            
            info!(user_id = %user.id, "Account activated successfully in database");
            Ok(())
        })
        .instrument(db_span) // Instrument the blocking task with the dedicated db_span.
        .await
        .map_err(|e| {
            error!("Database task panicked: {}", e);
            AuthServiceError::internal("Database task failed")
        })??;

        // ===== 4. SUCCESS =====
        metrics::auth::activation_success();
        info!("Account activation process completed successfully");

        Ok(())
    }
    .instrument(span) // Instrument the main async block with the original span.
    .await
}