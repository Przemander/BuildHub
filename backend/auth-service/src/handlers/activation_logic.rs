//! Business logic for account activation.

use crate::{
    app::AppState,
    db::users::User,
    utils::email::verify_activation_code,
    utils::metrics::AUTH_ACTIVATIONS,
    log_info, log_error, log_warn,
};
use redis::AsyncCommands;

/// Result of the activation logic, for rendering.
pub enum ActivationLogicResult {
    Success,
    AlreadyActive,
    InvalidOrExpired,
    NotFound,
    ServiceUnavailable,
    DatabaseUnavailable,
    ActivationFailed,
}

/// Processes the activation logic.
///
/// Returns an enum describing the result for the handler to render.
pub async fn process_activation(
    app_state: &AppState,
    code: &str,
) -> ActivationLogicResult {
    // Ensure Redis is configured
    let redis_client = if let Some(c) = &app_state.redis_client {
        c
    } else {
        log_error!("Activation", "Missing Redis client for activation", "failure");
        AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
        return ActivationLogicResult::ServiceUnavailable;
    };

    // Verify activation code and get associated email
    let email = match verify_activation_code(redis_client, code).await {
        Ok(e) => e,
        Err(_) => {
            log_warn!("Activation", &format!("Invalid or expired activation code: {}", code), "failure");
            AUTH_ACTIVATIONS.with_label_values(&["invalid_code"]).inc();
            return ActivationLogicResult::InvalidOrExpired;
        }
    };

    // Get a database connection
    let mut conn = match app_state.pool.get() {
        Ok(c) => c,
        Err(e) => {
            log_error!("Activation", &format!("Database connection failed: {}", e), "failure");
            AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
            return ActivationLogicResult::DatabaseUnavailable;
        }
    };

    // Lookup user by email
    let mut user = match User::find_by_email(&mut conn, &email) {
        Ok(u) => u,
        Err(_) => {
            log_warn!("Activation", &format!("No user found for email: {}", email), "failure");
            AUTH_ACTIVATIONS.with_label_values(&["user_not_found"]).inc();
            return ActivationLogicResult::NotFound;
        }
    };

    // If already active, inform the user
    if user.is_active.unwrap_or(false) {
        log_info!("Activation", &format!("Account already active for email: {}", email), "success");
        AUTH_ACTIVATIONS.with_label_values(&["already_active"]).inc();
        return ActivationLogicResult::AlreadyActive;
    }

    // Activate the account
    user.is_active = Some(true);
    if let Err(e) = user.update(&mut conn) {
        log_error!("Activation", &format!("Failed to activate account for {}: {}", email, e), "failure");
        AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
        return ActivationLogicResult::ActivationFailed;
    }

    // Clean up activation code from Redis (non-fatal)
    if let Ok(mut r) = redis_client.get_async_connection().await {
        let _: Result<(), _> = r.del(format!("activation:code:{}", code)).await;
    }

    log_info!("Activation", &format!("Account successfully activated for email: {}", email), "success");
    AUTH_ACTIVATIONS.with_label_values(&["success"]).inc();
    ActivationLogicResult::Success
}