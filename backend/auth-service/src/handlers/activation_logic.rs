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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{state_no_redis, state_with_redis};
    use crate::db::users::User;
    use redis::cmd;

    #[tokio::test]
    async fn missing_redis_returns_service_unavailable() {
        let state = state_no_redis();
        let res = process_activation(&state, "anycode").await;
        assert!(matches!(res, ActivationLogicResult::ServiceUnavailable));
    }

    #[tokio::test]
    async fn invalid_code_returns_invalid_or_expired() {
        let state = state_with_redis();
        // flush any old keys
        let mut conn = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut conn).await.unwrap();

        let res = process_activation(&state, "no-such-code").await;
        assert!(matches!(res, ActivationLogicResult::InvalidOrExpired));
    }

    #[tokio::test]
    async fn user_not_found_returns_not_found() {
        let state = state_with_redis();
        // seed an activation code for a non‐existent email
        let mut r = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        let code = "code123";
        let email = "nouser@example.com";
        let _: () = cmd("FLUSHDB").query_async(&mut r).await.unwrap();
        let _: () = r.set_ex(format!("activation:code:{}", code), email, 60).await.unwrap();

        let res = process_activation(&state, code).await;
        assert!(matches!(res, ActivationLogicResult::NotFound));
    }

    #[tokio::test]
    async fn already_active_returns_already_active() {
        let state = state_with_redis();
        let mut r = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut r).await.unwrap();

        // insert and activate user
        let mut db = state.pool.get().unwrap();
        let mut u = User::new("joe", "joe@x.com", "Pwd1!");
        u.is_active = Some(true);
        u.save(&mut db).unwrap();

        let code = "codeJoe";
        let _: () = r.set_ex(format!("activation:code:{}", code), &u.email, 60).await.unwrap();

        let res = process_activation(&state, code).await;
        assert!(matches!(res, ActivationLogicResult::AlreadyActive));
    }

    #[tokio::test]
    async fn successful_activation_returns_success() {
        let state = state_with_redis();
        // flush + seed code→email
        let mut r = state.redis_client
            .as_ref().unwrap()
            .get_async_connection().await.unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut r).await.unwrap();

        // create inactive user
        let mut db = state.pool.get().unwrap();
        let mut u = User::new("sam", "sam@x.com", "Pwd1!");
        u.is_active = Some(false);
        u.save(&mut db).unwrap();

        let code = "codeSam";
        let _: () = r.set_ex(format!("activation:code:{}", code), &u.email, 60).await.unwrap();

        let res = process_activation(&state, code).await;
        assert!(matches!(res, ActivationLogicResult::Success));

        // verify DB updated
        let mut db2 = state.pool.get().unwrap();
        let reloaded = User::find_by_email(&mut db2, &u.email).unwrap();
        assert!(reloaded.is_active.unwrap_or(false));
    }
}