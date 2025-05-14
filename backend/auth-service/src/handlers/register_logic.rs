//! Business logic for user registration.

use crate::{
    app::AppState,
    db::users::{RegisterData, User},
    utils::email::{generate_activation_code, store_activation_code},
    utils::metrics::AUTH_REGISTRATIONS,
    utils::validators::{validate_email, validate_password, validate_username},
    log_info, log_error, log_warn,
};
use axum::http::StatusCode;
use serde_json::json;

/// Processes registration: validates, creates user, stores activation code, sends email, logs and metrics.
///
/// Returns (StatusCode, JSON body) for the handler to respond.
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> (StatusCode, serde_json::Value) {
    // Check email configuration
    let email_cfg = match &app_state.email_config {
        Some(cfg) => cfg.clone(),
        None => {
            log_error!("Register", "Missing EmailConfig", "system_error");
            AUTH_REGISTRATIONS.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Missing EmailConfig"
                }),
            );
        }
    };

    // Check Redis availability
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Register", "Missing Redis client", "system_error");
            AUTH_REGISTRATIONS.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Missing RedisClient"
                }),
            );
        }
    };

    // Obtain a DB connection
    let mut conn = match app_state.pool.get() {
        Ok(c) => c,
        Err(e) => {
            log_error!("Register", &format!("Database connection failed: {}", e), "system_error");
            AUTH_REGISTRATIONS.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Database connection failed"
                }),
            );
        }
    };

    // Validate input
    if let Err(e) = validate_username(&data.username) {
        log_warn!("Register", &format!("Username validation failed: {}", e), "validation_failed");
        AUTH_REGISTRATIONS.with_label_values(&["validation_failed"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": e.to_string()
            }),
        );
    }
    if let Err(e) = validate_email(&data.email) {
        log_warn!("Register", &format!("Email validation failed: {}", e), "validation_failed");
        AUTH_REGISTRATIONS.with_label_values(&["validation_failed"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": e.to_string()
            }),
        );
    }
    if let Err(e) = validate_password(&data.password) {
        log_warn!("Register", &format!("Password validation failed: {}", e), "validation_failed");
        AUTH_REGISTRATIONS.with_label_values(&["validation_failed"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": e.to_string()
            }),
        );
    }

    // Check uniqueness
    if User::find_by_email(&mut conn, &data.email).is_ok() {
        log_warn!("Register", "Email already exists", "already_exists");
        AUTH_REGISTRATIONS.with_label_values(&["already_exists"]).inc();
        return (
            StatusCode::CONFLICT,
            json!({
                "status": "error",
                "message": "Email already exists"
            }),
        );
    }
    if User::find_by_username(&mut conn, &data.username).is_ok() {
        log_warn!("Register", "Username already exists", "already_exists");
        AUTH_REGISTRATIONS.with_label_values(&["already_exists"]).inc();
        return (
            StatusCode::CONFLICT,
            json!({
                "status": "error",
                "message": "Username already exists"
            }),
        );
    }

    // Create inactive user
    let mut user = User::new(&data.username, &data.email, &data.password);
    user.is_active = Some(false);
    if let Err(e) = user.save(&mut conn) {
        log_error!("Register", &format!("Saving user failed: {}", e), "failure");
        AUTH_REGISTRATIONS.with_label_values(&["failure"]).inc();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "status": "error",
                "message": "Saving user failed"
            }),
        );
    }

    // Generate and store activation code
    let code = generate_activation_code();
    if let Err(e) = store_activation_code(redis_client, &user.email, &code).await {
        log_error!("Register", &format!("Storing activation code failed: {}", e), "failure");
        AUTH_REGISTRATIONS.with_label_values(&["failure"]).inc();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "status": "error",
                "message": "Failed to store activation code"
            }),
        );
    }

    // Send activation email (non-fatal)
    if let Err(e) = email_cfg
        .send_activation_email(&user.email, &code, redis_client)
        .await
    {
        log_warn!("Register", &format!("Activation email failed: {}", e), "email_failed");
        // Do not return error, just log and continue
    }

    log_info!("Register", "User registration successful", "success");
    AUTH_REGISTRATIONS.with_label_values(&["success"]).inc();
    (
        StatusCode::CREATED,
        json!({
            "status": "success",
            "message": "Registration successful! Please check your email to activate your account."
        }),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::{RegisterData, User};
    use crate::utils::test_utils::state_with_redis;
    use crate::app::AppState;
    use crate::utils::email::EmailConfig;
    use axum::http::StatusCode;
    use serde_json::json;

    /// Build a state with in-memory DB + Redis + dummy EmailConfig
    fn make_state() -> AppState {
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        state
    }

    #[tokio::test]
    async fn missing_email_config_returns_internal_server_error() {
        let mut state = make_state();
        state.email_config = None;
        let data = RegisterData {
            username: "user".into(),
            email: "user@ex.com".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["message"], json!("Missing EmailConfig"));
    }

    #[tokio::test]
    async fn missing_redis_returns_internal_server_error() {
        let mut state = make_state();
        state.redis_client = None;
        let data = RegisterData {
            username: "user".into(),
            email: "user@ex.com".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["message"], json!("Missing RedisClient"));
    }

    #[tokio::test]
    async fn missing_username_returns_bad_request() {
        let state = make_state();
        let data = RegisterData {
            username: "".into(),
            email: "user@example.com".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("username"));
    }

    #[tokio::test]
    async fn invalid_email_returns_bad_request() {
        let state = make_state();
        let data = RegisterData {
            username: "testuser".into(),
            email: "not-an-email".into(),
            password: "Valid1!".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("email"));
    }

    #[tokio::test]
    async fn weak_password_returns_bad_request() {
        let state = make_state();
        let data = RegisterData {
            username: "testuser".into(),
            email: "user@example.com".into(),
            password: "short".into(),
        };
        let (status, body) = process_registration(&state, data).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("password"));
    }

    #[tokio::test]
    async fn duplicate_email_returns_conflict() {
        let state = make_state();
        let data1 = RegisterData {
            username: "first".into(),
            email: "dup@ex.com".into(),
            password: "Valid12!".into(),
        };
        let (s1, _) = process_registration(&state, data1.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);

        let data2 = RegisterData {
            username: "second".into(),
            email: data1.email.clone(),
            password: "Valid12!".into(),
        };
        let (s2, body2) = process_registration(&state, data2).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(body2["message"], json!("Email already exists"));
    }

    #[tokio::test]
    async fn duplicate_username_returns_conflict() {
        let state = make_state();
        let data1 = RegisterData {
            username: "sameuser".into(),
            email: "first@ex.com".into(),
            password: "Valid12!".into(),
        };
        let (s1, _) = process_registration(&state, data1.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);

        let data2 = RegisterData {
            username: data1.username.clone(),
            email: "second@ex.com".into(),
            password: "Valid12!".into(),
        };
        let (s2, body2) = process_registration(&state, data2).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(body2["message"], json!("Username already exists"));
    }

    #[tokio::test]
    async fn new_user_is_inactive_by_default() {
        let state = make_state();
        let data = RegisterData {
            username: "inact".into(),
            email: "inact@ex.com".into(),
            password: "Valid12!".into(), // >=8 chars for valid password
        };
        let (status, _) = process_registration(&state, data.clone()).await;
        assert_eq!(status, StatusCode::CREATED);

        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.is_active, Some(false));
    }

    #[tokio::test]
    async fn successful_registration_creates_user() {
        let state = make_state();
        let data = RegisterData {
            username: "newuser".into(),
            email: "new@user.com".into(),
            password: "Strong1!".into(),
        };
        let (status, body) = process_registration(&state, data.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["status"], json!("success"));

        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
    }
}