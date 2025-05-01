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