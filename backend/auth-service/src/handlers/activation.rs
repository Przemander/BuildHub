//! Account activation handler implementation.
//!
//! This module provides functionality for activating user accounts using
//! email activation links containing verification codes. The flow is:
//! 1. Verify the activation code stored in Redis and retrieve the associated email.
//! 2. Find the user account using the email.
//! 3. Activate the account if it is inactive.
//! 4. Remove the activation code from Redis.
//! 5. Render a styled HTML response indicating success or failure.
//!
//! Logging is focused on critical events (errors, warnings, process milestones).
//! High-frequency operations are tracked with metrics.

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use serde::Deserialize;
use redis::Client as RedisClient;
use std::env;

use crate::{log_info, log_warn, log_error, log_debug};
use crate::app::AppState;
use crate::config::database::DbPool;
use crate::db::users::User;
use crate::utils::email::verify_activation_code;
use crate::utils::errors::ApiError;
use crate::utils::metrics::{
    AUTH_ACTIVATIONS, DB_OPERATIONS, REDIS_OPERATIONS,
    REQUESTS_TOTAL, RequestTimer
};

/// Request parameters for account activation.
#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    pub code: String,
}

/// Handler for account activation requests.
///
/// This handler processes the activation by verifying the provided activation code,
/// updating the corresponding user account, cleaning up the Redis code, and returning
/// an HTML response to the user.
///
/// Returns:
/// - HTML response indicating success (200) or error (400, 404, or 500).
pub async fn activate_account_handler(
    Query(params): Query<ActivationParams>,
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/activate");
    REQUESTS_TOTAL.with_label_values(&["/auth/activate", "GET", "pending"]).inc();

    log_info!("Account Activation", "Processing activation request", "start");

    // Obtain a database pool and Redis client.
    let pool = app_state.pool.clone();
    let redis_client = match app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Account Activation", "Missing Redis client", "failure");
            AUTH_ACTIVATIONS.with_label_values(&["service_unavailable"]).inc();
            timer.set_status("500");
            timer.complete("GET");
            REQUESTS_TOTAL.with_label_values(&["/auth/activate", "GET", "500"]).inc();
            return render_error_page(&ApiError::internal_error("Service unavailable"));
        }
    };

    // Process activation logic.
    match process_activation(pool, redis_client, params.code).await {
        Ok(email) => {
            log_info!("Account Activation", "Activation completed", "success");
            AUTH_ACTIVATIONS.with_label_values(&["success"]).inc();
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/activate", "GET", "200"]).inc();
            timer.complete("GET");
            render_success_page()
        },
        Err(error) => {
            log_warn!("Account Activation", "Activation failed", "failure");
            let status_code = match error.status.as_str() {
                "bad_request" => {
                    AUTH_ACTIVATIONS.with_label_values(&["invalid_code"]).inc();
                    "400"
                },
                "not_found" => {
                    AUTH_ACTIVATIONS.with_label_values(&["user_not_found"]).inc();
                    "404"
                },
                _ => {
                    AUTH_ACTIVATIONS.with_label_values(&["system_error"]).inc();
                    "500"
                }
            };
            timer.set_status(status_code);
            REQUESTS_TOTAL.with_label_values(&["/auth/activate", "GET", status_code]).inc();
            timer.complete("GET");
            render_error_page(&error)
        }
    }
}

/// Core activation logic separated for clarity and testability.
///
/// # Arguments
/// * `pool` - The database connection pool.
/// * `redis_client` - The Redis client for activation code verification.
/// * `code` - The activation code from the query.
///
/// # Returns
/// On success, returns the email associated with the activated account.
/// On failure, returns an appropriate ApiError.
async fn process_activation(
    pool: DbPool,
    redis_client: RedisClient,
    code: String,
) -> Result<String, ApiError> {
    log_debug!("Account Activation", "Start activation process", "debug");

    // Verify the activation code in Redis and retrieve email.
    let email = match verify_activation_code(&redis_client, &code).await {
        Ok(email) => {
            REDIS_OPERATIONS.with_label_values(&["get", "success"]).inc();
            log_info!("Account Activation", "Activation code verified", "success");
            email
        },
        Err(_) => {
            REDIS_OPERATIONS.with_label_values(&["get", "failure"]).inc();
            log_warn!("Account Activation", "Activation code verification failed", "failure");
            return Err(ApiError::bad_request_error("Invalid or expired activation code"));
        }
    };

    // Obtain a database connection.
    let mut conn = match pool.get() {
        Ok(conn) => {
            DB_OPERATIONS.with_label_values(&["connection", "success"]).inc();
            log_debug!("Account Activation", "Database connection established", "debug");
            conn
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            log_error!("Account Activation", "Failed to get database connection", "failure");
            return Err(ApiError::internal_error("Database connection error"));
        }
    };

    // Find the user by email.
    let mut user = match User::find_by_email(&mut conn, &email) {
        Ok(user) => {
            DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
            log_debug!("Account Activation", "User found", "debug");
            user
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["query", "failure"]).inc();
            log_warn!("Account Activation", "User not found", "failure");
            return Err(ApiError::not_found_error("User account"));
        }
    };

    // If the user is already active, return the email immediately.
    if let Some(is_active) = user.is_active {
        if is_active {
            AUTH_ACTIVATIONS.with_label_values(&["already_active"]).inc();
            log_warn!("Account Activation", "User account already active", "warning");
            return Ok(email);
        }
    }
    log_debug!("Account Activation", "Proceeding to activate user", "debug");

    // Mark the user as active.
    user.is_active = Some(true);
    match user.update(&mut conn) {
        Ok(_) => {
            DB_OPERATIONS.with_label_values(&["update", "success"]).inc();
            log_info!("Account Activation", "User account activated", "success");
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["update", "failure"]).inc();
            log_error!("Account Activation", "Failed to update account", "failure");
            return Err(ApiError::internal_error("Failed to activate account"));
        }
    }

    // Attempt to remove the activation code from Redis.
    match redis_client.get_async_connection().await {
        Ok(mut redis_conn) => {
            REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
            let key = format!("activation:code:{}", code);
            if let Err(_) = redis::cmd("DEL")
                .arg(&[key])
                .query_async::<_, ()>(&mut redis_conn)
                .await
            {
                REDIS_OPERATIONS.with_label_values(&["del", "failure"]).inc();
                log_warn!("Account Activation", "Failed to delete activation code from Redis", "warning");
            } else {
                REDIS_OPERATIONS.with_label_values(&["del", "success"]).inc();
                log_debug!("Account Activation", "Activation code deleted", "debug");
            }
        },
        Err(_) => {
            REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            log_warn!("Account Activation", "Could not obtain Redis connection for cleanup", "warning");
            // Proceed without failing activation.
        }
    }

    Ok(email)
}

/// Renders a styled HTML success page after successful account activation.
fn render_success_page() -> Html<String> {
    log_debug!("Account Activation", "Rendering success page", "debug");
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Account Activated - BuildHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background-color: #f9f9f9;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
            margin-top: 50px;
        }
        h1 {
            color: #4a86e8;
            margin-top: 0;
        }
        .button {
            background-color: #4a86e8;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
            font-weight: 500;
            margin-top: 15px;
            transition: background-color 0.3s;
        }
        .button:hover {
            background-color: #3a76d8;
        }
        .check-icon {
            color: #4CAF50;
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="check-icon">✓</div>
        <h1>Account Activated!</h1>
        <p>Your account has been successfully activated. You can now log in to access your BuildHub account.</p>
        <a href="/login" class="button">Go to Login</a>
    </div>
</body>
</html>"#.to_string()
    )
}

/// Renders a styled HTML error page when activation fails.
fn render_error_page(error: &ApiError) -> Html<String> {
    log_debug!("Account Activation", "Rendering error page", "debug");

    let (heading, message) = match error.status.as_str() {
        "bad_request" => (
            "Invalid Activation Link",
            "The activation link is invalid or has expired. Please request a new activation link."
        ),
        "not_found" => (
            "Account Not Found",
            "We couldn't find an account associated with this activation link."
        ),
        _ => (
            "Activation Failed",
            "There was a problem activating your account. Please try again later or contact support."
        ),
    };

    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Activation Failed - BuildHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background-color: #f9f9f9;
        }}
        .container {{
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
            margin-top: 50px;
        }}
        h1 {{
            color: #e74c3c;
            margin-top: 0;
        }}
        .button {{
            background-color: #4a86e8;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
            font-weight: 500;
            margin-top: 15px;
            transition: background-color 0.3s;
        }}
        .button:hover {{
            background-color: #3a76d8;
        }}
        .error-icon {{
            color: #e74c3c;
            font-size: 48px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>{}</h1>
        <p>{}</p>
        <a href="/" class="button">Return to Home</a>
    </div>
</body>
</html>"#,
        heading,
        message
    ))
}

/// Generates an activation link by combining the frontend URL and the activation code.
///
/// # Arguments
/// * `activation_code` - The activation code.
///
/// # Returns
/// A complete URL string for activating the account.
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| {
        log_debug!("Account Activation", "Frontend URL not set", "defaulting to localhost");
        "http://localhost:3000".to_string()
    });

    log_debug!("Account Activation", "Generating activation link", "debug");
    format!("{}/auth/activate?code={}", frontend_url, activation_code)
}