//! User registration handler implementation.
//!
//! This module provides functionality for creating new user accounts,
//! including input validation, database storage, and email activation.
//!
//! The registration request flow is as follows:
//! 1. Validate the user input: username, email, and password.
//! 2. Create a new inactive user in the database.
//! 3. Generate an activation code and store it in Redis.
//! 4. Send an activation email to the user.
//! 5. Return success (201) or appropriate error responses.
//!
//! Best practices applied:
//! - Clear inline documentation using Rust doc comments.
//! - Structured logging (INFO/WARN/ERROR) for high-level process changes.
//! - Integrated metrics for high-frequency events.
//! - Separation of concerns via the dedicated process_registration function.
//! - Early returns for error conditions using the Result type.

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use crate::app::AppState;
use crate::config::database::DbPool;
use crate::db::users::{User, RegisterData};
use crate::utils::email::{EmailConfig, generate_activation_code};
use crate::utils::errors::ApiError;
use crate::utils::validators::{validate_username, validate_email, validate_password};
use crate::{log_info, log_warn, log_error, log_debug};
use redis::Client as RedisClient;
use crate::utils::metrics::{
    AUTH_REGISTRATIONS, DB_OPERATIONS, REDIS_OPERATIONS, 
    EMAILS_SENT, REQUESTS_TOTAL, RequestTimer
};

/// Handler for user registration requests.
///
/// # Flow
/// 1. Validates input data.
/// 2. Creates an inactive user in the database.
/// 3. Generates an activation code and stores it in Redis.
/// 4. Sends an activation email (non-fatal if it fails).
/// 5. Returns a JSON response with status 201 on success.
pub async fn register_handler(
    State(app_state): State<AppState>,
    Json(register_data): Json<RegisterData>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/register");
    REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "pending"]).inc();
    
    // Retrieve shared resources.
    let pool = app_state.pool.clone();
    let email_config = match &app_state.email_config {
        Some(cfg) => cfg.clone(),
        None => {
            log_error!("Registration", "Missing Email configuration", "failure");
            timer.set_status("500");
            timer.complete("POST");
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "500"]).inc();
            return ApiError::internal_error("Missing EmailConfig").into_response();
        }
    };
    let redis_client = match &app_state.redis_client {
        Some(r) => r.clone(),
        None => {
            log_error!("Registration", "Missing Redis client", "failure");
            timer.set_status("500");
            timer.complete("POST");
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "500"]).inc();
            return ApiError::internal_error("Missing RedisClient").into_response();
        }
    };

    match process_registration(pool, email_config, redis_client, register_data).await {
        Ok(response) => {
            log_info!("Registration", "Registration process complete", "success");
            AUTH_REGISTRATIONS.with_label_values(&["success"]).inc();
            timer.set_status("201");
            timer.complete("POST");
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "201"]).inc();
            response.into_response()
        },
        Err(api_error) => {
            log_warn!("Registration", "Registration process failed", "failure");
            let status_code = match api_error.status.as_str() {
                "bad_request" => {
                    AUTH_REGISTRATIONS.with_label_values(&["validation_error"]).inc();
                    "400"
                },
                "conflict" => {
                    AUTH_REGISTRATIONS.with_label_values(&["already_exists"]).inc();
                    "409"
                },
                "internal_error" => {
                    AUTH_REGISTRATIONS.with_label_values(&["system_error"]).inc();
                    "500"
                },
                _ => {
                    AUTH_REGISTRATIONS.with_label_values(&["failure"]).inc();
                    "400"
                }
            };
            timer.set_status(status_code);
            timer.complete("POST");
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", status_code]).inc();
            api_error.into_response()
        },
    }
}

/// Core registration logic separated for clarity and testability.
async fn process_registration(
    pool: DbPool,
    email_config: EmailConfig,
    redis_client: RedisClient,
    register_data: RegisterData,
) -> Result<impl IntoResponse, ApiError> {
    // Obtain a database connection.
    let mut conn = match pool.get() {
        Ok(conn) => {
            DB_OPERATIONS.with_label_values(&["connection", "success"]).inc();
            log_debug!("Registration", "Database connection obtained", "success");
            conn
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            log_error!("Registration", "Failed to get database connection", "failure");
            return Err(ApiError::internal_error("Database connection error"));
        }
    };

    // Validate input and enforce uniqueness.
    validate_registration(&register_data, &mut conn)?;

    // Create a new inactive user.
    let user = match create_inactive_user(&mut conn, &register_data) {
        Ok(user) => {
            DB_OPERATIONS.with_label_values(&["insert", "success"]).inc();
            log_info!("Registration", "User created", "success");
            user
        },
        Err(e) => {
            DB_OPERATIONS.with_label_values(&["insert", "failure"]).inc();
            return Err(e);
        }
    };
    
    // Generate an activation code and store it in Redis.
    let activation_code = generate_activation_code();
    if let Err(e) = store_activation_code(&redis_client, &user.email, &activation_code).await {
        REDIS_OPERATIONS.with_label_values(&["set_ex", "failure"]).inc();
        return Err(e);
    }
    REDIS_OPERATIONS.with_label_values(&["set_ex", "success"]).inc();
    log_info!("Registration", "Activation code stored", "success");

    // Send activation email (non-fatal if it fails).
    match email_config.send_activation_email(&user.email, &activation_code, &redis_client).await {
        Ok(_) => {
            EMAILS_SENT.with_label_values(&["activation", "success"]).inc();
            log_info!("Registration", "Activation email sent", "success");
        },
        Err(_) => {
            EMAILS_SENT.with_label_values(&["activation", "failure"]).inc();
            log_warn!("Registration", "Activation email failed", "failure");
        }
    }
    
    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "status": "success",
            "message": "Registration successful! Please check your email to activate your account."
        }))
    ))
}

/// Creates an inactive user and saves it to the database.
fn create_inactive_user(
    conn: &mut diesel::SqliteConnection,
    data: &RegisterData,
) -> Result<User, ApiError> {
    let mut user = User::new(&data.username, &data.email, &data.password);
    user.is_active = Some(false);
    
    DB_OPERATIONS.with_label_values(&["insert", "attempt"]).inc();
    match user.save(conn) {
        Ok(_) => {
            DB_OPERATIONS.with_label_values(&["insert", "success"]).inc();
            log_debug!("Registration", "User saved to database", "success");
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["insert", "failure"]).inc();
            log_error!("Registration", "Failed to save user", "failure");
            return Err(ApiError::internal_error("Failed to register user. Database error."));
        }
    }

    DB_OPERATIONS.with_label_values(&["query", "attempt"]).inc();
    match User::find_by_email(conn, &data.email) {
        Ok(user) => {
            DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
            Ok(user)
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["query", "failure"]).inc();
            log_error!("Registration", "User verification failed", "failure");
            Err(ApiError::internal_error("Failed to retrieve user after registration."))
        }
    }
}

/// Validates registration data and checks for uniqueness.
fn validate_registration(
    data: &RegisterData,
    conn: &mut diesel::SqliteConnection,
) -> Result<(), ApiError> {
    log_debug!("Registration", "Begin data validation", "success");
    
    if let Err(e) = validate_username(&data.username) {
        AUTH_REGISTRATIONS.with_label_values(&["invalid_username"]).inc();
        return Err(e);
    }
    log_debug!("Registration", "Username validation passed", "success");
    
    if let Err(e) = validate_email(&data.email) {
        AUTH_REGISTRATIONS.with_label_values(&["invalid_email"]).inc();
        return Err(e);
    }
    log_debug!("Registration", "Email validation passed", "success");
    
    if let Err(e) = validate_password(&data.password) {
        AUTH_REGISTRATIONS.with_label_values(&["invalid_password"]).inc();
        return Err(e);
    }
    log_debug!("Registration", "Password validation passed", "success");

    DB_OPERATIONS.with_label_values(&["query", "attempt"]).inc();
    if User::find_by_email(conn, &data.email).is_ok() {
        DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
        AUTH_REGISTRATIONS.with_label_values(&["email_exists"]).inc();
        log_warn!("Registration", "Email uniqueness check failed", "failure");
        return Err(ApiError::unique_constraint_error("email", "Email already exists"));
    }
    DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
    log_debug!("Registration", "Email uniqueness check passed", "success");

    DB_OPERATIONS.with_label_values(&["query", "attempt"]).inc();
    if User::find_by_username(conn, &data.username).is_ok() {
        DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
        AUTH_REGISTRATIONS.with_label_values(&["username_exists"]).inc();
        log_warn!("Registration", "Username uniqueness check failed", "failure");
        return Err(ApiError::unique_constraint_error("username", "Username already exists"));
    }
    DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
    log_debug!("Registration", "Username uniqueness check passed", "success");

    Ok(())
}

/// Stores an activation code in Redis with a 24‑hour expiry.
async fn store_activation_code(
    redis_client: &RedisClient, 
    email: &str, 
    code: &str
) -> Result<(), ApiError> {
    use redis::AsyncCommands;

    let mut conn = match redis_client.get_async_connection().await {
        Ok(conn) => {
            REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
            log_debug!("Registration", "Redis connection obtained", "success");
            conn
        },
        Err(_) => {
            REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            log_error!("Registration", "Redis connection failed", "failure");
            return Err(ApiError::internal_error("Service unavailable - please try again later"));
        }
    };
    
    let key = format!("activation:code:{}", code);
    const ACTIVATION_CODE_EXPIRY: u64 = 86_400;
    
    match conn.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_EXPIRY as usize).await {
        Ok(_) => {
            REDIS_OPERATIONS.with_label_values(&["set_ex", "success"]).inc();
            log_debug!("Registration", "Activation code stored in Redis", "success");
            Ok(())
        },
        Err(_) => {
            REDIS_OPERATIONS.with_label_values(&["set_ex", "failure"]).inc();
            log_error!("Registration", "Failed to store activation code in Redis", "failure");
            Err(ApiError::internal_error("Failed to complete registration. Please try again later."))
        }
    }
}