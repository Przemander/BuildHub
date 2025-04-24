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

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use crate::app::AppState;
use crate::config::database::DbPool;
use crate::db::users::{User, RegisterData};
use crate::utils::email::{EmailConfig, generate_activation_code, store_activation_code};
use crate::utils::errors::{ApiError, ServiceError};
use crate::utils::validators::{validate_username, validate_email, validate_password};
use crate::{log_info, log_warn, log_error, log_debug};
use redis::Client as RedisClient;
use crate::utils::metrics::{
    AUTH_REGISTRATIONS, DB_OPERATIONS, 
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
    let mut timer = RequestTimer::start("/auth/register", "POST");
    REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "pending"]).inc();
    
    // Retrieve shared resources.
    let pool = app_state.pool.clone();
    let email_config = match &app_state.email_config {
        Some(cfg) => cfg.clone(),
        None => {
            log_error!("Registration", "Missing Email configuration", "failure");
            timer.set_status("500");
            // timer.complete(); // Drop will handle completion
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "500"]).inc();
            return ApiError::internal_error("Missing EmailConfig").into_response();
        }
    };
    let redis_client = match &app_state.redis_client {
        Some(r) => r.clone(),
        None => {
            log_error!("Registration", "Missing Redis client", "failure");
            timer.set_status("500");
            // timer.complete(); // Drop will handle completion
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "500"]).inc();
            return ApiError::internal_error("Missing RedisClient").into_response();
        }
    };

    match process_registration(pool, &email_config, &redis_client, register_data).await {
        Ok(response) => {
            log_info!("Registration", "Registration process complete", "success");
            AUTH_REGISTRATIONS.with_label_values(&["success"]).inc();
            timer.set_status("201");
            // timer.complete(); // Drop will handle completion
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", "201"]).inc();
            response.into_response()
        },
        Err(service_error) => {
            log_warn!("Registration", "Registration process failed", "failure");
            let api_error = ApiError::from(service_error);
            let status_code = match api_error.status.as_str() {
                "bad_request" | "validation_error" => {
                    AUTH_REGISTRATIONS.with_label_values(&["validation_error"]).inc();
                    "400"
                },
                "unique_constraint_error" | "already_exists" => {
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
            // timer.complete(); // Drop will handle completion
            REQUESTS_TOTAL.with_label_values(&["/auth/register", "POST", status_code]).inc();
            api_error.into_response()
        },
    }
}

/// Core registration logic separated for clarity and testability.
async fn process_registration(
    pool: DbPool,
    email_config: &EmailConfig,
    redis_client: &RedisClient,
    register_data: RegisterData,
) -> Result<impl IntoResponse, ServiceError> {
    // Obtain a database connection.
    let mut conn = pool.get().map_err(|_| {
        DB_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        log_error!("Registration", "Failed to get database connection", "failure");
        ServiceError::Internal("Database connection error".to_string())
    })?;
    DB_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    log_debug!("Registration", "Database connection obtained", "success");

    // Validate input and enforce uniqueness.
    validate_registration(&register_data, &mut conn)?;

    // Create a new inactive user.
    let user = create_inactive_user(&mut conn, &register_data)?;

    // Generate an activation code and store it in Redis.
    let activation_code = generate_activation_code();
    store_activation_code(redis_client, &user.email, &activation_code).await?;

    log_info!("Registration", "Activation code stored", "success");

    // Send activation email (non-fatal if it fails).
    match email_config.send_activation_email(&user.email, &activation_code, redis_client).await {
        Ok(_) => {
            EMAILS_SENT.with_label_values(&["activation", "success"]).inc();
            log_info!("Registration", "Activation email sent", "success");
        },
        Err(e) => {
            EMAILS_SENT.with_label_values(&["activation", "failure"]).inc();
            log_warn!("Registration", &format!("Activation email failed: {}", e), "failure");
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
/// Handles unique constraint violations as already_exists errors.
fn create_inactive_user(
    conn: &mut diesel::SqliteConnection,
    data: &RegisterData,
) -> Result<User, ServiceError> {
    let mut user = User::new(&data.username, &data.email, &data.password);
    user.is_active = Some(false);

    DB_OPERATIONS.with_label_values(&["insert", "attempt"]).inc();
    match user.save(conn) {
        Ok(_) => {
            DB_OPERATIONS.with_label_values(&["insert", "success"]).inc();
            log_debug!("Registration", "User saved to database", "success");
        }
        Err(e) => {
            DB_OPERATIONS.with_label_values(&["insert", "failure"]).inc();
            log_error!("Registration", &format!("Failed to save user: {}", e), "failure");
            // Handle unique constraint violation from DB as already_exists
            if let diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation, _
            ) = e {
                return Err(ServiceError::Validation(crate::utils::errors::ValidationError::AlreadyExists("user".to_string())));
            }
            return Err(ServiceError::Internal("Failed to register user. Database error.".to_string()));
        }
    }

    // Diesel SQLite does not support RETURNING *; fetch user by email.
    DB_OPERATIONS.with_label_values(&["query", "attempt"]).inc();
    let found_user = User::find_by_email(conn, &data.email).map_err(|e| {
        DB_OPERATIONS.with_label_values(&["query", "failure"]).inc();
        log_error!("Registration", &format!("User verification failed: {}", e), "failure");
        ServiceError::Internal("Failed to retrieve user after registration.".to_string())
    })?;
    DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
    Ok(found_user)
}

/// Validates registration data and checks for uniqueness.
/// All validation errors are mapped to "validation_error" and uniqueness to "already_exists".
fn validate_registration(
    data: &RegisterData,
    conn: &mut diesel::SqliteConnection,
) -> Result<(), ServiceError> {
    log_debug!("Registration", "Begin data validation", "success");
    
    validate_username(&data.username)
        .map_err(|e| {
            AUTH_REGISTRATIONS.with_label_values(&["validation_error"]).inc();
            ServiceError::Validation(e)
        })?;
    log_debug!("Registration", "Username validation passed", "success");
    
    validate_email(&data.email)
        .map_err(|e| {
            AUTH_REGISTRATIONS.with_label_values(&["validation_error"]).inc();
            ServiceError::Validation(e)
        })?;
    log_debug!("Registration", "Email validation passed", "success");
    
    validate_password(&data.password)
        .map_err(|e| {
            AUTH_REGISTRATIONS.with_label_values(&["validation_error"]).inc();
            ServiceError::Validation(e)
        })?;
    log_debug!("Registration", "Password validation passed", "success");

    DB_OPERATIONS.with_label_values(&["query", "attempt"]).inc();
    if User::find_by_email(conn, &data.email).is_ok() {
        DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
        AUTH_REGISTRATIONS.with_label_values(&["already_exists"]).inc();
        log_warn!("Registration", "Email uniqueness check failed", "failure");
        return Err(ServiceError::Validation(crate::utils::errors::ValidationError::AlreadyExists("email".to_string())));
    }
    DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
    log_debug!("Registration", "Email uniqueness check passed", "success");

    DB_OPERATIONS.with_label_values(&["query", "attempt"]).inc();
    if User::find_by_username(conn, &data.username).is_ok() {
        DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
        AUTH_REGISTRATIONS.with_label_values(&["already_exists"]).inc();
        log_warn!("Registration", "Username uniqueness check failed", "failure");
        return Err(ServiceError::Validation(crate::utils::errors::ValidationError::AlreadyExists("username".to_string())));
    }
    DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
    log_debug!("Registration", "Username uniqueness check passed", "success");

    Ok(())
}