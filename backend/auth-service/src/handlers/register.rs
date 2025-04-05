//! User registration handler implementation.
//!
//! This module provides functionality for creating new user accounts,
//! including validation, database storage, and email activation.

use axum::{Extension, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use crate::config::database::DbPool;
use crate::db::users::{User, RegisterData};
use crate::utils::email::{EmailConfig, generate_activation_code};
use crate::utils::errors::ApiError;
use crate::utils::validators::{validate_username, validate_email, validate_password};
use serde_json::json;
use log::{info, error};
use redis::Client as RedisClient;

/// Handler for user registration requests.
///
/// # Request Flow
/// 1. Validates input data (username, email, password)
/// 2. Creates a new inactive user in the database
/// 3. Generates an activation code and stores it in Redis
/// 4. Sends an activation email to the user
/// 5. Returns a success response
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `email_config` - Email service configuration
/// * `redis_client` - Redis client for activation code storage
/// * `register_data` - User registration data from request body
///
/// # Returns
/// * `201 Created` - On successful registration
/// * `400 Bad Request` - For invalid input data
/// * `500 Internal Server Error` - For database or service failures
pub async fn register_handler(
    Extension(pool): Extension<DbPool>,
    Extension(email_config): Extension<EmailConfig>,
    Extension(redis_client): Extension<RedisClient>,
    Json(register_data): Json<RegisterData>,
) -> impl IntoResponse {
    // Process registration and map the result to HTTP response
    match process_registration(pool, email_config, redis_client, register_data).await {
        Ok(response) => response.into_response(),
        Err(api_error) => api_error.into_response(),
    }
}

/// Core registration logic separated for better testability and cleaner error handling.
async fn process_registration(
    pool: DbPool,
    email_config: EmailConfig,
    redis_client: RedisClient,
    register_data: RegisterData,
) -> Result<impl IntoResponse, ApiError> {
    // Obtain database connection
    let mut conn = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::internal_error("Database connection error")
        })?;

    // Validate input data
    validate_registration(&register_data, &mut conn)?;

    // Create and save inactive user
    let user = create_inactive_user(&mut conn, &register_data)?;
    info!("User created successfully: {}", user.username);
    
    // Generate and store activation code
    let activation_code = generate_activation_code();
    store_activation_code(&redis_client, &user.email, &activation_code).await?;
    info!("Activation code stored for: {}", user.email);

    // Send activation email with the Redis client
    match email_config.send_activation_email(&user.email, &activation_code, &redis_client).await {
        Ok(_) => info!("Activation email sent to {}", user.email),
        Err(e) => error!("Failed to send activation email: {} - user can request a new one", e),
    }
    
    // Return success response
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "status": "success",
            "message": "Registration successful! Please check your email to activate your account."
        }))
    ))
}

/// Creates a new inactive user and saves it to the database.
fn create_inactive_user(
    conn: &mut diesel::SqliteConnection,
    data: &RegisterData,
) -> Result<User, ApiError> {
    // Create user with inactive status
    let mut user = User::new(&data.username, &data.email, &data.password);
    user.is_active = Some(false);
    
    // Save to database
    user.save(conn)
        .map_err(|e| {
            error!("Failed to save user: {}", e);
            ApiError::internal_error("Failed to register user. Database error.")
        })?;

    // Fetch the saved user from the database
    User::find_by_email(conn, &data.email)
        .map_err(|e| {
            error!("Failed to fetch saved user: {}", e);
            ApiError::internal_error("Failed to retrieve user after registration.")
        })
}

/// Validates registration data using the utility validation functions
/// and checks for uniqueness constraints in the database.
///
/// # Arguments
/// * `data` - Registration data to validate
/// * `conn` - Database connection for uniqueness checks
///
/// # Returns
/// * `Ok(())` - If validation passes
/// * `Err(ApiError)` - With specific validation error
fn validate_registration(
    data: &RegisterData,
    conn: &mut diesel::SqliteConnection,
) -> Result<(), ApiError> {
    // Validate format of inputs
    validate_username(&data.username)?;
    validate_email(&data.email)?;
    validate_password(&data.password)?;

    // Check uniqueness constraints
    // Using is_ok() to check for existence is idiomatic in this case
    if User::find_by_email(conn, &data.email).is_ok() {
        return Err(ApiError::unique_constraint_error(
            "email", 
            "Email already exists"
        ));
    }

    if User::find_by_username(conn, &data.username).is_ok() {
        return Err(ApiError::unique_constraint_error(
            "username", 
            "Username already exists"
        ));
    }

    Ok(())
}

/// Store activation code in Redis with expiration.
///
/// # Arguments
/// * `redis_client` - Redis client
/// * `email` - User's email address (will be stored as value)
/// * `code` - Activation code (used as part of the key)
///
/// # Returns
/// * `Ok(())` - If storage succeeds
/// * `Err(ApiError)` - If Redis operation fails
async fn store_activation_code(
    redis_client: &RedisClient, 
    email: &str, 
    code: &str
) -> Result<(), ApiError> {
    use redis::AsyncCommands;

    // Get async connection
    let mut conn = redis_client.get_async_connection().await
        .map_err(|e| {
            error!("Redis connection error: {}", e);
            ApiError::internal_error(&format!("Service unavailable - please try again later"))
        })?;
    
    // Key format: activation:code:{uuid}
    let key = format!("activation:code:{}", code);
    
    // Store email as value with 24-hour expiration (86400 seconds)
    // Using a constant would be better for the expiration time
    const ACTIVATION_CODE_EXPIRY: u64 = 86_400; // 24 hours in seconds
    
    conn.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_EXPIRY as usize).await
        .map_err(|e| {
            error!("Failed to store activation code: {}", e);
            ApiError::internal_error("Failed to complete registration. Please try again later.")
        })?;
    
    Ok(())
}