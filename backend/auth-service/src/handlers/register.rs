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

pub async fn register_handler(
    Extension(pool): Extension<DbPool>,
    Extension(email_config): Extension<EmailConfig>,
    Extension(redis_client): Extension<RedisClient>,
    Json(register_data): Json<RegisterData>,
) -> impl IntoResponse {
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to get database connection: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Database connection error"})),
            );
        }
    };

    // Validate input data
    if let Err(e) = validate_registration(&register_data, &mut conn) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": e.message})),
        );
    }

    // Create an inactive user
    let mut user = User::new(
        &register_data.username,
        &register_data.email,
        &register_data.password,
    );
    user.is_active = Some(false);

    // Save the user to database
    match user.save(&mut conn) {
        Ok(_) => {
            info!("User created successfully: {}", register_data.username);
            
            // Generate a unique activation code
            let activation_code = generate_activation_code();

            // Store activation code in Redis
            match store_activation_code(&redis_client, &register_data.email, &activation_code).await {
                Ok(_) => {
                    info!("Activation code stored for: {}", register_data.email);

                    // Send activation email
                    if let Err(e) = email_config.send_activation_email(
                        &register_data.email,
                        &activation_code,
                    ) {
                        error!("Failed to send activation email: {}", e);
                        // Continue anyway - user can request another activation email
                    } else {
                        info!("Activation email sent to {}", register_data.email);
                    }
                    
                    // Return success response
                    (
                        StatusCode::CREATED,
                        Json(json!({
                            "status": "success",
                            "message": "Registration successful! Please check your email to activate your account."
                        }))
                    )
                },
                Err(e) => {
                    error!("Failed to store activation code: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "status": "error",
                            "message": "Failed to complete registration. Please try again later."
                        }))
                    )
                }
            }
        },
        Err(e) => {
            error!("Failed to save user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": "Failed to register user. Database error."
                }))
            )
        }
    }
}

/// Validates registration data using the utility validation functions
/// and checks for uniqueness constraints in the database.
fn validate_registration(
    data: &RegisterData,
    conn: &mut diesel::SqliteConnection,
) -> Result<(), ApiError> {
    // Use the imported validation functions
    validate_username(&data.username)?;
    validate_email(&data.email)?;
    validate_password(&data.password)?;

    // Check if email already exists
    if User::find_by_email(conn, &data.email).is_ok() {
        return Err(ApiError::unique_constraint_error(
            "email", 
            "Email already exists"
        ));
    }

    // Check if username already exists
    if User::find_by_username(conn, &data.username).is_ok() {
        return Err(ApiError::unique_constraint_error(
            "username", 
            "Username already exists"
        ));
    }

    Ok(())
}

/// Store activation code in Redis
async fn store_activation_code(redis_client: &RedisClient, email: &str, code: &str) -> Result<(), ApiError> {
    use redis::AsyncCommands;

    // Get async connection
    let mut conn = redis_client.get_async_connection().await
        .map_err(|e| ApiError::internal_error(&format!("Redis connection error: {}", e)))?;
    
    // Key format: activation:code:{uuid}
    let key = format!("activation:code:{}", code);
    
    // Store email as value with 24-hour expiration (86400 seconds)
    conn.set_ex::<_, _, ()>(key, email, 86400).await
        .map_err(|e| ApiError::internal_error(&format!("Failed to store activation code: {}", e)))?;
    
    Ok(())
}