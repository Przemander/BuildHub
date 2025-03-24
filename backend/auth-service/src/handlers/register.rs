use axum::{Extension, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use crate::config::database::DbPool;
use crate::db::users::{User, RegisterData};
use crate::utils::errors::ApiError;
use crate::utils::validators::{validate_username, validate_email, validate_password};
use serde_json::json;
use log::info;

pub async fn register_handler(
    Extension(pool): Extension<DbPool>,
    Json(register_data): Json<RegisterData>,
) -> impl IntoResponse {
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(_) => {
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
            Json(json!({"status": e.status, "message": e.message})),
        );
    }

    let user = User::new(&register_data.username, &register_data.email, &register_data.password);
    match user.save(&mut conn) {
        Ok(_) => {
            info!("User registered successfully: {}", register_data.username);
            (
                StatusCode::CREATED,
                Json(json!({"status": "success", "message": "User registered successfully"}))
            )
        }
        Err(_) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Failed to register user"}))
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