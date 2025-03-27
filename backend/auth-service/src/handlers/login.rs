use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use log::{info, error};

use crate::config::database::DbPool;
use crate::db::users::User;
use crate::utils::jwt::{generate_token, validate_token, revoke_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
use crate::utils::errors::ApiError;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    username: String,
    email: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    token: String,
}

pub async fn login_handler(
    Extension(pool): Extension<DbPool>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get database connection
    let mut conn = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::internal_error("Database connection error")
        })?;

    // Find user by username
    let user = User::find_by_username(&mut conn, &login_request.username)
        .map_err(|_| {
            info!("Login failed: user not found - {}", login_request.username);
            ApiError::unauthorized_error("Invalid username or password")
        })?;

    // Verify password
    match user.verify_password(&login_request.password) {
        Ok(is_valid) if is_valid => {},
        Ok(_) => {
            info!("Login failed: invalid password for user - {}", login_request.username);
            return Err(ApiError::unauthorized_error("Invalid username or password"));
        },
        Err(e) => {
            error!("Password verification error for user {}: {}", login_request.username, e);
            return Err(ApiError::internal_error("Password verification failed"));
        }
    }

    // Check if user is active
    if let Some(is_active) = user.is_active {
        if !is_active {
            info!("Login failed: user is not active - {}", login_request.username);
            return Err(ApiError::unauthorized_error("Account is not activated"));
        }
    }

    // Generate access token
    let access_token = generate_token(&user.username, TOKEN_TYPE_ACCESS, None)
        .map_err(|e| {
            error!("Failed to generate access token: {}", e);
            ApiError::internal_error("Authentication error")
        })?;

    // Generate refresh token
    let refresh_token = generate_token(&user.username, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            error!("Failed to generate refresh token: {}", e);
            ApiError::internal_error("Authentication error")
        })?;

    info!("User logged in successfully: {}", user.username);

    // Return tokens
    Ok(Json(json!({
        "status": "success",
        "message": "Login successful",
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "user": {
                "username": user.username,
                "email": user.email,
            }
        }
    })))
}

pub async fn logout_handler(
    Extension(redis_client): Extension<redis::Client>,
    Json(logout_request): Json<LogoutRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Revoke the token
    revoke_token(&logout_request.token, &redis_client).await
        .map_err(|e| {
            error!("Failed to revoke token: {}", e);
            ApiError::internal_error("Failed to logout")
        })?;
    
    info!("Token successfully revoked");
    
    Ok(Json(json!({
        "status": "success",
        "message": "Successfully logged out"
    })))
}

pub async fn refresh_token_handler(
    Extension(redis_client): Extension<redis::Client>,
    Json(refresh_request): Json<LogoutRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate the refresh token
    let claims = validate_token(&refresh_request.token, &redis_client).await?;

    // Check if it's actually a refresh token
    if claims.token_type != TOKEN_TYPE_REFRESH {
        return Err(ApiError::bad_request_error("Not a refresh token"));
    }

    // Generate a new access token
    let new_access_token = generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None)
        .map_err(|e| {
            error!("Failed to generate new access token: {}", e);
            ApiError::internal_error("Token refresh failed")
        })?;

    // Revoke the old refresh token
    if let Err(e) = revoke_token(&refresh_request.token, &redis_client).await {
        error!("Failed to revoke old refresh token: {}", e);
        // Continue anyway since we'll issue a new token
    }

    // Generate a new refresh token
    let new_refresh_token = generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            error!("Failed to generate new refresh token: {}", e);
            ApiError::internal_error("Token refresh failed")
        })?;

    info!("Tokens refreshed for user: {}", claims.sub);

    Ok(Json(json!({
        "status": "success",
        "message": "Tokens refreshed successfully",
        "data": {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer"
        }
    })))
}