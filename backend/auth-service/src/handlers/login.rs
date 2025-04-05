//! User authentication handlers implementation.
//!
//! This module provides functionality for user authentication flow, including:
//! - Login with username/password credentials
//! - Token-based authentication using JWTs
//! - Refresh token functionality
//! - Secure logout with token revocation

use axum::{Extension, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use log::{info, error};
use redis::Client as RedisClient;

use crate::config::database::DbPool;
use crate::db::users::User;
use crate::utils::jwt::{generate_token, validate_token, revoke_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
use crate::utils::errors::ApiError;

/// Request payload for login endpoint
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

/// Response structure for user data
#[derive(Debug, Serialize)]
pub struct UserResponse {
    username: String,
    email: String,
}

/// Response structure for token data
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    user: UserResponse,
}

/// Request payload for logout and token refresh endpoints
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    token: String,
}

/// Handler for user login requests.
///
/// # Authentication Flow
/// 1. Validates the username and password
/// 2. Verifies the user account is active
/// 3. Generates access and refresh tokens
/// 4. Returns tokens with user information
///
/// # Returns
/// * `200 OK` - On successful authentication with tokens
/// * `401 Unauthorized` - For invalid credentials or inactive accounts
/// * `500 Internal Server Error` - For service failures
pub async fn login_handler(
    Extension(pool): Extension<DbPool>,
    Json(login_request): Json<LoginRequest>,
) -> impl IntoResponse {
    match process_login(pool, login_request).await {
        Ok(response) => response.into_response(),
        Err(api_error) => api_error.into_response(),
    }
}

/// Core login logic separated for better testability and cleaner error handling.
async fn process_login(
    pool: DbPool,
    login_request: LoginRequest,
) -> Result<impl IntoResponse, ApiError> {
    // Obtain database connection
    let mut conn = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::internal_error("Database connection error")
        })?;

    // Find and authenticate user
    let user = authenticate_user(&mut conn, &login_request)?;
    
    // Generate tokens
    let (access_token, refresh_token) = generate_auth_tokens(&user.username)?;

    info!("User logged in successfully: {}", user.username);

    // Return success response with tokens
    Ok((
        StatusCode::OK,
        Json(json!({
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
        }))
    ))
}

/// Authenticates a user by username and password, and checks account status.
///
/// # Arguments
/// * `conn` - Database connection
/// * `login_request` - Login credentials
///
/// # Returns
/// * `Ok(User)` - Authenticated active user
/// * `Err(ApiError)` - Authentication error with appropriate status code
fn authenticate_user(
    conn: &mut diesel::SqliteConnection,
    login_request: &LoginRequest,
) -> Result<User, ApiError> {
    // Find user by username
    let user = User::find_by_username(conn, &login_request.username)
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

    Ok(user)
}

/// Generates access and refresh tokens for a user.
///
/// # Arguments
/// * `username` - Username to include in the token claims
///
/// # Returns
/// * `Ok((access_token, refresh_token))` - Generated tokens
/// * `Err(ApiError)` - If token generation fails
fn generate_auth_tokens(username: &str) -> Result<(String, String), ApiError> {
    // Generate access token
    let access_token = generate_token(username, TOKEN_TYPE_ACCESS, None)
        .map_err(|e| {
            error!("Failed to generate access token: {}", e);
            ApiError::internal_error("Authentication error")
        })?;

    // Generate refresh token
    let refresh_token = generate_token(username, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            error!("Failed to generate refresh token: {}", e);
            ApiError::internal_error("Authentication error")
        })?;
        
    Ok((access_token, refresh_token))
}

/// Handler for user logout requests.
///
/// Revokes the provided token by adding it to a blocklist in Redis.
///
/// # Returns
/// * `200 OK` - On successful logout
/// * `500 Internal Server Error` - If token revocation fails
pub async fn logout_handler(
    Extension(redis_client): Extension<RedisClient>,
    Json(logout_request): Json<TokenRequest>,
) -> impl IntoResponse {
    match process_logout(redis_client, logout_request.token).await {
        Ok(response) => response.into_response(),
        Err(api_error) => api_error.into_response(),
    }
}

/// Core logout logic separated for better testability.
async fn process_logout(
    redis_client: RedisClient,
    token: String,
) -> Result<impl IntoResponse, ApiError> {
    // Revoke the token
    revoke_token(&token, &redis_client).await
        .map_err(|e| {
            error!("Failed to revoke token: {}", e);
            ApiError::internal_error("Failed to logout")
        })?;
    
    info!("Token successfully revoked");
    
    // Return success response
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Successfully logged out"
        }))
    ))
}

/// Handler for token refresh requests.
///
/// Validates the provided refresh token, revokes it, and issues new tokens.
///
/// # Returns
/// * `200 OK` - On successful token refresh with new tokens
/// * `400 Bad Request` - If the token is not a valid refresh token
/// * `401 Unauthorized` - If the token is invalid or expired
/// * `500 Internal Server Error` - If token generation fails
pub async fn refresh_token_handler(
    Extension(redis_client): Extension<RedisClient>,
    Json(refresh_request): Json<TokenRequest>,
) -> impl IntoResponse {
    match process_token_refresh(redis_client, refresh_request.token).await {
        Ok(response) => response.into_response(),
        Err(api_error) => api_error.into_response(),
    }
}

/// Core token refresh logic separated for better testability.
async fn process_token_refresh(
    redis_client: RedisClient,
    token: String,
) -> Result<impl IntoResponse, ApiError> {
    // Validate the refresh token
    let claims = validate_token(&token, &redis_client).await?;

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

    // Revoke the old refresh token (best-effort)
    if let Err(e) = revoke_token(&token, &redis_client).await {
        error!("Failed to revoke old refresh token: {}, continuing anyway", e);
        // Continue anyway since we'll issue a new token
    }

    // Generate a new refresh token
    let new_refresh_token = generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None)
        .map_err(|e| {
            error!("Failed to generate new refresh token: {}", e);
            ApiError::internal_error("Token refresh failed")
        })?;

    info!("Tokens refreshed for user: {}", claims.sub);

    // Return success response with new tokens
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Tokens refreshed successfully",
            "data": {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer"
            }
        }))
    ))
}