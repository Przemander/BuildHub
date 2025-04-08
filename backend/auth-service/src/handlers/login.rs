//! User authentication handlers implementation.
//!
//! This module provides functionality for user authentication flow, including:
//! - Login with username/password credentials
//! - Token-based authentication using JWTs
//! - Refresh token functionality
//! - Secure logout with token revocation

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use redis::Client as RedisClient;

// Import Log explicitly with no reference to error, info since we won't use them directly
use crate::utils::log::Log;
use crate::app::AppState;
use crate::config::database::DbPool;
use crate::db::users::User;
use crate::utils::errors::ApiError;
use crate::utils::jwt::{generate_token, validate_token, revoke_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    username: String,
    email: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    user: UserResponse,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    token: String,
}

/// Handler for user login requests.
pub async fn login_handler(
    State(app_state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> impl IntoResponse {
    Log::event(
        "INFO",
        "Authentication",
        "Login attempt",
        "in_progress"
    );

    // Record the username for tracking
    let username = login_request.username.clone();

    match process_login(app_state.pool.clone(), login_request).await {
        Ok(response) => {
            // Record metrics
            app_state.metrics.record_authentication("success");
            app_state.metrics.record_token_operation("issue", "access");
            app_state.metrics.record_token_operation("issue", "refresh");
            
            Log::event(
                "INFO",
                "Authentication",
                "Login complete",
                "success"
            );
            
            response.into_response()
        },
        Err(api_error) => {
            // Record failed authentication metric
            app_state.metrics.record_authentication("failure");
            
            // Log failure with reason
            Log::event(
                "WARN",
                "Authentication",
                "Login failed",
                "failure"
            );
            
            api_error.into_response()
        },
    }
}

async fn process_login(
    pool: DbPool,
    login_request: LoginRequest,
) -> Result<impl IntoResponse, ApiError> {
    let username = login_request.username.clone();
    
    Log::event(
        "INFO",
        "Authentication",
        "Get database connection",
        "in_progress"
    );

    let mut conn = pool.get().map_err(|e| {
        Log::event(
            "ERROR",
            "Authentication",
            "Get database connection",
            "failure"
        );
        ApiError::internal_error("Database connection error")
    })?;

    Log::event(
        "INFO",
        "Authentication",
        "Authenticate user credentials",
        "in_progress"
    );

    let user = authenticate_user(&mut conn, &login_request)?;
    
    Log::event(
        "INFO",
        "Authentication",
        "Generate authentication tokens",
        "in_progress"
    );

    let (access_token, refresh_token) = generate_auth_tokens(&user.username)?;

    Log::event(
        "INFO",
        "Authentication",
        "Authentication process completed",
        "success"
    );

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

fn authenticate_user(
    conn: &mut diesel::SqliteConnection,
    login_request: &LoginRequest,
) -> Result<User, ApiError> {
    // First try to find the user
    Log::event(
        "INFO",
        "Authentication",
        "Find user by username",
        "in_progress"
    );
    
    let user = User::find_by_username(conn, &login_request.username).map_err(|_| {
        Log::event(
            "WARN",
            "Authentication",
            "Find user by username",
            "failure"
        );
        
        ApiError::unauthorized_error("Invalid username or password")
    })?;
    
    Log::event(
        "INFO",
        "Authentication",
        "User found in database",
        "success"
    );

    // Validate password
    Log::event(
        "INFO",
        "Authentication",
        "Verify password",
        "in_progress"
    );

    match user.verify_password(&login_request.password) {
        Ok(true) => {
            Log::event(
                "INFO",
                "Authentication",
                "Verify password",
                "success"
            );
        },
        Ok(false) => {
            Log::event(
                "WARN",
                "Authentication",
                "Verify password",
                "failure"
            );
            return Err(ApiError::unauthorized_error("Invalid username or password"));
        },
        Err(_) => {
            Log::event(
                "ERROR",
                "Authentication",
                "Password verification process",
                "failure"
            );
            return Err(ApiError::internal_error("Password verification failed"));
        }
    }

    // Check if account is activated
    Log::event(
        "INFO", 
        "Authentication",
        "Check account activation status",
        "in_progress"
    );
    
    if let Some(false) = user.is_active {
        Log::event(
            "WARN", 
            "Authentication", 
            "Check account activation status", 
            "failure"
        );
        return Err(ApiError::unauthorized_error("Account is not activated"));
    }
    
    Log::event(
        "INFO", 
        "Authentication",
        "Check account activation status",
        "success"
    );

    Ok(user)
}

fn generate_auth_tokens(username: &str) -> Result<(String, String), ApiError> {
    // Generate access token
    Log::event(
        "INFO", 
        "Authentication",
        "Generate access token",
        "in_progress"
    );

    let access_token = generate_token(username, TOKEN_TYPE_ACCESS, None).map_err(|_| {
        Log::event(
            "ERROR", 
            "Authentication",
            "Generate access token",
            "failure"
        );
        ApiError::internal_error("Authentication error")
    })?;
    
    Log::event(
        "INFO", 
        "Authentication",
        "Generate access token",
        "success"
    );

    // Generate refresh token
    Log::event(
        "INFO", 
        "Authentication",
        "Generate refresh token",
        "in_progress"
    );

    let refresh_token = generate_token(username, TOKEN_TYPE_REFRESH, None).map_err(|_| {
        Log::event(
            "ERROR", 
            "Authentication",
            "Generate refresh token",
            "failure"
        );
        ApiError::internal_error("Authentication error")
    })?;
    
    Log::event(
        "INFO", 
        "Authentication",
        "Generate refresh token",
        "success"
    );

    Ok((access_token, refresh_token))
}

/// Handler for user logout requests.
pub async fn logout_handler(
    State(app_state): State<AppState>,
    Json(logout_request): Json<TokenRequest>,
) -> impl IntoResponse {
    Log::event(
        "INFO",
        "Session Management",
        "Logout request",
        "in_progress"
    );
    
    let redis_client = match app_state.redis_client {
        Some(client) => client,
        None => {
            Log::event(
                "ERROR",
                "Session Management",
                "Get Redis client",
                "failure"
            );
            return ApiError::internal_error("Redis client not available").into_response();
        },
    };
    
    match process_logout(redis_client.clone(), logout_request.token).await {
        Ok(response) => {
            Log::event(
                "INFO",
                "Session Management",
                "Logout request",
                "success"
            );
            response.into_response()
        },
        Err(api_error) => {
            Log::event(
                "ERROR",
                "Session Management",
                "Logout request",
                "failure"
            );
            api_error.into_response()
        },
    }
}

/// Core logout logic separated for better testability.
async fn process_logout(
    redis_client: RedisClient,
    token: String,
) -> Result<impl IntoResponse, ApiError> {
    // Try to validate token to get user info for logging
    let user_info = match validate_token(&token, &redis_client).await {
        Ok(claims) => claims.sub,
        Err(_) => "unknown".to_string()
    };

    // Revoke the token
    Log::event(
        "INFO",
        "Session Management",
        "Revoke token",
        "in_progress"
    );
    
    revoke_token(&token, &redis_client).await.map_err(|_| {
        Log::event(
            "ERROR",
            "Session Management",
            "Revoke token",
            "failure"
        );
        ApiError::internal_error("Failed to logout")
    })?;
    
    Log::event(
        "INFO",
        "Session Management",
        "Revoke token",
        "success"
    );
    
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
pub async fn refresh_token_handler(
    State(app_state): State<AppState>,
    Json(refresh_request): Json<TokenRequest>,
) -> impl IntoResponse {
    Log::event(
        "INFO",
        "Token Management",
        "Token refresh request",
        "in_progress"
    );
    
    let redis_client = match app_state.redis_client {
        Some(client) => client,
        None => {
            Log::event(
                "ERROR",
                "Token Management",
                "Get Redis client",
                "failure"
            );
            return ApiError::internal_error("Redis client not available").into_response();
        },
    };
    
    match process_token_refresh(redis_client.clone(), refresh_request.token).await {
        Ok(response) => {
            // Record token issue metrics
            app_state.metrics.record_token_operation("refresh", "access");
            app_state.metrics.record_token_operation("refresh", "refresh");
            
            Log::event(
                "INFO",
                "Token Management",
                "Token refresh request",
                "success"
            );
            
            response.into_response()
        },
        Err(api_error) => {
            Log::event(
                "WARN",
                "Token Management",
                "Token refresh request",
                "failure"
            );
            
            api_error.into_response()
        },
    }
}

/// Core token refresh logic separated for better testability.
async fn process_token_refresh(
    redis_client: RedisClient,
    token: String,
) -> Result<impl IntoResponse, ApiError> {
    // Validate the refresh token
    Log::event(
        "INFO",
        "Token Management",
        "Validate refresh token",
        "in_progress"
    );
    
    let claims = validate_token(&token, &redis_client).await.map_err(|_| {
        Log::event(
            "WARN",
            "Token Management",
            "Validate refresh token",
            "failure"
        );
        ApiError::unauthorized_error("Invalid or expired token")
    })?;
    
    Log::event(
        "INFO",
        "Token Management",
        "Validate refresh token",
        "success"
    );

    // Check if it's actually a refresh token
    Log::event(
        "INFO",
        "Token Management",
        "Check token type",
        "in_progress"
    );
    
    if claims.token_type != TOKEN_TYPE_REFRESH {
        Log::event(
            "WARN",
            "Token Management",
            "Check token type",
            "failure"
        );
        return Err(ApiError::bad_request_error("Not a refresh token"));
    }
    
    Log::event(
        "INFO",
        "Token Management",
        "Check token type",
        "success"
    );

    // Generate a new access token
    Log::event(
        "INFO",
        "Token Management",
        "Generate new access token",
        "in_progress"
    );
    
    let new_access_token = generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None).map_err(|_| {
        Log::event(
            "ERROR",
            "Token Management",
            "Generate new access token",
            "failure"
        );
        ApiError::internal_error("Token refresh failed")
    })?;
    
    Log::event(
        "INFO",
        "Token Management",
        "Generate new access token",
        "success"
    );

    // Revoke the old refresh token
    Log::event(
        "INFO",
        "Token Management",
        "Revoke old refresh token",
        "in_progress"
    );
    
    if let Err(_) = revoke_token(&token, &redis_client).await {
        Log::event(
            "WARN",
            "Token Management",
            "Revoke old refresh token",
            "failure"
        );
        // Continue anyway since we'll issue a new token
    } else {
        Log::event(
            "INFO",
            "Token Management",
            "Revoke old refresh token",
            "success"
        );
    }

    // Generate a new refresh token
    Log::event(
        "INFO",
        "Token Management",
        "Generate new refresh token",
        "in_progress"
    );
    
    let new_refresh_token = generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None).map_err(|_| {
        Log::event(
            "ERROR",
            "Token Management",
            "Generate new refresh token",
            "failure"
        );
        ApiError::internal_error("Token refresh failed")
    })?;
    
    Log::event(
        "INFO",
        "Token Management",
        "Generate new refresh token",
        "success"
    );

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