//! User login handler.
//!
//! Provides functionality for authenticating users with username/password
//! credentials and issuing JWT tokens upon successful authentication.

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use diesel::SqliteConnection;

use crate::{log_info, log_warn, log_error};
use crate::app::AppState;
use crate::config::database::get_connection;
use crate::db::users::User;
use crate::utils::errors::{ApiError, AuthError, ServiceError};
use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
use crate::utils::metrics::{
    AUTH_LOGIN_ATTEMPTS, TOKEN_OPERATIONS, RATE_LIMIT_BLOCKS,
    REQUESTS_TOTAL, DB_OPERATIONS, RequestTimer,
};
use crate::utils::rate_limit::check_and_increment;

/// All possible label values for AUTH_LOGIN_ATTEMPTS:
/// result: "success", "failure"
/// All possible label values for TOKEN_OPERATIONS:
/// type: "access", "refresh"; operation: "generate", "error"
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub username: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LoginSuccessData {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserResponse,
}

/// Handler for processing user login requests.
///
/// Measures overall request duration through a RequestTimer and
/// uses metrics to track the outcomes. Logging is kept minimal:
/// errors and overall outcome are logged.
pub async fn login_handler(
    State(app_state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> impl IntoResponse {
    let mut timer = RequestTimer::start("/auth/login", "POST");
    REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "pending"]).inc();

    // --- Rate limiting ---
    // Use username as the key for rate limiting (could also use IP if available)
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Authentication", "Missing Redis client for rate limiting", "failure");
            timer.set_status("500");
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "500"]).inc();
            return ApiError::internal_error("Redis unavailable for rate limiting").into_response();
        }
    };
    let rate_key = format!("rate:login:{}", login_request.username);
    let allowed = match check_and_increment(redis_client, &rate_key, 5, 60).await {
        Ok(true) => true,
        Ok(false) => {
            RATE_LIMIT_BLOCKS.with_label_values(&["/auth/login"]).inc();
            log_warn!("Authentication", "Login rate limit exceeded", "failure");
            timer.set_status("429");
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "429"]).inc();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "status": "error",
                    "message": "Too many login attempts. Please try again later."
                }))
            ).into_response();
        }
        Err(e) => {
            log_error!("Authentication", &format!("Rate limit Redis error: {}", e), "failure");
            // Fail open or closed based on policy; here, we allow login if Redis fails
            true
        }
    };

    if !allowed {
        // Defensive: should not reach here, but double-check
        RATE_LIMIT_BLOCKS.with_label_values(&["/auth/login"]).inc();
        timer.set_status("429");
        REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "429"]).inc();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "status": "error",
                "message": "Too many login attempts. Please try again later."
            }))
        ).into_response();
    }

    let result = process_login(&app_state.pool, login_request).await;

    match &result {
        Ok(_) => {
            AUTH_LOGIN_ATTEMPTS.with_label_values(&["success"]).inc();
            log_info!("Authentication", "User login complete", "success");
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "200"]).inc();
        },
        Err(api_error) => {
            AUTH_LOGIN_ATTEMPTS.with_label_values(&["failure"]).inc();
            log_warn!("Authentication", &format!("User login failed: {}", api_error.message), "failure");
            let status_code = match api_error.status.as_str() {
                "unauthorized" => "401",
                "internal_error" => "500",
                _ => "400",
            };
            timer.set_status(status_code);
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", status_code]).inc();
        },
    }

    // No need to call timer.complete(); Drop will handle it.
    result.into_response()
}

/// Separates out login processing into authentication and token generation.
async fn process_login(
    pool: &crate::config::database::DbPool,
    login_request: LoginRequest,
) -> Result<impl IntoResponse, ApiError> {
    // Obtain a database connection (metrics track success/failure).
    let mut conn = match get_connection(pool) {
        Ok(conn) => {
            DB_OPERATIONS.with_label_values(&["connection", "success"]).inc();
            conn
        },
        Err(e) => {
            DB_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            log_error!("Authentication", "Database connection failed", "failure");
            return Err(ServiceError::Database(e).into());
        }
    };

    // Authenticate user using existing logic but with new error types
    let user = authenticate_user(&mut conn, &login_request)?;
    
    // Generate tokens for the authenticated user
    let (access_token, refresh_token) = generate_auth_tokens(&user.username)?;

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

/// Authenticates a user by looking up by username and verifying the password.
/// This preserves the existing logic but with better error types.
fn authenticate_user(
    conn: &mut SqliteConnection,
    login_request: &LoginRequest,
) -> Result<User, ApiError> {
    // Find user by username
    let user = match User::find_by_username(conn, &login_request.username) {
        Ok(user) => {
            DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
            user
        },
        Err(err) => {
            DB_OPERATIONS.with_label_values(&["query", "failure"]).inc();
            log_warn!("Authentication", "User lookup failed", "failure");
            match err {
                diesel::result::Error::NotFound => {
                    return Err(ServiceError::Auth(AuthError::InvalidCredentials).into());
                },
                _ => {}
            }
            return Err(ServiceError::Database(crate::utils::errors::DatabaseError::from(err)).into())
        }
    };

    // Verify password
    match user.verify_password(&login_request.password) {
        Ok(true) => { /* Password verified */ },
        Ok(false) => {
            log_warn!("Authentication", "Password verification failed", "failure");
            return Err(ServiceError::Auth(AuthError::InvalidCredentials).into());
        },
        Err(err) => {
            log_error!("Authentication", &format!("Password verification error: {}", err), "failure");
            return Err(ServiceError::User(err.into()).into());
        }
    }

    // Check if account is active
    if !user.is_active.unwrap_or(false) {
        log_warn!("Authentication", "Inactive account", "failure");
        return Err(ServiceError::Auth(AuthError::AccountNotActivated).into());
    }

    log_info!("Authentication", "User authenticated", "success");
    Ok(user)
}

/// Generates an access and refresh token for a user.
/// Maps JWT errors to our domain-specific error types.
fn generate_auth_tokens(username: &str) -> Result<(String, String), ApiError> {
    let access_token = match generate_token(username, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "generate"]).inc();
            token
        },
        Err(e) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "error"]).inc();
            log_error!("Authentication", &format!("Access token generation failed: {}", e), "failure");
            // Distinguish configuration errors if possible
            let msg = e.to_string();
            if msg.contains("secret") {
                return Err(ServiceError::Auth(
                    AuthError::TokenError("Token configuration error".to_string())
                ).into());
            }
            return Err(ServiceError::Auth(
                AuthError::TokenError("Failed to generate access token".to_string())
            ).into());
        }
    };

    let refresh_token = match generate_token(username, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "generate"]).inc();
            token
        },
        Err(e) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc();
            log_error!("Authentication", &format!("Refresh token generation failed: {}", e), "failure");
            let msg = e.to_string();
            if msg.contains("secret") {
                return Err(ServiceError::Auth(
                    AuthError::TokenError("Token configuration error".to_string())
                ).into());
            }
            return Err(ServiceError::Auth(
                AuthError::TokenError("Failed to generate refresh token".to_string())
            ).into());
        }
    };

    Ok((access_token, refresh_token))
}