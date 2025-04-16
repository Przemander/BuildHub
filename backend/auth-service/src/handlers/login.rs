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
use crate::db::users::User;
use crate::utils::errors::ApiError;
use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH};
use crate::utils::metrics::{
    AUTH_LOGIN_ATTEMPTS, TOKEN_OPERATIONS,
    REQUESTS_TOTAL, DB_OPERATIONS, RequestTimer,
};

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
    let mut timer = RequestTimer::start("/auth/login");
    REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "pending"]).inc();

    let result = process_login(app_state.pool.clone(), login_request).await;

    match &result {
        Ok(_) => {
            AUTH_LOGIN_ATTEMPTS.with_label_values(&["success"]).inc();
            log_info!("Authentication", "User login complete", "success");
            timer.set_status("200");
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "200"]).inc();
        },
        Err(api_error) => {
            AUTH_LOGIN_ATTEMPTS.with_label_values(&["failure"]).inc();
            log_warn!("Authentication", "User login failed", "failure");
            let status_code = match api_error.status.as_str() {
                "unauthorized" => "401",
                "internal_error" => "500",
                _ => "400",
            };
            timer.set_status(status_code);
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", status_code]).inc();
        },
    }

    timer.complete("POST");
    result.into_response()
}

/// Separates out login processing into authentication and token generation.
async fn process_login(
    pool: crate::config::database::DbPool,
    login_request: LoginRequest,
) -> Result<impl IntoResponse, ApiError> {
    // Obtain a database connection (metrics track success/failure).
    let mut conn = match pool.get() {
        Ok(conn) => {
            DB_OPERATIONS.with_label_values(&["connection", "success"]).inc();
            conn
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            log_error!("Authentication", "Database connection failed", "failure");
            return Err(ApiError::internal_error("Database connection error"));
        }
    };

    let user = authenticate_user(&mut conn, &login_request)?;
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
/// Only logs error conditions and overall outcome.
fn authenticate_user(
    conn: &mut SqliteConnection,
    login_request: &LoginRequest,
) -> Result<User, ApiError> {
    let user = match User::find_by_username(conn, &login_request.username) {
        Ok(user) => {
            DB_OPERATIONS.with_label_values(&["query", "success"]).inc();
            user
        },
        Err(_) => {
            DB_OPERATIONS.with_label_values(&["query", "failure"]).inc();
            log_warn!("Authentication", "User lookup failed", "failure");
            return Err(ApiError::unauthorized_error("Invalid username or password"));
        }
    };

    match user.verify_password(&login_request.password) {
        Ok(true) => { /* Password verified – metric already recorded if needed */ },
        Ok(false) => {
            log_warn!("Authentication", "Password verification failed", "failure");
            return Err(ApiError::unauthorized_error("Invalid username or password"));
        },
        Err(_) => {
            log_error!("Authentication", "Password verification error", "failure");
            return Err(ApiError::internal_error("Password verification failed"));
        }
    }

    if let Some(false) = user.is_active {
        log_warn!("Authentication", "Inactive account", "failure");
        return Err(ApiError::unauthorized_error("Account is not activated"));
    }

    log_info!("Authentication", "User authenticated", "success");
    Ok(user)
}

/// Generates an access and refresh token for a user.
/// Logs only error scenarios along with a summary metric update.
fn generate_auth_tokens(username: &str) -> Result<(String, String), ApiError> {
    let access_token = match generate_token(username, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "generate"]).inc();
            token
        },
        Err(_) => {
            TOKEN_OPERATIONS.with_label_values(&["access", "error"]).inc();
            log_error!("Authentication", "Access token generation failed", "failure");
            return Err(ApiError::internal_error("Authentication error"));
        }
    };

    let refresh_token = match generate_token(username, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "generate"]).inc();
            token
        },
        Err(_) => {
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc();
            log_error!("Authentication", "Refresh token generation failed", "failure");
            return Err(ApiError::internal_error("Authentication error"));
        }
    };

    Ok((access_token, refresh_token))
}