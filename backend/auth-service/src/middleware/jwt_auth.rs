//! JWT authentication middleware for BuildHub.
//!
//! This middleware validates JWT tokens on protected routes using the shared JWT utility functions.
//! It checks for token presence, validity, and revocation (via Redis blocklist).
//! On failure, it returns a 401 Unauthorized response and logs the event.

use crate::app::AppState;
use crate::utils::errors::ApiError;
use crate::utils::jwt;
use crate::log_info;
use crate::log_warn;
use crate::log_error;
use axum::{extract::State, http::Request, middleware::Next, response::IntoResponse};
use std::sync::Arc;

/// JWT authentication middleware for protected routes.
///
/// Expects the `Authorization: Bearer <token>` header.
/// On success, passes the request to the next handler.
/// On failure, returns 401 Unauthorized and logs the event.
pub async fn jwt_auth_middleware<B>(
    State(app_state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    // Extract the Authorization header
    let token = match req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
    {
        Some(header) if header.starts_with("Bearer ") => {
            header.trim_start_matches("Bearer ").trim()
        }
        _ => {
            log_warn!("JWTAuth", "Missing or invalid Authorization header", "unauthorized");
            return ApiError::unauthorized("Missing or invalid Authorization header")
                .into_response();
        }
    };

    // Validate the token using the shared JWT utility
    let redis_client = match &app_state.redis_client {
        Some(redis) => redis,
        None => {
            log_error!("JWTAuth", "Redis unavailable for token validation", "system_error");
            return ApiError::internal("Redis unavailable for token validation").into_response();
        }
    };

    match jwt::validate_token(token, redis_client).await {
        Ok(claims) => {
            log_info!("JWTAuth", &format!("Token valid for user {}", claims.sub), "success");
            next.run(req).await
        }
        Err(err) => {
            log_warn!(
                "JWTAuth",
                &format!("Invalid or expired token: {}", err),
                "unauthorized"
            );
            ApiError::unauthorized(&format!("Invalid or expired token: {}", err)).into_response()
        }
    }
}