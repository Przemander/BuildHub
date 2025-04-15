//! JWT Authentication Middleware.
//!
//! This middleware validates the JWT token found in the Authorization header, ensuring the token follows
//! the Bearer format, its signature is valid, and the token is not expired. If a Redis client is provided,
//! it also verifies that the token is not blacklisted.
//!
//! Best practices applied:
//! - Structured logging at key steps (errors/warnings and overall outcomes).
//! - Metrics integration for tracking authentication attempts and failures.
//! - Early returns for error conditions using Rust’s Result type.
//! - Detailed DEBUG logging is available for development and is suppressed in production.

use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use crate::utils::jwt::{validate_token, decode_token, TokenClaims, TOKEN_TYPE_ACCESS};
use crate::utils::errors::ApiError;
use log::{debug, warn};
use redis::Client as RedisClient;
use std::sync::Arc;
use crate::utils::metrics::{JWT_AUTH_ATTEMPTS, JWT_AUTH_SUCCESS, JWT_AUTH_FAILURE};
use chrono::Utc;

/// JWT authentication middleware for protected routes.
///
/// Extracts the JWT token from the Authorization header, performs validation (using Redis for blacklist checking when available),
/// and injects the token claims and username into the request extensions for downstream handlers.
pub async fn jwt_auth_middleware<B>(
    State(redis_client): State<Option<Arc<RedisClient>>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Response
where
    B: Send + 'static,
{
    JWT_AUTH_ATTEMPTS.with_label_values(&["attempt"]).inc();

    // Extract the Authorization header.
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => header,
        None => {
            debug!("No Authorization header found");
            JWT_AUTH_FAILURE.with_label_values(&["missing_header"]).inc();
            return ApiError::unauthorized_error("Authorization header missing").into_response();
        }
    };

    // Convert header to string.
    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            debug!("Invalid Authorization header format");
            JWT_AUTH_FAILURE.with_label_values(&["invalid_format"]).inc();
            return ApiError::unauthorized_error("Invalid Authorization header format").into_response();
        }
    };

    // Check scheme and extract token.
    if !auth_str.starts_with("Bearer ") {
        debug!("Invalid Authorization scheme");
        JWT_AUTH_FAILURE.with_label_values(&["invalid_scheme"]).inc();
        return ApiError::unauthorized_error("Bearer authentication required").into_response();
    }
    let token = &auth_str[7..];
    if token.is_empty() {
        debug!("Empty token provided");
        JWT_AUTH_FAILURE.with_label_values(&["empty_token"]).inc();
        return ApiError::unauthorized_error("Empty token").into_response();
    }

    // Authenticate the token.
    let claims = match authenticate_token(token, redis_client.as_deref()).await {
        Ok(claims) => claims,
        Err(error) => {
            JWT_AUTH_FAILURE.with_label_values(&["validation_error"]).inc();
            return error.into_response();
        }
    };

    debug!("Authentication successful for user: {}", claims.sub);
    JWT_AUTH_SUCCESS.with_label_values(&["success"]).inc();

    // Inject token claims and username into request extensions.
    req.extensions_mut().insert(claims.clone());
    req.extensions_mut().insert(claims.sub);

    next.run(req).await
}

/// Helper function to authenticate a JWT token.
///
/// When a Redis client is available, the token is validated using a full check (including blacklist verification).
/// Otherwise, basic validation is performed by decoding the token, ensuring its type matches, and checking its issuance time.
///
/// # Arguments
/// * `token`: The JWT token string from the header.
/// * `redis_client`: Optional Redis client for blacklist checking.
///
/// # Returns
/// * `Ok(TokenClaims)` if authentication is successful.
/// * `Err(ApiError)` if authentication fails.
async fn authenticate_token(
    token: &str,
    redis_client: Option<&RedisClient>,
) -> Result<TokenClaims, ApiError> {
    if let Some(redis) = redis_client {
        // Full validation with Redis-based blacklist check.
        validate_token(token, redis).await
    } else {
        // Basic validation without Redis.
        let claims = decode_token(token)?;
        
        // Check for correct token type.
        if claims.token_type != TOKEN_TYPE_ACCESS {
            debug!("Invalid token type: {}", claims.token_type);
            return Err(ApiError::unauthorized_error("Invalid token type"));
        }
        
        // Allow for a 1-minute clock skew.
        let now = Utc::now().timestamp() as usize;
        if claims.iat > now + 60 {
            warn!("Token validation failed: token issued in the future (possible clock skew)");
            return Err(ApiError::unauthorized_error("Invalid token issue time"));
        }
        
        Ok(claims)
    }
}