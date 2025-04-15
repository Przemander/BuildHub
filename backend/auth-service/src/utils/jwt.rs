//! JSON Web Token (JWT) utility functions for authentication.
//!
//! This module provides functionality for token generation, validation, and revocation,
//! following the JWT standard. It includes:
//! - Access and refresh token generation
//! - Token validation and decoding
//! - Token revocation using Redis blocklist
//! - Custom claims handling
//!
//! Best practices applied:
//! - Clear module and function documentation with Rust doc comments.
//! - Structured logging using log_debug, log_info, log_warn, and log_error.
//! - Metrics integration to track token operations and validations.
//! - Consistent error handling using a custom ApiError type.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::env;
use chrono::{Duration, Utc};
use crate::{log_info, log_warn, log_error, log_debug};
use crate::utils::errors::ApiError;
use crate::utils::metrics::{TOKEN_OPERATIONS, TOKEN_VALIDATIONS};

/// Claims structure for JWT tokens.
/// 
/// Represents the payload data for our JWT tokens following RFC 7519 with custom fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,        // Subject (username)
    pub exp: usize,         // Expiration time (Unix timestamp)
    pub iat: usize,         // Issued at time (Unix timestamp)
    pub token_type: String, // Token type (access/refresh)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>, // JWT ID (optional, for token revocation)
}

/// Token types constants.
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Generates a JWT token with specified claims.
///
/// # Arguments
/// * `username` - The subject (sub) claim value.
/// * `token_type` - Type of token (access or refresh).
/// * `expires_in` - Optional custom expiration duration.
///
/// # Returns
/// * `Result<String, ApiError>` containing the generated JWT or error.
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, ApiError> {
    log_debug!("Token Management", "Begin token generation", "attempt");
    TOKEN_OPERATIONS.with_label_values(&["generate", "attempt"]).inc();

    let now = Utc::now();

    let expiration = match expires_in {
        Some(duration) => now + duration,
        None => match token_type {
            TOKEN_TYPE_ACCESS => {
                let seconds = env::var("JWT_ACCESS_TOKEN_EXPIRES_IN")
                    .ok()
                    .and_then(|val| val.parse::<i64>().ok())
                    .unwrap_or(3600);
                now + Duration::seconds(seconds)
            },
            TOKEN_TYPE_REFRESH => {
                let seconds = env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                    .ok()
                    .and_then(|val| val.parse::<i64>().ok())
                    .unwrap_or(604800);
                now + Duration::seconds(seconds)
            },
            _ => {
                log_warn!("Token Management", "Unknown token type", "failure");
                now + Duration::hours(1)
            }
        },
    };

    let claims = TokenClaims {
        sub: username.to_string(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: token_type.to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };

    let secret = env::var("JWT_SECRET").map_err(|_| {
        log_error!("Token Management", "JWT secret configuration", "failure");
        TOKEN_OPERATIONS.with_label_values(&["generate", "failure"]).inc();
        ApiError::configuration_error("JWT secret is not configured")
    })?;

    let mut header = Header::default();
    header.alg = Algorithm::HS256;

    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|_| {
            log_error!("Token Management", "Token encoding", "failure");
            TOKEN_OPERATIONS.with_label_values(&["generate", "failure"]).inc();
            ApiError::internal_error("Failed to generate token")
        })
        .map(|token| {
            log_debug!("Token Management", "Token encoding", "success");
            TOKEN_OPERATIONS.with_label_values(&["generate", "success"]).inc();
            token
        })
}

/// Decodes a JWT token and returns its claims without additional blocklist verification.
///
/// # Arguments
/// * `token` - JWT token string.
///
/// # Returns
/// * `Result<TokenClaims, ApiError>` containing token claims or error.
pub fn decode_token(token: &str) -> Result<TokenClaims, ApiError> {
    log_debug!("Token Management", "Begin token decoding", "attempt");
    TOKEN_VALIDATIONS.with_label_values(&["decode", "attempt"]).inc();

    let secret = env::var("JWT_SECRET").map_err(|_| {
        log_error!("Token Management", "JWT secret configuration", "failure");
        TOKEN_VALIDATIONS.with_label_values(&["decode", "failure"]).inc();
        ApiError::configuration_error("JWT secret is not configured")
    })?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 5;

    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| {
        log_debug!("Token Management", "Token decoding", "success");
        TOKEN_VALIDATIONS.with_label_values(&["decode", "success"]).inc();
        data.claims
    })
    .map_err(|e| {
        let error_resp = match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                log_debug!("Token Management", "Token expiration check", "failure");
                ApiError::unauthorized_error("Token has expired")
            },
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                log_warn!("Token Management", "Token signature verification", "failure");
                ApiError::unauthorized_error("Invalid token signature")
            },
            _ => {
                log_error!("Token Management", "Token decoding", "failure");
                ApiError::unauthorized_error("Invalid token")
            }
        };
        TOKEN_VALIDATIONS.with_label_values(&["decode", "failure"]).inc();
        error_resp
    })
}

/// Validates a JWT token and checks for its revocation via Redis.
///
/// # Arguments
/// * `token` - JWT token string.
/// * `redis_client` - Redis client for blocklist checking.
///
/// # Returns
/// * `Result<TokenClaims, ApiError>` containing token claims or error.
pub async fn validate_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<TokenClaims, ApiError> {
    log_debug!("Token Management", "Begin token validation", "attempt");
    TOKEN_VALIDATIONS.with_label_values(&["validate", "attempt"]).inc();

    let claims = decode_token(token)?;

    match crate::config::redis::is_token_blocked(redis_client, token).await {
        Ok(is_blocked) => {
            if is_blocked {
                log_debug!("Token Management", "Token revocation check", "failure");
                TOKEN_VALIDATIONS.with_label_values(&["validate", "revoked"]).inc();
                return Err(ApiError::unauthorized_error("Token has been revoked"));
            }
        },
        Err(_) => {
            log_warn!("Token Management", "Redis revocation check", "failure");
        }
    }

    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        log_debug!("Token Management", "Token expiration check", "failure");
        TOKEN_VALIDATIONS.with_label_values(&["validate", "expired"]).inc();
        return Err(ApiError::unauthorized_error("Token has expired"));
    }
    if claims.iat > now + 60 {
        log_warn!("Token Management", "Token issue time check", "failure");
        TOKEN_VALIDATIONS.with_label_values(&["validate", "invalid_iat"]).inc();
        return Err(ApiError::unauthorized_error("Invalid token issue time"));
    }

    log_info!("Token Management", "Token validation complete", "success");
    TOKEN_VALIDATIONS.with_label_values(&["validate", "success"]).inc();
    Ok(claims)
}

/// Revokes a JWT token by adding it to a blocklist in Redis until expiration.
///
/// # Arguments
/// * `token` - JWT token string to revoke.
/// * `redis_client` - Redis client for the blocklist.
///
/// # Returns
/// * `Result<(), ApiError>` indicating success or error.
pub async fn revoke_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<(), ApiError> {
    log_debug!("Token Management", "Begin token revocation", "attempt");
    TOKEN_OPERATIONS.with_label_values(&["revoke", "attempt"]).inc();

    let claims = decode_token(token)?;

    let now = Utc::now().timestamp() as usize;
    if claims.exp <= now {
        log_debug!("Token Management", "Token already expired", "success");
        TOKEN_OPERATIONS.with_label_values(&["revoke", "expired"]).inc();
        return Ok(());
    }

    let ttl = claims.exp - now;
    crate::config::redis::block_token(redis_client, token, ttl)
        .await
        .map_err(|_| {
            log_error!("Token Management", "Redis token blocking", "failure");
            TOKEN_OPERATIONS.with_label_values(&["revoke", "failure"]).inc();
            ApiError::internal_error("Failed to revoke token")
        })?;

    log_info!("Token Management", "Token revocation complete", "success");
    TOKEN_OPERATIONS.with_label_values(&["revoke", "success"]).inc();
    Ok(())
}