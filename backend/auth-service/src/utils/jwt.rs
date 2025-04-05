//! JSON Web Token (JWT) utility functions for authentication.
//!
//! This module provides functionality for token generation, validation,
//! and revocation using JWT standard. It includes:
//! - Access and refresh token generation
//! - Token validation and decoding
//! - Token revocation using Redis blocklist
//! - Custom claims handling

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::env;
use chrono::{Duration, Utc};
use log::{error, info, debug, warn};

use crate::utils::errors::ApiError;

/// Claims structure for JWT tokens.
///
/// This structure represents the payload data for our JWT tokens,
/// following RFC 7519 standard with custom fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,       // Subject (username)
    pub exp: usize,        // Expiration time (Unix timestamp)
    pub iat: usize,        // Issued at time (Unix timestamp)
    pub token_type: String, // Token type (access/refresh)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>, // JWT ID (optional, for token revocation)
}

/// Token types constants
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Generates a JWT token with the specified claims.
///
/// # Arguments
/// * `username` - The subject (sub) claim value
/// * `token_type` - Type of token (access/refresh)
/// * `expires_in` - Optional custom expiration duration
///
/// # Returns
/// * `Result<String, ApiError>` - JWT token string or error
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, ApiError> {
    debug!("Generating {} token for user: {}", token_type, username);
    
    // Get the current timestamp
    let now = Utc::now();

    // Calculate expiration based on token type or provided duration
    let expiration = match expires_in {
        Some(duration) => now + duration,
        None => {
            match token_type {
                TOKEN_TYPE_ACCESS => {
                    // Read from environment or use default
                    let seconds = env::var("JWT_ACCESS_TOKEN_EXPIRES_IN")
                        .ok()
                        .and_then(|val| val.parse::<i64>().ok())
                        .unwrap_or(3600); // Default: 1 hour
                    now + Duration::seconds(seconds)
                },
                TOKEN_TYPE_REFRESH => {
                    // Read from environment or use default
                    let seconds = env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                        .ok()
                        .and_then(|val| val.parse::<i64>().ok())
                        .unwrap_or(604800); // Default: 7 days
                    now + Duration::seconds(seconds)
                },
                _ => {
                    warn!("Unknown token type: {}, using default expiration", token_type);
                    now + Duration::hours(1)
                },
            }
        }
    };

    // Create token claims
    let claims = TokenClaims {
        sub: username.to_string(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: token_type.to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()), // Add unique ID for token revocation
    };

    // Get JWT secret from environment
    let secret = env::var("JWT_SECRET").map_err(|_| {
        error!("JWT_SECRET environment variable not set");
        ApiError::configuration_error("JWT secret is not configured")
    })?;

    // Configure header with algorithm
    let mut header = Header::default();
    header.alg = Algorithm::HS256; // Explicitly set algorithm

    // Encode token
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| {
        error!("Failed to generate token: {}", e);
        ApiError::internal_error(&format!("Failed to generate token: {}", e))
    }).map(|token| {
        debug!("Token generated successfully");
        token
    })
}

/// Decodes a JWT token without verifying if it's blocked.
///
/// # Arguments
/// * `token` - JWT token string
///
/// # Returns
/// * `Result<TokenClaims, ApiError>` - Token claims or error
pub fn decode_token(token: &str) -> Result<TokenClaims, ApiError> {
    debug!("Decoding JWT token");

    // Get JWT secret from environment
    let secret = env::var("JWT_SECRET").map_err(|_| {
        error!("JWT_SECRET environment variable not set");
        ApiError::configuration_error("JWT secret is not configured")
    })?;

    // Configure validation
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 5; // 5 seconds leeway for clock skew

    // Decode and validate token
    decode::<TokenClaims>(
        token, 
        &DecodingKey::from_secret(secret.as_bytes()), 
        &validation
    )
    .map(|data| {
        debug!("Token decoded successfully for user: {}", data.claims.sub);
        data.claims
    })
    .map_err(|e| {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                debug!("Token expired: {}", e);
                ApiError::unauthorized_error("Token has expired")
            },
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                warn!("Invalid token signature detected");
                ApiError::unauthorized_error("Invalid token signature")
            },
            _ => {
                error!("Failed to decode JWT token: {}", e);
                ApiError::unauthorized_error("Invalid token")
            }
        }
    })
}

/// Validates a token by decoding it and checking if it's blocked in Redis.
///
/// # Arguments
/// * `token` - JWT token string
/// * `redis_client` - Redis client for checking blocklist
///
/// # Returns
/// * `Result<TokenClaims, ApiError>` - Token claims or error
pub async fn validate_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<TokenClaims, ApiError> {
    debug!("Validating JWT token");
    
    // First decode the token to get claims
    let claims = decode_token(token)?;
    
    // Check if token is blocked in Redis
    match crate::config::redis::is_token_blocked(redis_client, token).await {
        Ok(is_blocked) => {
            if is_blocked {
                debug!("Token validation failed: token is revoked");
                return Err(ApiError::unauthorized_error("Token has been revoked"));
            }
        },
        Err(e) => {
            warn!("Error checking if token is blocked: {}, continuing validation", e);
            // Continue validation even if Redis check fails
            // This ensures users can still authenticate if Redis is temporarily down
        }
    }

    // Perform additional validation checks
    let now = Utc::now().timestamp() as usize;
    
    // Check expiration (although decode_token already does this)
    if claims.exp < now {
        debug!("Token validation failed: token expired");
        return Err(ApiError::unauthorized_error("Token has expired"));
    }

    // Check if token was issued in the future (clock skew)
    if claims.iat > now + 60 { // Allow 1 minute of clock skew
        warn!("Token validation failed: token issued in the future (possible clock skew)");
        return Err(ApiError::unauthorized_error("Invalid token issue time"));
    }

    info!("Token validated successfully for user: {}", claims.sub);
    Ok(claims)
}

/// Revokes a token by adding it to a blocklist in Redis.
///
/// # Arguments
/// * `token` - JWT token string to revoke
/// * `redis_client` - Redis client for blocklist
///
/// # Returns
/// * `Result<(), ApiError>` - Success or error
pub async fn revoke_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<(), ApiError> {
    debug!("Revoking token");

    // First decode the token to get claims and validate it
    let claims = decode_token(token)?;

    // Calculate remaining time until expiration
    let now = Utc::now().timestamp() as usize;
    
    // If token is already expired, no need to revoke
    if claims.exp <= now {
        debug!("Token already expired, no need to revoke");
        return Ok(());
    }
    
    // Calculate time-to-live for the blocked token in Redis
    let ttl = claims.exp - now;
    
    // Blocklist the token in Redis until its original expiration
    crate::config::redis::block_token(redis_client, token, ttl)
        .await
        .map_err(|e| {
            error!("Failed to revoke token in Redis: {}", e);
            ApiError::internal_error(&format!("Failed to revoke token: {}", e))
        })?;

    info!("Token revoked successfully for user: {}", claims.sub);
    Ok(())
}