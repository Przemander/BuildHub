use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use chrono::{Duration, Utc};
use log::{error, info};

use crate::utils::errors::ApiError;

/// Claims structure for JWT tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,    // Subject (typically username)
    pub exp: usize,    // Expiration time
    pub iat: usize,   // Issued at
    pub token_type: String, // Token type (e.g. "access" or "refresh")
}

/// Token types
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Helper function to generate a JWT token
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, ApiError> {
    // Get the current timestamp
    let now = Utc::now();

    // Calculate expiration based on token type or provided duration
    let expiration = match expires_in {
        Some(duration) => now + duration,
        None => match token_type {
            TOKEN_TYPE_ACCESS => now + Duration::hours(1),    // Access token expires in 1 hour
            TOKEN_TYPE_REFRESH => now + Duration::days(7),    // Refresh token expires in 7 days
            _ => now + Duration::hours(1),    // Default expiration
         }
    };

    let claims = Claims {
        sub: username.to_string(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: token_type.to_string(),
    };

    let secret = env::var("JWT_SECRET").map_err(|_| {
        error!("JWT_SECRET environment variable not set");
        ApiError {
            status: "configuration_error".to_string(),
            message: "JWT secret is not configured".to_string(),
        }
    })?;

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| {
        error!("Failed to generate token: {}", e);
        ApiError {
            status: "internal_error".to_string(),
            message: format!("Failed to generate token: {}", e),
        }
    })
}

/// Helper function to decode a JWT token
pub fn decode_token(token: &str) -> Result<Claims, ApiError> {
    let secret = env::var("JWT_SECRET").map_err(|_| {
        error!("JWT_SECRET environment variable not set");
        ApiError {
            status: "configuration_error".to_string(),
            message: "JWT secret is not cofigured".to_string(),
        }
    })?;

    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())
        .map(|data| {
            info!("Token decoded successfully: for user {}", data.claims.sub);
            data.claims
        })
        .map_err(|e|{
            error!("Failed to decode JWT token: {}", e);
            ApiError {
                status: "unauthorized".to_string(),
                message: "Invalid or expired token".to_string(),
            }
        })
}

/// Helper function to validate a token and extract the claims
/// This also checks if the token has been blocked in Redis
pub async fn validate_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<Claims, ApiError> {
    // Check if token is blocked
    match crate::config::redis::is_token_blocked(redis_client, token).await {
        Ok(is_blocked) => {
            if is_blocked {
                return Err(ApiError {
                    status: "unauthorized".to_string(),
                    message: "Token has been revoked".to_string(),
                });
            }
        },
        Err(e) => {
            error!("Error checking if token is blocked: {}", e);
            // Continue the validation even if Redis check fails
        }
    }

    // Decode and validate the token
    let claims = decode_token(token)?;

    // Check if token is expired
    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        return Err(ApiError {
            status: "unauthorized".to_string(),
            message: "Token has expired".to_string(),
        });
    }

    Ok(claims)
}

/// Helper function to revoke a token
pub async fn revoke_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<(), ApiError> {
    // First decode the token to get is expiration
    let claims = decode_token(token)?;

    // Calculate remaining time until expiration
    let now = Utc::now().timestamp() as usize;
    let ttl = if claims.exp > now {
        claims.exp - now
    } else {
        0 // Token already expired
    };

    // Block the token in Redis until its original expiration
    if ttl > 0 {
        crate::config::redis::block_token(redis_client, token, ttl)
        .await
        .map_err(|e| ApiError {
            status: "internal_error".to_string(),
            message: format!("Failed to revoke token: {}", e),
        })?;
    }

    Ok(())
}