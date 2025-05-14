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
//! - Consistent error handling using domain errors and ServiceError internally.

use crate::utils::errors::{JwtError, ServiceError};
use crate::utils::metrics::{TOKEN_OPERATIONS, TOKEN_VALIDATIONS};
use crate::{log_debug, log_error, log_info, log_warn};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

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
/// * `Result<String, ServiceError>` containing the generated JWT or error.
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, ServiceError> {
    log_debug!("Token Management", "Begin token generation", "attempt");
    TOKEN_OPERATIONS
        .with_label_values(&["generate", "attempt"])
        .inc();

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
            }
            TOKEN_TYPE_REFRESH => {
                let seconds = env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                    .ok()
                    .and_then(|val| val.parse::<i64>().ok())
                    .unwrap_or(604800);
                now + Duration::seconds(seconds)
            }
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

    // pull secret, fail if missing or empty
    let secret = match env::var("JWT_SECRET") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            log_error!("Token Management", "JWT secret configuration", "failure");
            TOKEN_OPERATIONS
                .with_label_values(&["generate", "failure"])
                .inc();
            return Err(ServiceError::Jwt(JwtError::Configuration(
                "JWT secret is not configured".to_string(),
            )));
        }
    };

    let mut header = Header::default();
    header.alg = Algorithm::HS256;

    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|_| {
            log_error!("Token Management", "Token encoding", "failure");
            TOKEN_OPERATIONS
                .with_label_values(&["generate", "failure"])
                .inc();
            ServiceError::Jwt(JwtError::Internal("Failed to generate token".to_string()))
        })
        .map(|token| {
            log_debug!("Token Management", "Token encoding", "success");
            TOKEN_OPERATIONS
                .with_label_values(&["generate", "success"])
                .inc();
            token
        })
}

/// Decodes a JWT token and returns its claims without additional blocklist verification.
///
/// # Arguments
/// * `token` - JWT token string.
///
/// # Returns
/// * `Result<TokenClaims, ServiceError>` containing token claims or error.
pub fn decode_token(token: &str) -> Result<TokenClaims, ServiceError> {
    log_debug!("Token Management", "Begin token decoding", "attempt");
    TOKEN_VALIDATIONS
        .with_label_values(&["decode", "attempt"])
        .inc();

    let secret = env::var("JWT_SECRET").map_err(|_| {
        log_error!("Token Management", "JWT secret configuration", "failure");
        TOKEN_VALIDATIONS
            .with_label_values(&["decode", "failure"])
            .inc();
        ServiceError::Jwt(JwtError::Configuration(
            "JWT secret is not configured".to_string(),
        ))
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
        TOKEN_VALIDATIONS
            .with_label_values(&["decode", "success"])
            .inc();
        data.claims
    })
    .map_err(|e| {
        let err = match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                log_debug!("Token Management", "Token expiration check", "failure");
                JwtError::Expired
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                log_warn!(
                    "Token Management",
                    "Token signature verification",
                    "failure"
                );
                JwtError::InvalidSignature
            }
            _ => {
                log_error!("Token Management", "Token decoding", "failure");
                JwtError::Invalid
            }
        };
        TOKEN_VALIDATIONS
            .with_label_values(&["decode", "failure"])
            .inc();
        ServiceError::Jwt(err)
    })
}

/// Validates a JWT token and checks for its revocation via Redis.
///
/// # Arguments
/// * `token` - JWT token string.
/// * `redis_client` - Redis client for blocklist checking.
///
/// # Returns
/// * `Result<TokenClaims, ServiceError>` containing token claims or error.
pub async fn validate_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<TokenClaims, ServiceError> {
    log_debug!("Token Management", "Begin token validation", "attempt");
    TOKEN_VALIDATIONS
        .with_label_values(&["validate", "attempt"])
        .inc();

    let claims = decode_token(token)?;

    match crate::config::redis::is_token_blocked(redis_client, token).await {
        Ok(is_blocked) => {
            if is_blocked {
                log_debug!("Token Management", "Token revocation check", "failure");
                TOKEN_VALIDATIONS
                    .with_label_values(&["validate", "revoked"])
                    .inc();
                return Err(ServiceError::Jwt(JwtError::Revoked));
            }
        }
        Err(_) => {
            log_warn!("Token Management", "Redis revocation check", "failure");
        }
    }

    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        log_debug!("Token Management", "Token expiration check", "failure");
        TOKEN_VALIDATIONS
            .with_label_values(&["validate", "expired"])
            .inc();
        return Err(ServiceError::Jwt(JwtError::Expired));
    }
    if claims.iat > now + 60 {
        log_warn!("Token Management", "Token issue time check", "failure");
        TOKEN_VALIDATIONS
            .with_label_values(&["validate", "invalid_iat"])
            .inc();
        return Err(ServiceError::Jwt(JwtError::InvalidIat));
    }

    log_info!("Token Management", "Token validation complete", "success");
    TOKEN_VALIDATIONS
        .with_label_values(&["validate", "success"])
        .inc();
    Ok(claims)
}

/// Revokes a JWT token by adding it to a blocklist in Redis until expiration.
///
/// # Arguments
/// * `token` - JWT token string to revoke.
/// * `redis_client` - Redis client for the blocklist.
///
/// # Returns
/// * `Result<(), ServiceError>` indicating success or error.
pub async fn revoke_token(token: &str, redis_client: &redis::Client) -> Result<(), ServiceError> {
    log_debug!("Token Management", "Begin token revocation", "attempt");
    TOKEN_OPERATIONS
        .with_label_values(&["revoke", "attempt"])
        .inc();

    let claims = decode_token(token)?;

    let now = Utc::now().timestamp() as usize;
    if claims.exp <= now {
        log_debug!("Token Management", "Token already expired", "success");
        TOKEN_OPERATIONS
            .with_label_values(&["revoke", "expired"])
            .inc();
        return Ok(());
    }

    let ttl = claims.exp - now;
    crate::config::redis::block_token(redis_client, token, ttl)
        .await
        .map_err(|_| {
            log_error!("Token Management", "Redis token blocking", "failure");
            TOKEN_OPERATIONS
                .with_label_values(&["revoke", "failure"])
                .inc();
            ServiceError::Jwt(JwtError::Internal("Failed to revoke token".to_string()))
        })?;

    log_info!("Token Management", "Token revocation complete", "success");
    TOKEN_OPERATIONS
        .with_label_values(&["revoke", "success"])
        .inc();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::{env, thread};
    use redis::Client;
    use crate::config::redis::is_token_blocked;

    // Ensure we always use a test secret
    fn init_secret() {
        env::set_var("JWT_SECRET", "test-secret");
    }

    #[test]
    fn generate_and_decode_token_roundtrip() {
        init_secret();
        let tok = generate_token("alice", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("should generate");
        let claims = decode_token(&tok).expect("should decode");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.token_type, TOKEN_TYPE_ACCESS);
    }

    #[test]
    fn generate_fails_without_secret() {
        // leave the var present, but empty => still treated as “not configured”
        env::set_var("JWT_SECRET", "");

        let err = generate_token("u", TOKEN_TYPE_ACCESS, Some(Duration::hours(1))).unwrap_err();
        match err {
            ServiceError::Jwt(JwtError::Configuration(_)) => {}
            _ => panic!("expected Configuration error"),
        }
    }

    #[test]
    fn decode_invalid_token_errors() {
        init_secret();
        let bad = "not-a.jwt.token";
        let err = decode_token(bad).unwrap_err();
        match err {
            ServiceError::Jwt(JwtError::Invalid) => {}
            _ => panic!("expected Invalid token error"),
        }
    }

    #[tokio::test]
    async fn validate_token_ok_and_revoked() {
        init_secret();
        // generate a short‐lived token
        let tok = generate_token("bob", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .unwrap();
        let client = Client::open("redis://127.0.0.1/").unwrap();

        // Should validate before revocation
        let claims = validate_token(&tok, &client).await.unwrap();
        assert_eq!(claims.sub, "bob");

        // Revoke it
        revoke_token(&tok, &client).await.unwrap();
        // small sleep to let Redis write
        thread::sleep(std::time::Duration::from_millis(50));

        // Now validate_token should Err(Revoked)
        let err = validate_token(&tok, &client).await.unwrap_err();
        match err {
            ServiceError::Jwt(JwtError::Revoked) => {}
            _ => panic!("expected Revoked"),
        }
    }

    #[tokio::test]
    async fn revoke_token_on_expired_is_noop() {
        init_secret();
        // expiry in the past
        let tok = generate_token("x", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1)))
            .unwrap();
        let client = Client::open("redis://127.0.0.1/").unwrap();
        // Should be Ok and not error
        revoke_token(&tok, &client).await.unwrap();
        // And blocklist should _not_ contain it
        let blocked = is_token_blocked(&client, &tok).await.unwrap();
        assert!(!blocked);
    }
}