//! JSON Web Token (JWT) utilities for BuildHub Auth Service.
//!
//! This module handles JWT creation, decoding, validation, and revocation,
//! integrating structured logging and Prometheus metrics.

use crate::utils::errors::{JwtError, ServiceError};
use crate::utils::metrics::{TOKEN_OPERATIONS, TOKEN_VALIDATIONS};
use crate::{log_debug, log_error, log_info, log_warn};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;
use redis::Client as RedisClient;

/// JWT claims storage following RFC7519 with custom token_type and jti.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Token type labels.
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Default expiration durations (in seconds).
const DEFAULT_ACCESS_EXP: i64 = 3_600;
const DEFAULT_REFRESH_EXP: i64 = 604_800;

/// Retrieves JWT secret from env or returns a configuration error.
fn get_jwt_secret() -> Result<String, ServiceError> {
    match env::var("JWT_SECRET").map(str::trim) {
        Ok(s) if !s.is_empty() => Ok(s.to_string()),
        _ => {
            log_error!("Token Management", "Missing JWT_SECRET", "failure");
            TOKEN_OPERATIONS
                .with_label_values(&["generate", "failure"])
                .inc();
            Err(ServiceError::Jwt(JwtError::Configuration(
                "JWT_SECRET is not configured".into(),
            )))
        }
    }
}

/// Generates a new JWT (access or refresh) for a given subject.
#[inline]
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, ServiceError> {
    log_debug!("Token Management", "Generating token", "attempt");
    TOKEN_OPERATIONS.with_label_values(&["generate", "attempt"]).inc();

    let now = Utc::now();
    let exp_time = match expires_in {
        Some(d) => now + d,
        None => {
            let secs = match token_type {
                TOKEN_TYPE_ACCESS => env::var("JWT_ACCESS_TOKEN_EXPIRES_IN").ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_ACCESS_EXP),
                TOKEN_TYPE_REFRESH => env::var("JWT_REFRESH_TOKEN_EXPIRES_IN").ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_REFRESH_EXP),
                _ => {
                    log_warn!("Token Management", "Unknown token type", "failure");
                    DEFAULT_ACCESS_EXP
                }
            };
            now + Duration::seconds(secs)
        }
    };

    let claims = TokenClaims {
        sub: username.to_string(),
        exp: exp_time.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: token_type.to_string(),
        jti: Some(Uuid::new_v4().to_string()),
    };

    let secret = get_jwt_secret()?;
    let mut header = Header::new(Algorithm::HS256);

    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|_| {
            log_error!("Token Management", "Encoding failed", "failure");
            TOKEN_OPERATIONS.with_label_values(&["generate", "failure"]).inc();
            ServiceError::Jwt(JwtError::Internal("Token generation failed".into()))
        })
        .map(|token| {
            log_info!("Token Management", "Token generated", "success");
            TOKEN_OPERATIONS.with_label_values(&["generate", "success"]).inc();
            token
        })
}

/// Decodes JWT without checking revocation.
#[inline]
pub fn decode_token(token: &str) -> Result<TokenClaims, ServiceError> {
    log_debug!("Token Management", "Decoding token", "attempt");
    TOKEN_VALIDATIONS.with_label_values(&["decode", "attempt"]).inc();

    let secret = get_jwt_secret()?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 5;

    decode::<TokenClaims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)
        .map(|data| {
            log_info!("Token Management", "Token decoded", "success");
            TOKEN_VALIDATIONS.with_label_values(&["decode", "success"]).inc();
            data.claims
        })
        .map_err(|e| {
            let kind = match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => JwtError::InvalidSignature,
                _ => JwtError::Invalid,
            };
            log_error!("Token Management", "Decoding error", "failure");
            TOKEN_VALIDATIONS.with_label_values(&["decode", "failure"]).inc();
            ServiceError::Jwt(kind)
        })
}

/// Validates a token and ensures it's not revoked in Redis.
#[inline]
pub async fn validate_token(
    token: &str,
    redis_client: &RedisClient,
) -> Result<TokenClaims, ServiceError> {
    log_debug!("Token Management", "Validating token", "attempt");
    TOKEN_VALIDATIONS.with_label_values(&["validate", "attempt"]).inc();

    let claims = decode_token(token)?;
    // Check blocklist
    if crate::config::redis::is_token_blocked(redis_client, token).await
        .unwrap_or(false)
    {
        log_warn!("Token Management", "Token revoked", "failure");
        TOKEN_VALIDATIONS.with_label_values(&["validate", "revoked"]).inc();
        return Err(ServiceError::Jwt(JwtError::Revoked));
    }

    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        log_warn!("Token Management", "Token expired", "failure");
        TOKEN_VALIDATIONS.with_label_values(&["validate", "expired"]).inc();
        return Err(ServiceError::Jwt(JwtError::Expired));
    }
    if claims.iat > now + 60 {
        log_warn!("Token Management", "Invalid iat", "failure");
        TOKEN_VALIDATIONS.with_label_values(&["validate", "invalid_iat"]).inc();
        return Err(ServiceError::Jwt(JwtError::InvalidIat));
    }

    log_info!("Token Management", "Token valid", "success");
    TOKEN_VALIDATIONS.with_label_values(&["validate", "success"]).inc();
    Ok(claims)
}

/// Revokes a token by adding it to Redis blocklist until its expiration.
#[inline]
pub async fn revoke_token(
    token: &str,
    redis_client: &RedisClient,
) -> Result<(), ServiceError> {
    log_debug!("Token Management", "Revoking token", "attempt");
    TOKEN_OPERATIONS.with_label_values(&["revoke", "attempt"]).inc();

    let claims = decode_token(token)?;
    let now = Utc::now().timestamp() as usize;
    if claims.exp <= now {
        log_info!("Token Management", "Token already expired", "success");
        TOKEN_OPERATIONS.with_label_values(&["revoke", "expired"]).inc();
        return Ok(());
    }

    let ttl = claims.exp - now;
    crate::config::redis::block_token(redis_client, token, ttl).await.map_err(|_| {
        log_error!("Token Management", "Blocklist failed", "failure");
        TOKEN_OPERATIONS.with_label_values(&["revoke", "failure"]).inc();
        ServiceError::Jwt(JwtError::Internal("Revoke failed".into()))
    })?;

    log_info!("Token Management", "Token revoked", "success");
    TOKEN_OPERATIONS.with_label_values(&["revoke", "success"]).inc();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::{env, thread};
    use redis::Client;
    use crate::config::redis::is_token_blocked;

    fn init_secret() { env::set_var("JWT_SECRET", "test-secret"); }

    #[test]
    fn roundtrip_generate_decode() {
        init_secret();
        let tok = generate_token("alice", TOKEN_TYPE_ACCESS, Some(Duration::hours(1))).unwrap();
        let cl = decode_token(&tok).unwrap();
        assert_eq!(cl.sub, "alice");
    }

    #[test]
    fn generate_fails_without_secret() {
        env::set_var("JWT_SECRET", "");
        match generate_token("u", TOKEN_TYPE_ACCESS, Some(Duration::hours(1))).unwrap_err() {
            ServiceError::Jwt(JwtError::Configuration(_)) => (),
            _ => panic!("Expected configuration error"),
        }
    }

    #[test]
    fn invalid_decode_errors() {
        init_secret();
        match decode_token("bad.token").unwrap_err() {
            ServiceError::Jwt(JwtError::Invalid) => (),
            _ => panic!("Expected invalid token"),
        }
    }

    #[tokio::test]
    async fn validate_and_revoke_flow() {
        init_secret();
        let tok = generate_token("bob", TOKEN_TYPE_ACCESS, Some(Duration::hours(1))).unwrap();
        let client = Client::open("redis://127.0.0.1/").unwrap();
        let cl = validate_token(&tok, &client).await.unwrap();
        assert_eq!(cl.sub, "bob");
        revoke_token(&tok, &client).await.unwrap();
        thread::sleep(std::time::Duration::from_millis(50));
        match validate_token(&tok, &client).await.unwrap_err() {
            ServiceError::Jwt(JwtError::Revoked) => (),
            _ => panic!("Expected revoked error"),
        }
    }

    #[tokio::test]
    async fn revoke_expired_token_noop() {
        init_secret();
        let tok = generate_token("x", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1))).unwrap();
        let client = Client::open("redis://127.0.0.1/").unwrap();
        revoke_token(&tok, &client).await.unwrap();
        let blocked = is_token_blocked(&client, &tok).await.unwrap();
        assert!(!blocked);
    }
}
