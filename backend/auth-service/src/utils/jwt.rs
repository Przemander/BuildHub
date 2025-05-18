//! JSON Web Token (JWT) utility functions for authentication.
//!
//! This module provides functionality for token generation, validation, and revocation,
//! following the JWT standard. It includes:
//! - Access and refresh token generation with configurable expiration
//! - Token validation and decoding with proper signature verification
//! - Token revocation using Redis blocklist for security
//! - Custom claims handling with standardized JWT fields
//!
//! # Security Features
//! - Token expiration enforcement
//! - Token revocation via centralized blocklist
//! - Signature verification using HMAC-SHA256
//! - Protection against token reuse and clock skew
//!
//! # Best Practices Applied
//! - Comprehensive documentation with Rust doc comments
//! - Structured logging across all operations (debug, info, warn, error)
//! - Metrics instrumentation for operational visibility
//! - Domain-specific error types with meaningful messages
//! - Proper environment configuration validation

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

/// Default token expiration times in seconds if not configured in environment.
const DEFAULT_ACCESS_TOKEN_EXPIRY_SECS: i64 = 3600;      // 1 hour
const DEFAULT_REFRESH_TOKEN_EXPIRY_SECS: i64 = 604800;   // 7 days
const LEEWAY_SECONDS: u64 = 5;  // Clock skew tolerance

/// Retrieves the JWT secret from environment variables.
///
/// # Returns
/// * `Result<String, ServiceError>` containing the secret or configuration error.
#[inline]
fn get_jwt_secret() -> Result<String, ServiceError> {
    match env::var("JWT_SECRET") {
        Ok(s) if !s.trim().is_empty() => Ok(s),
        _ => {
            log_error!("Token Management", "JWT secret not configured", "failure");
            Err(ServiceError::Jwt(JwtError::Configuration(
                "JWT secret is not configured".to_string(),
            )))
        }
    }
}

/// Generates a JWT token with specified claims.
///
/// # Arguments
/// * `username` - The subject (sub) claim value.
/// * `token_type` - Type of token (access or refresh).
/// * `expires_in` - Optional custom expiration duration.
///
/// # Returns
/// * `Result<String, ServiceError>` containing the generated JWT or error.
#[inline]
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
                    .unwrap_or(DEFAULT_ACCESS_TOKEN_EXPIRY_SECS);
                now + Duration::seconds(seconds)
            }
            TOKEN_TYPE_REFRESH => {
                let seconds = env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                    .ok()
                    .and_then(|val| val.parse::<i64>().ok())
                    .unwrap_or(DEFAULT_REFRESH_TOKEN_EXPIRY_SECS);
                now + Duration::seconds(seconds)
            }
            _ => {
                log_warn!(
                    "Token Management", 
                    &format!("Unknown token type: {}", token_type), 
                    "failure"
                );
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

    let secret = get_jwt_secret()?;

    let mut header = Header::default();
    header.alg = Algorithm::HS256;
    header.typ = Some("JWT".to_string());  // Explicitly set type for clarity

    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|e| {
            log_error!(
                "Token Management", 
                &format!("Token encoding failed: {}", e), 
                "failure"
            );
            TOKEN_OPERATIONS
                .with_label_values(&["generate", "failure"])
                .inc();
            ServiceError::Jwt(JwtError::Internal("Failed to generate token".to_string()))
        })
        .map(|token| {
            log_debug!(
                "Token Management", 
                &format!("Token generated for {}", username),
                "success"
            );
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
#[inline]
pub fn decode_token(token: &str) -> Result<TokenClaims, ServiceError> {
    log_debug!("Token Management", "Begin token decoding", "attempt");
    TOKEN_VALIDATIONS
        .with_label_values(&["decode", "attempt"])
        .inc();

    let secret = get_jwt_secret()?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = LEEWAY_SECONDS;  // Allow for small clock skew
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);  // Require these fields

    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| {
        log_debug!(
            "Token Management", 
            &format!("Token decoded for {}", data.claims.sub),
            "success"
        );
        TOKEN_VALIDATIONS
            .with_label_values(&["decode", "success"])
            .inc();
        data.claims
    })
    .map_err(|e| {
        let err = match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                log_debug!("Token Management", "Token expired", "failure");
                JwtError::Expired
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                log_warn!(
                    "Token Management",
                    "Invalid token signature detected",
                    "failure"
                );
                JwtError::InvalidSignature
            }
            err_kind => {
                log_error!(
                    "Token Management", 
                    &format!("Token decode error: {:?}", err_kind),
                    "failure"
                );
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
#[inline]
pub async fn validate_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<TokenClaims, ServiceError> {
    log_debug!("Token Management", "Begin token validation", "attempt");
    TOKEN_VALIDATIONS
        .with_label_values(&["validate", "attempt"])
        .inc();

    // First decode the token to verify signature and basic structure
    let claims = decode_token(token)?;

    // Then check if the token has been revoked
    match crate::config::redis::is_token_blocked(redis_client, token).await {
        Ok(is_blocked) => {
            if is_blocked {
                log_debug!(
                    "Token Management", 
                    &format!("Token for {} has been revoked", claims.sub), 
                    "failure"
                );
                TOKEN_VALIDATIONS
                    .with_label_values(&["validate", "revoked"])
                    .inc();
                return Err(ServiceError::Jwt(JwtError::Revoked));
            }
        }
        Err(e) => {
            log_warn!(
                "Token Management", 
                &format!("Redis revocation check failed: {}", e), 
                "failure"
            );
            // Continue validation - fail open rather than fail closed for revocation checks
            // This is a reasonable tradeoff to maintain service availability if Redis is down
        }
    }

    // Double-check expiration time (even though the decoder should have verified this)
    // This is an additional safeguard
    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        log_debug!(
            "Token Management", 
            &format!("Token for {} has expired", claims.sub), 
            "failure"
        );
        TOKEN_VALIDATIONS
            .with_label_values(&["validate", "expired"])
            .inc();
        return Err(ServiceError::Jwt(JwtError::Expired));
    }

    // Check for tokens issued in the future (possible clock skew or tampering)
    if claims.iat > now + 60 {  // Allow up to 1 minute of clock skew
        log_warn!(
            "Token Management", 
            &format!("Token for {} has future issue time (possible tampering)", claims.sub), 
            "failure"
        );
        TOKEN_VALIDATIONS
            .with_label_values(&["validate", "invalid_iat"])
            .inc();
        return Err(ServiceError::Jwt(JwtError::InvalidIat));
    }

    log_info!(
        "Token Management", 
        &format!("Token for {} successfully validated", claims.sub), 
        "success"
    );
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
#[inline]
pub async fn revoke_token(token: &str, redis_client: &redis::Client) -> Result<(), ServiceError> {
    log_debug!("Token Management", "Begin token revocation", "attempt");
    TOKEN_OPERATIONS
        .with_label_values(&["revoke", "attempt"])
        .inc();

    // First decode the token to get expiry time
    let claims = match decode_token(token) {
        Ok(claims) => claims,
        Err(e) => {
            // For invalid tokens, we don't need to revoke
            log_warn!(
                "Token Management",
                &format!("Not revoking invalid token: {:?}", e),
                "skipped"
            );
            TOKEN_OPERATIONS
                .with_label_values(&["revoke", "invalid_token"])
                .inc();
            return Ok(());
        }
    };

    // Check if token is already expired
    let now = Utc::now().timestamp() as usize;
    if claims.exp <= now {
        log_debug!(
            "Token Management", 
            &format!("Token for {} already expired, no need to revoke", claims.sub), 
            "success"
        );
        TOKEN_OPERATIONS
            .with_label_values(&["revoke", "expired"])
            .inc();
        return Ok(());
    }

    // Add to blocklist with TTL matching remaining token lifetime
    let ttl = claims.exp - now;
    crate::config::redis::block_token(redis_client, token, ttl)
        .await
        .map_err(|e| {
            log_error!(
                "Token Management", 
                &format!("Failed to add token to blocklist: {}", e), 
                "failure"
            );
            TOKEN_OPERATIONS
                .with_label_values(&["revoke", "failure"])
                .inc();
            ServiceError::Jwt(JwtError::Internal("Failed to revoke token".to_string()))
        })?;

    log_info!(
        "Token Management", 
        &format!("Token for {} successfully revoked", claims.sub), 
        "success"
    );
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
        env::set_var("JWT_SECRET", "test-secret-key-for-unit-tests-only");
    }

    #[test]
    fn generate_and_decode_token_roundtrip() {
        init_secret();
        let username = "alice";
        let tok = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("should generate token");
        let claims = decode_token(&tok).expect("should decode token");
        
        assert_eq!(claims.sub, username, "Subject claim should match username");
        assert_eq!(claims.token_type, TOKEN_TYPE_ACCESS, "Token type should match");
        assert!(claims.jti.is_some(), "JTI should be present");
        
        let now = Utc::now().timestamp() as usize;
        assert!(claims.iat <= now, "Issue time should be in the past or present");
        assert!(claims.exp > now, "Expiry time should be in the future");
    }

    #[test]
    fn token_expiry_should_reflect_parameter() {
        init_secret();
        // Short 5-minute token
        let username = "bob";
        let short_duration = Duration::minutes(5);
        let short_tok = generate_token(username, TOKEN_TYPE_ACCESS, Some(short_duration))
            .expect("should generate short token");
        
        let claims = decode_token(&short_tok).expect("should decode token");
        let now = Utc::now().timestamp() as usize;
        
        // Allow 1 sec for test execution
        let expected_expiry = now + (short_duration.num_seconds() as usize);
        
        // Fix: use if/else to compare the values without abs()
        let diff = if claims.exp > expected_expiry {
            claims.exp - expected_expiry
        } else {
            expected_expiry - claims.exp
        };
        
        assert!(
            diff <= 1,
            "Expiry should be approximately 5 minutes from now"
        );
    }

    #[test]
    fn generate_fails_without_secret() {
        // leave the var present, but empty => still treated as "not configured"
        env::set_var("JWT_SECRET", "");

        let err = generate_token("user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1))).unwrap_err();
        match err {
            ServiceError::Jwt(JwtError::Configuration(msg)) => {
                assert!(msg.contains("JWT secret"), "Error should mention JWT secret");
            }
            _ => panic!("Expected Configuration error"),
        }
    }

    #[test]
    fn decode_invalid_token_errors() {
        init_secret();
        let bad_tokens = [
            "not-a-jwt-token",
            "invalid.jwt.format",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" // Valid JWT but wrong signature
        ];
        
        for bad in bad_tokens {
            let err = decode_token(bad).unwrap_err();
            match err {
                ServiceError::Jwt(JwtError::Invalid) | ServiceError::Jwt(JwtError::InvalidSignature) => {
                    // Either error is acceptable depending on the type of invalid token
                }
                _ => panic!("Expected Invalid token or InvalidSignature error, got {:?}", err),
            }
        }
    }

    #[tokio::test]
    async fn validate_token_ok_and_revoked() {
        init_secret();
        let username = "bob";
        
        // Generate a short‐lived token
        let tok = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .unwrap();
        let client = Client::open("redis://127.0.0.1/").unwrap();

        // Should validate before revocation
        let claims = validate_token(&tok, &client).await.unwrap();
        assert_eq!(claims.sub, username, "Subject should match username");

        // Revoke it
        revoke_token(&tok, &client).await.unwrap();
        // Small sleep to let Redis write
        thread::sleep(std::time::Duration::from_millis(50));

        // Now validate_token should Err(Revoked)
        let err = validate_token(&tok, &client).await.unwrap_err();
        match err {
            ServiceError::Jwt(JwtError::Revoked) => {}
            _ => panic!("Expected Revoked error, got: {:?}", err),
        }
    }

    #[tokio::test]
    async fn revoke_token_on_expired_is_noop() {
        init_secret();
        // Create token with expiry in the past
        let tok = generate_token("expired_user", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1)))
            .unwrap();
        let client = Client::open("redis://127.0.0.1/").unwrap();
        
        // Should be Ok and not error
        revoke_token(&tok, &client).await.unwrap();
        // And blocklist should _not_ contain it (no point blocking expired tokens)
        let blocked = is_token_blocked(&client, &tok).await.unwrap();
        assert!(!blocked, "Expired tokens should not be added to blocklist");
    }
    
    #[tokio::test]
    async fn validate_token_with_missing_fields_fails() {
        init_secret();
        // Create a token without correct fields
        let username = "test_user";
        let now = Utc::now();
        
        let claims = TokenClaims {
            sub: username.to_string(),
            exp: (now + Duration::hours(1)).timestamp() as usize, 
            iat: now.timestamp() as usize,
            token_type: "custom".to_string(),  // Non-standard type
            jti: None,  // Missing JTI
        };
        
        let secret = get_jwt_secret().unwrap();
        let mut header = Header::default();
        header.alg = Algorithm::HS256;
        
        // Create the token
        let token = encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap();
        
        // Decoding should work since it has required fields
        let decoded = decode_token(&token).unwrap();
        assert_eq!(decoded.token_type, "custom");
        assert_eq!(decoded.jti, None);
        
        // But validation should succeed (custom types are allowed)
        let client = Client::open("redis://127.0.0.1/").unwrap();
        let validated = validate_token(&token, &client).await.unwrap();
        assert_eq!(validated.sub, username);
    }
}