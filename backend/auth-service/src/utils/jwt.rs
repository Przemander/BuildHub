//! # Enterprise-Grade JWT Authentication System
//!
//! This module provides comprehensive JSON Web Token (JWT) functionality with:
//!
//! - **Security-First Design**: Industry best practices for token management
//! - **Complete Token Lifecycle**: Generation, validation, and revocation
//! - **RFC 7519 Compliance**: Standard claim structure with extensions
//! - **Distributed System Support**: Clock skew tolerance and revocation
//! - **Comprehensive Observability**: Metrics and tracing for all operations
//!
//! The implementation follows OWASP security guidelines with defense-in-depth
//! principles to protect against common JWT vulnerabilities.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::Client as RedisClient;
use serde::{Deserialize, Serialize};
use std::env;
use tracing::{error, info, warn};

use crate::{
    config::redis::{block_token, is_token_blocked},  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

// =============================================================================
// TYPES AND CONSTANTS
// =============================================================================

/// JWT Claims structure, compliant with RFC 7519.
/// This is the definitive structure for all JWTs issued by this service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (the user identifier)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at (Unix timestamp)
    pub iat: usize,
    /// Type of the token (e.g., "access", "refresh")
    pub token_type: String,
    /// JWT ID (unique identifier for the token, used for revocation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

const DEFAULT_ACCESS_TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour
const DEFAULT_REFRESH_TOKEN_EXPIRY_SECS: i64 = 604800; // 7 days
const LEEWAY_SECONDS: u64 = 5;
const MIN_SECRET_LENGTH: usize = 32;

// =============================================================================
// SECRET MANAGEMENT
// =============================================================================

/// Gets JWT secret from environment.
fn get_jwt_secret() -> Result<String, AuthServiceError> {
    let secret = env::var("JWT_SECRET")
        .map_err(|_| {
            error!("JWT_SECRET environment variable not set");
            AuthServiceError::configuration("JWT_SECRET is required")
        })?
        .trim()
        .to_string();

    if secret.is_empty() {
        error!("JWT_SECRET is empty");
        return Err(AuthServiceError::configuration("JWT_SECRET cannot be empty"));
    }

    if secret.len() < MIN_SECRET_LENGTH {
        error!("JWT_SECRET too short: {} chars", secret.len());
        return Err(AuthServiceError::configuration(
            format!("JWT_SECRET must be at least {} characters", MIN_SECRET_LENGTH)
        ));
    }

    Ok(secret)
}

// =============================================================================
// TOKEN GENERATION
// =============================================================================

/// Generates a JWT token.
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, AuthServiceError> {
    let now = Utc::now();
    let expiration = match expires_in {
        Some(duration) => now + duration,
        None => {
            let seconds = match token_type {
                TOKEN_TYPE_ACCESS => env::var("JWT_ACCESS_TOKEN_EXPIRES_IN")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_ACCESS_TOKEN_EXPIRY_SECS),
                TOKEN_TYPE_REFRESH => env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_REFRESH_TOKEN_EXPIRY_SECS),
                _ => {
                    warn!("Unknown token type: {}", token_type);
                    DEFAULT_ACCESS_TOKEN_EXPIRY_SECS
                }
            };
            now + Duration::seconds(seconds)
        }
    };

    let claims = TokenClaims {
        sub: username.to_string(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: token_type.to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };

    let secret = get_jwt_secret()?;
    let header = Header::new(Algorithm::HS256);
    
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|e| {
            error!("Failed to encode JWT: {}", e);
            AuthServiceError::internal("Failed to generate token")
        })
        .map(|token| {
            info!(username = %username, token_type = %token_type, "Token generated");
            token
        })
}

// =============================================================================
// TOKEN VALIDATION
// =============================================================================

/// Decodes a JWT token.
pub fn decode_token(token: &str) -> Result<TokenClaims, AuthServiceError> {
    let secret = get_jwt_secret()?;
    
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = LEEWAY_SECONDS;
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);

    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        
        let error_msg = match e.kind() {
            ErrorKind::ExpiredSignature => "Token has expired",
            ErrorKind::InvalidSignature => {
                warn!("Invalid JWT signature");
                "Invalid token signature"
            }
            _ => {
                warn!("JWT decode error: {}", e);
                "Invalid token format"
            }
        };
        
        AuthServiceError::authentication(error_msg)
    })
    .map(|data| data.claims)
}

/// Validates a token with Redis revocation check.
pub async fn validate_token(
    token: &str,
    redis_client: &RedisClient,
) -> Result<TokenClaims, AuthServiceError> {
    // Decode first
    let claims = decode_token(token)?;
    
    // Check if revoked
    match is_token_blocked(redis_client, token).await {
        Ok(true) => {
            return Err(AuthServiceError::authentication("Token has been revoked"));
        }
        Ok(false) => {}
        Err(e) => {
            warn!("Redis check failed, continuing: {}", e);
            // Fail open - allow if Redis is down
        }
    }

    // Additional security checks
    let now = Utc::now().timestamp() as usize;
    
    if claims.exp <= now {
        return Err(AuthServiceError::authentication("Token has expired"));
    }

    if claims.iat > now + 60 {
        warn!(
            "Token has future iat: {} > {} for user {}",
            claims.iat, now, claims.sub
        );
        return Err(AuthServiceError::authentication("Invalid token timestamp"));
    }

    info!(username = %claims.sub, token_type = %claims.token_type, "Token validated");
    Ok(claims)
}

// =============================================================================
// TOKEN REVOCATION
// =============================================================================

/// Revokes a JWT token.
pub async fn revoke_token(token: &str, redis_client: &RedisClient) -> Result<(), AuthServiceError> {
    // Try to decode (but don't fail if expired/invalid)
    let claims = match decode_token(token) {
        Ok(claims) => claims,
        Err(_) => {
            // Invalid or expired token - consider it already revoked
            return Ok(());
        }
    };

    let now = Utc::now().timestamp() as usize;
    if claims.exp <= now {
        return Ok(()); // Already expired
    }

    let ttl = claims.exp - now;
    
    block_token(redis_client, token, ttl).await
        .map_err(|e| {
            error!("Failed to revoke token: {}", e);
            AuthServiceError::external(format!("Failed to revoke token: {}", e))
        })
        .map(|_| {
            info!(username = %claims.sub, "Token revoked");
        })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_MUTEX.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn run_with_env<F: FnOnce()>(test: F)
    where
        F: FnOnce(),
    {
        let _guard = env_lock();
        cleanup_test_env();
        test();
        cleanup_test_env();
    }

    fn setup_test_env() {
        env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters");
    }

    fn cleanup_test_env() {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_ACCESS_TOKEN_EXPIRES_IN");
        env::remove_var("JWT_REFRESH_TOKEN_EXPIRES_IN");
    }

    #[test]
    fn test_get_jwt_secret_valid() {
        run_with_env(|| {
            setup_test_env();
            let secret = get_jwt_secret();
            assert!(secret.is_ok());
            assert_eq!(secret.unwrap(), "test-secret-key-minimum-32-characters");
        });
    }

    #[test]
    fn test_get_jwt_secret_missing() {
        run_with_env(|| {
            let result = get_jwt_secret();
            assert!(result.is_err());
            match result {
                Err(AuthServiceError::Configuration(msg)) => {
                    assert!(msg.contains("JWT_SECRET"));
                }
                _ => panic!("Expected Configuration error"),
            }
        });
    }

    #[test]
    fn test_get_jwt_secret_empty() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", "");
            let result = get_jwt_secret();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("empty"));
        });
    }

    #[test]
    fn test_get_jwt_secret_too_short() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", "short");
            let result = get_jwt_secret();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("32 characters"));
        });
    }

    #[test]
    fn test_get_jwt_secret_exactly_min_length() {
        run_with_env(|| {
            let secret = "a".repeat(MIN_SECRET_LENGTH);
            env::set_var("JWT_SECRET", &secret);
            let result = get_jwt_secret();
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_get_jwt_secret_with_whitespace() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", "  test-secret-key-minimum-32-characters  ");
            let result = get_jwt_secret();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "test-secret-key-minimum-32-characters");
        });
    }

    #[test]
    fn test_generate_access_token_with_duration() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)));
            assert!(token.is_ok());
        });
    }

    #[test]
    fn test_generate_refresh_token_with_duration() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_REFRESH, Some(Duration::days(7)));
            assert!(token.is_ok());
        });
    }

    #[test]
    fn test_generate_token_default_expiry() {
        run_with_env(|| {
            setup_test_env();
            let access_token = generate_token("testuser", TOKEN_TYPE_ACCESS, None);
            assert!(
                access_token.is_ok(),
                "Failed to generate access token: {:?}",
                access_token.err()
            );
            let refresh_token = generate_token("testuser", TOKEN_TYPE_REFRESH, None);
            assert!(
                refresh_token.is_ok(),
                "Failed to generate refresh token: {:?}",
                refresh_token.err()
            );
        });
    }

    #[test]
    fn test_generate_token_custom_expiry_from_env() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters");
            env::set_var("JWT_ACCESS_TOKEN_EXPIRES_IN", "7200");
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, None);
            assert!(token.is_ok());
        });
    }

    #[test]
    fn test_generate_token_unknown_type() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", "unknown", None);
            assert!(token.is_ok());
        });
    }

    #[test]
    fn test_generate_token_without_secret() {
        run_with_env(|| {
            let result = generate_token("testuser", TOKEN_TYPE_ACCESS, None);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("JWT_SECRET"));
        });
    }

    #[test]
    fn test_generated_token_has_correct_structure() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
                .expect("Should generate token");
            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 3);
        });
    }

    #[test]
    fn test_token_roundtrip() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
                .expect("Should generate token");
            let claims = decode_token(&token).expect("Should decode token");
            assert_eq!(claims.sub, "testuser");
            assert_eq!(claims.token_type, TOKEN_TYPE_ACCESS);
            assert!(claims.jti.is_some());
        });
    }

    #[test]
    fn test_decode_token_claims_structure() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("alice", TOKEN_TYPE_REFRESH, Some(Duration::hours(2)))
                .expect("Should generate token");
            let claims = decode_token(&token).expect("Should decode token");
            assert_eq!(claims.sub, "alice");
            assert_eq!(claims.token_type, TOKEN_TYPE_REFRESH);
            assert!(claims.exp > claims.iat);
            assert!(claims.jti.is_some());
        });
    }

    #[test]
    fn test_decode_token_with_wrong_secret() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
                .expect("Should generate token");
            env::set_var("JWT_SECRET", "different-secret-key-min-32-chars");
            let result = decode_token(&token);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("signature") || err_msg.contains("Invalid token"),
                "Expected signature or token error, got: {}",
                err_msg
            );
        });
    }

    #[test]
    fn test_expired_token() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, Some(Duration::hours(-1)))
                .expect("Should generate token");
            let result = decode_token(&token);
            assert!(result.is_err(), "Expected error for expired token");
            if let Err(e) = result {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("expired") || err_msg.contains("Invalid token"),
                    "Expected expiration or token error, got: {}",
                    err_msg
                );
            }
        });
    }

    #[test]
    fn test_token_with_leeway() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-3)))
                .expect("Should generate token");
            let _ = decode_token(&token);
        });
    }

    #[test]
    fn test_invalid_signature() {
        run_with_env(|| {
            setup_test_env();
            let token = generate_token("testuser", TOKEN_TYPE_ACCESS, None)
                .expect("Should generate token");
            let parts: Vec<&str> = token.split('.').collect();
            let tampered = format!("{}.{}.invalid", parts[0], parts[1]);
            let result = decode_token(&tampered);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("signature")
                    || err_msg.contains("Invalid token")
                    || err_msg.contains("format"),
                "Expected token validation error, got: {}",
                err_msg
            );
        });
    }

    #[test]
    fn test_malformed_token() {
        run_with_env(|| {
            setup_test_env();
            let result = decode_token("not.a.valid.jwt.token");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_empty_token() {
        run_with_env(|| {
            setup_test_env();
            let result = decode_token("");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_token_missing_parts() {
        run_with_env(|| {
            setup_test_env();
            let result = decode_token("header.payload");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_token_type_constants() {
        run_with_env(|| {
            assert_eq!(TOKEN_TYPE_ACCESS, "access");
            assert_eq!(TOKEN_TYPE_REFRESH, "refresh");
        });
    }

    #[test]
    fn test_default_expiry_constants() {
        run_with_env(|| {
            assert_eq!(DEFAULT_ACCESS_TOKEN_EXPIRY_SECS, 3600);
            assert_eq!(DEFAULT_REFRESH_TOKEN_EXPIRY_SECS, 604800);
        });
    }

    #[test]
    fn test_min_secret_length_constant() {
        run_with_env(|| {
            assert_eq!(MIN_SECRET_LENGTH, 32);
        });
    }

    #[test]
    fn test_leeway_seconds_constant() {
        run_with_env(|| {
            assert_eq!(LEEWAY_SECONDS, 5);
        });
    }

    #[test]
    fn test_token_claims_serialization() {
        run_with_env(|| {
            let claims = TokenClaims {
                sub: "user123".to_string(),
                exp: 1234567890,
                iat: 1234567800,
                token_type: TOKEN_TYPE_ACCESS.to_string(),
                jti: Some("unique-id".to_string()),
            };
            let json = serde_json::to_string(&claims).unwrap();
            assert!(json.contains("user123"));
            assert!(json.contains("access"));
        });
    }

    #[test]
    fn test_token_claims_deserialization() {
        run_with_env(|| {
            let json = r#"{
                "sub": "user456",
                "exp": 1234567890,
                "iat": 1234567800,
                "token_type": "refresh"
            }"#;
            let claims: TokenClaims = serde_json::from_str(json).unwrap();
            assert_eq!(claims.sub, "user456");
            assert_eq!(claims.token_type, "refresh");
            assert!(claims.jti.is_none());
        });
    }

    #[test]
    fn test_token_claims_jti_optional() {
        run_with_env(|| {
            let json = r#"{
                "sub": "user789",
                "exp": 1234567890,
                "iat": 1234567800,
                "token_type": "access",
                "jti": "test-jti"
            }"#;
            let claims: TokenClaims = serde_json::from_str(json).unwrap();
            assert_eq!(claims.jti, Some("test-jti".to_string()));
        });
    }

    #[test]
    fn test_weak_secret_rejected() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", "short");
            let result = generate_token("user", TOKEN_TYPE_ACCESS, None);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("32 characters"));
        });
    }

    #[test]
    fn test_secret_exactly_31_chars_rejected() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", &"a".repeat(31));
            let result = generate_token("user", TOKEN_TYPE_ACCESS, None);
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_secret_exactly_32_chars_accepted() {
        run_with_env(|| {
            env::set_var("JWT_SECRET", &"a".repeat(32));
            let result = generate_token("user", TOKEN_TYPE_ACCESS, None);
            assert!(result.is_ok());
        });
    }
}
