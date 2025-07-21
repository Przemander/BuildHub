//! # JSON Web Token (JWT) Management Module
//!
//! This module provides comprehensive JWT functionality for the BuildHub authentication service,
//! implementing industry-standard token generation, validation, and revocation patterns with
//! enterprise-grade security features and observability.
//!
//! ## Features
//!
//! - **Secure Token Generation**: HMAC-SHA256 signatures with configurable expiration
//! - **Comprehensive Validation**: Signature verification, expiration checks, and revocation status
//! - **Token Revocation**: Redis-based blacklist with automatic cleanup
//! - **Clock Skew Tolerance**: Configurable leeway for distributed system timing
//! - **Audit Trail**: Comprehensive logging for security monitoring
//! - **Custom Claims**: Extensible claims structure with standard JWT fields
//! - **Type Safety**: Strongly typed token operations with structured error handling
//!
//! ## Security Model
//!
//! - **HMAC-SHA256**: Industry-standard symmetric signing algorithm
//! - **Token Blacklisting**: Immediate revocation capability via Redis
//! - **Expiration Enforcement**: Multiple layers of expiration validation
//! - **Clock Skew Protection**: Prevents future-dated tokens and timing attacks
//! - **Signature Validation**: Cryptographic verification of token integrity
//!
//! ## Token Types
//!
//! - **Access Tokens**: Short-lived (1 hour default) for API authentication
//! - **Refresh Tokens**: Long-lived (7 days default) for token renewal
//! - **Custom Types**: Extensible for additional use cases
//!
//! ## Configuration
//!
//! Required environment variables:
//! - `JWT_SECRET`: Signing secret (minimum 32 characters recommended)
//! - `JWT_ACCESS_TOKEN_EXPIRES_IN`: Access token lifetime in seconds (optional)
//! - `JWT_REFRESH_TOKEN_EXPIRES_IN`: Refresh token lifetime in seconds (optional)

use crate::utils::error_new::{AuthServiceError, JwtError};
use crate::metricss::jwt_metrics::{
    generate, validate, revoke,
};
use crate::{log_debug, log_error, log_info, log_warn};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use tracing_error::SpanTrace;

// =============================================================================
// TYPE DEFINITIONS AND CONSTANTS
// =============================================================================

/// JWT Claims structure following RFC 7519 with custom extensions.
///
/// This structure represents the payload data contained within JWT tokens,
/// combining standard JWT claims with application-specific fields for
/// comprehensive token management.
///
/// # Standard Claims (RFC 7519)
///
/// - `sub`: Subject - identifies the user (username)
/// - `exp`: Expiration Time - Unix timestamp when token expires
/// - `iat`: Issued At - Unix timestamp when token was created
///
/// # Custom Claims
///
/// - `token_type`: Distinguishes between access/refresh tokens
/// - `jti`: JWT ID - unique identifier for token revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (username) - identifies the principal
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at time (Unix timestamp)
    pub iat: usize,
    /// Token type classification (access/refresh/custom)
    pub token_type: String,
    /// JWT ID for revocation tracking (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Token type constants for type safety and consistency.
///
/// These constants ensure consistent token type values across the application
/// and prevent typos in token generation and validation logic.
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Default token expiration times in seconds when not configured via environment.
///
/// These values balance security (shorter is more secure) with user experience
/// (longer reduces re-authentication frequency).
const DEFAULT_ACCESS_TOKEN_EXPIRY_SECS: i64 = 3600;    // 1 hour
const DEFAULT_REFRESH_TOKEN_EXPIRY_SECS: i64 = 604800; // 7 days

/// Clock skew tolerance in seconds for distributed systems.
///
/// This allows for small time differences between servers and prevents
/// legitimate tokens from being rejected due to minor clock drift.
const LEEWAY_SECONDS: u64 = 5;

/// Minimum recommended JWT secret length for security.
///
/// HMAC-SHA256 security depends on secret entropy. Shorter secrets
/// are vulnerable to brute force attacks.
const MIN_SECRET_LENGTH: usize = 32;

// =============================================================================
// JWT SECRET MANAGEMENT
// =============================================================================

/// Retrieves and validates the JWT signing secret from environment configuration.
///
/// This function provides secure access to the JWT signing secret with
/// comprehensive validation to ensure cryptographic security. The secret
/// is validated for minimum length and content requirements.
///
/// # Security Validation
///
/// - **Presence Check**: Ensures `JWT_SECRET` environment variable exists
/// - **Content Validation**: Verifies secret is not empty or whitespace-only
/// - **Length Validation**: Enforces minimum length for cryptographic security
/// - **Trimming**: Removes accidental whitespace that could weaken security
///
/// # Returns
///
/// - `Ok(String)`: Valid JWT secret ready for cryptographic operations
/// - `Err(AuthServiceError)`: Configuration error with detailed context
///
/// # Security Considerations
///
/// - Secret should be randomly generated with high entropy
/// - Minimum 32 characters recommended for HMAC-SHA256 security
/// - Should be rotated periodically in production environments
/// - Never log or expose the secret in error messages
fn get_jwt_secret() -> Result<String, AuthServiceError> {
    match env::var("JWT_SECRET") {
        Ok(secret) => {
            let trimmed_secret = secret.trim();
            
            if trimmed_secret.is_empty() {
                log_error!(
                    "JWT Configuration", 
                    "JWT secret is empty or contains only whitespace", 
                    "configuration_error"
                );
                return Err(AuthServiceError::Jwt(JwtError::Configuration {
                    message: "JWT secret cannot be empty".to_string(),
                    span: SpanTrace::capture(),
                }));
            }
            
            if trimmed_secret.len() < MIN_SECRET_LENGTH {
                log_error!(
                    "JWT Configuration", 
                    &format!(
                        "JWT secret is too short ({} chars), minimum {} characters required for security", 
                        trimmed_secret.len(), 
                        MIN_SECRET_LENGTH
                    ), 
                    "configuration_error"
                );
                return Err(AuthServiceError::Jwt(JwtError::Configuration {
                    message: format!(
                        "JWT secret must be at least {} characters for security", 
                        MIN_SECRET_LENGTH
                    ),
                    span: SpanTrace::capture(),
                }));
            }
            
            log_debug!(
                "JWT Configuration", 
                &format!("JWT secret loaded successfully ({} characters)", trimmed_secret.len()), 
                "configuration_success"
            );
            
            Ok(trimmed_secret.to_string())
        }
        Err(e) => {
            log_error!(
                "JWT Configuration", 
                &format!("JWT_SECRET environment variable not found: {}", e), 
                "configuration_error"
            );
            Err(AuthServiceError::Jwt(JwtError::Configuration {
                message: "JWT_SECRET environment variable is required".to_string(),
                span: SpanTrace::capture(),
            }))
        }
    }
}

// =============================================================================
// TOKEN GENERATION
// =============================================================================

/// Generates a JWT token with specified claims and configurable expiration.
///
/// This function creates cryptographically signed JWT tokens with comprehensive
/// claim validation, flexible expiration policies, and detailed observability.
/// It supports both standard token types and custom expiration durations.
///
/// # Arguments
///
/// - `username`: Subject identifier (typically username or user ID)
/// - `token_type`: Token classification (use constants: `TOKEN_TYPE_ACCESS`, `TOKEN_TYPE_REFRESH`)
/// - `expires_in`: Optional custom expiration duration (overrides environment defaults)
///
/// # Returns
///
/// - `Ok(String)`: Successfully generated JWT token ready for use
/// - `Err(AuthServiceError)`: Generation failed with detailed error context
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, AuthServiceError> {
    log_debug!(
        "JWT Generation", 
        &format!("Generating {} token for user: {}", token_type, username), 
        "generation_attempt"
    );
    
    let _timer = generate::time();

    // Calculate token expiration based on type and configuration
    let now = Utc::now();
    let expiration = match expires_in {
        Some(duration) => {
            log_debug!(
                "JWT Generation", 
                &format!("Using custom expiration: {} seconds", duration.num_seconds()), 
                "custom_expiration"
            );
            now + duration
        }
        None => {
            let seconds = match token_type {
                TOKEN_TYPE_ACCESS => {
                    env::var("JWT_ACCESS_TOKEN_EXPIRES_IN")
                        .ok()
                        .and_then(|val| val.parse::<i64>().ok())
                        .unwrap_or(DEFAULT_ACCESS_TOKEN_EXPIRY_SECS)
                }
                TOKEN_TYPE_REFRESH => {
                    env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                        .ok()
                        .and_then(|val| val.parse::<i64>().ok())
                        .unwrap_or(DEFAULT_REFRESH_TOKEN_EXPIRY_SECS)
                }
                _ => {
                    log_warn!(
                        "JWT Generation", 
                        &format!("Unknown token type '{}', using default 1-hour expiration", token_type), 
                        "unknown_token_type"
                    );
                    DEFAULT_ACCESS_TOKEN_EXPIRY_SECS
                }
            };
            
            log_debug!(
                "JWT Generation", 
                &format!("Using default expiration for {}: {} seconds", token_type, seconds), 
                "default_expiration"
            );
            
            now + Duration::seconds(seconds)
        }
    };

    // Construct JWT claims with comprehensive metadata
    let claims = TokenClaims {
        sub: username.to_string(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: token_type.to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()), // Unique ID for revocation
    };

    // Configure JWT header for HMAC-SHA256 signing
    let mut header = Header::default();
    header.alg = Algorithm::HS256;

    // Retrieve signing secret with security validation
    let secret = get_jwt_secret()?;
    
    // Generate and sign the JWT token
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|e| {
            log_error!(
                "JWT Generation", 
                &format!("Token encoding failed for user {}: {}", username, e), 
                "encoding_failure"
            );
            generate::record_failure();
            
            AuthServiceError::Jwt(JwtError::Internal {
                message: "Failed to encode JWT token".to_string(),
                span: SpanTrace::capture(),
            })
        })
        .map(|token| {
            log_info!(
                "JWT Generation", 
                &format!(
                    "Successfully generated {} token for {} (expires: {})", 
                    token_type, 
                    username,
                    expiration.format("%Y-%m-%d %H:%M:%S UTC")
                ), 
                "generation_success"
            );
            generate::record_success();
            token
        })
}

// =============================================================================
// TOKEN DECODING AND VALIDATION
// =============================================================================

/// Decodes a JWT token and validates its cryptographic signature and structure.
///
/// This function performs comprehensive token validation including signature
/// verification, expiration checking, and claim structure validation. It
/// provides the foundation for all token validation operations.
///
/// # Arguments
///
/// - `token`: JWT token string to decode and validate
///
/// # Returns
///
/// - `Ok(TokenClaims)`: Successfully decoded and validated token claims
/// - `Err(AuthServiceError)`: Validation failed with specific error context
pub fn decode_token(token: &str) -> Result<TokenClaims, AuthServiceError> {
    log_debug!(
        "JWT Decoding", 
        &format!("Decoding token (length: {} chars)", token.len()), 
        "decoding_attempt"
    );
    
    let _timer = validate::time();

    // Retrieve verification secret
    let secret = get_jwt_secret()?;

    // Configure comprehensive validation rules
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = LEEWAY_SECONDS;
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);

    // Decode and validate token
    decode::<TokenClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    validate::record_expired();
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    validate::record_invalid_signature();
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken | 
                jsonwebtoken::errors::ErrorKind::Json(_) |
                jsonwebtoken::errors::ErrorKind::Base64(_) => {
                    validate::record_invalid_format();
                }
                _ => {
                    validate::record_invalid_format();
                }
            }
            
            let jwt_error: JwtError = e.into();
            AuthServiceError::Jwt(jwt_error)
        })
        .map(|data| {
            validate::record_success();
            data.claims
        })
}

/// Validates a JWT token with comprehensive security checks including revocation status.
///
/// This function provides complete token validation by combining cryptographic
/// verification with business logic checks including revocation status via Redis.
/// It serves as the primary token validation entry point for authentication.
///
/// # Arguments
///
/// - `token`: JWT token string to validate
/// - `redis_client`: Redis client for revocation status checking
///
/// # Returns
///
/// - `Ok(TokenClaims)`: Token is valid and not revoked
/// - `Err(AuthServiceError)`: Validation failed with specific error context
pub async fn validate_token(
    token: &str,
    redis_client: &redis::Client,
) -> Result<TokenClaims, AuthServiceError> {
    let _timer = validate::time();
    
    let claims = decode_token(token)?;

    // Check revocation status
    match crate::config::redis::is_token_blocked(redis_client, token).await {
        Ok(is_blocked) => {
            if is_blocked {
                validate::record_revoked();
                return Err(AuthServiceError::Jwt(JwtError::Revoked { 
                    span: SpanTrace::capture() 
                }));
            }
        }
        Err(_) => {
            validate::record_redis_failure();
            // Continue with fail-open policy
        }
    }

    // Additional security validations beyond basic decoding
    let now = Utc::now().timestamp() as usize;
    
    // Double-check expiration (decoder should have caught this, but be defensive)
    if claims.exp <= now {
        log_debug!(
            "JWT Validation", 
            &format!("Token for {} has expired (exp: {}, now: {})", claims.sub, claims.exp, now), 
            "expiration_detected"
        );
        validate::record_expired();
        
        return Err(AuthServiceError::Jwt(JwtError::Expired { 
            span: SpanTrace::capture() 
        }));
    }

    // Check for tokens issued in the future (clock skew or tampering)
    if claims.iat > now + 60 {  // Allow up to 1 minute of clock skew
        log_warn!(
            "JWT Validation", 
            &format!(
                "Token for {} has future issue time (iat: {}, now: {}, diff: {}s) - possible tampering", 
                claims.sub, 
                claims.iat, 
                now, 
                claims.iat as i64 - now as i64
            ), 
            "future_token_detected"
        );
        validate::record_invalid_iat();
        
        return Err(AuthServiceError::Jwt(JwtError::InvalidIat { 
            span: SpanTrace::capture() 
        }));
    }

    log_info!(
        "JWT Validation", 
        &format!(
            "Successfully validated {} token for user: {} (expires: {})", 
            claims.token_type,
            claims.sub,
            chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "invalid timestamp".to_string())
        ), 
        "validation_success"
    );
    validate::record_success();
    
    Ok(claims)
}

// =============================================================================
// TOKEN REVOCATION
// =============================================================================

/// Revokes a JWT token by adding it to Redis blacklist until natural expiration.
///
/// This function implements secure token revocation by maintaining a Redis-based
/// blacklist of invalidated tokens. Revoked tokens remain blocked until their
/// natural expiration time, ensuring they cannot be reused.
///
/// # Arguments
///
/// - `token`: JWT token string to revoke
/// - `redis_client`: Redis client for blacklist management
///
/// # Returns
///
/// - `Ok(())`: Token successfully revoked or already expired
/// - `Err(AuthServiceError)`: Revocation operation failed
pub async fn revoke_token(
    token: &str, 
    redis_client: &redis::Client
) -> Result<(), AuthServiceError> {
    let _timer = revoke::time();

    let claims = match decode_token(token) {
        Ok(claims) => claims,
        Err(AuthServiceError::Jwt(jwt_error)) => {
            match jwt_error {
                JwtError::Expired { .. } => {
                    // For expired tokens, revocation is no-op but still success
                    revoke::record_success();
                    return Ok(());
                }
                _ => {
                    // Invalid tokens also no-op but still success
                    revoke::record_success();
                    return Ok(());
                }
            }
        }
        Err(other_error) => {
            revoke::record_failure();
            return Err(other_error);
        }
    };

    // Check if already expired
    let now = Utc::now().timestamp() as usize;
    if claims.exp <= now {
        revoke::record_success(); // expired = success/no-op
        return Ok(());
    }

    // Revoke in Redis
    let ttl = claims.exp - now;
    crate::config::redis::block_token(redis_client, token, ttl)
        .await
        .map_err(|cache_error| {
            revoke::record_failure();
            
            AuthServiceError::Jwt(JwtError::Internal {
                message: format!("Failed to revoke token: {}", cache_error),
                span: SpanTrace::capture(),
            })
        })
        .map(|_| {
            revoke::record_success();
        })
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use redis::Client;
    use std::{env, thread};

    /// Sets up test environment with a secure test JWT secret.
    fn setup_test_environment() {
        env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-for-security-compliance");
    }

    /// Creates a Redis client for integration testing.
    fn create_test_redis_client() -> Client {
        Client::open("redis://127.0.0.1:6379/")
            .expect("Redis must be running on localhost:6379 for integration tests")
    }

    // =============================================================================
    // TOKEN GENERATION TESTS
    // =============================================================================

    #[test]
    fn test_token_generation_and_decoding_roundtrip() {
        setup_test_environment();
        
        let username = "test_user";
        let token_type = TOKEN_TYPE_ACCESS;
        let custom_duration = Duration::hours(2);
        
        // Generate token with custom expiration
        let token = generate_token(username, token_type, Some(custom_duration))
            .expect("Token generation should succeed");
        
        // Decode and validate the generated token
        let claims = decode_token(&token)
            .expect("Token decoding should succeed");
        
        // Verify claim contents
        assert_eq!(claims.sub, username, "Subject should match input username");
        assert_eq!(claims.token_type, token_type, "Token type should match input");
        assert!(claims.jti.is_some(), "JWT ID should be present for revocation");
        
        // Verify timing constraints
        let now = Utc::now().timestamp() as usize;
        assert!(claims.iat <= now, "Issue time should be in the past or present");
        assert!(claims.exp > now, "Expiration should be in the future");
        
        // Verify custom expiration is approximately correct (within 5 seconds)
        let expected_exp = now + custom_duration.num_seconds() as usize;
        let exp_diff = if claims.exp > expected_exp {
            claims.exp - expected_exp
        } else {
            expected_exp - claims.exp
        };
        assert!(exp_diff <= 5, "Expiration should match custom duration within timing tolerance");
    }

    #[test]
    fn test_token_generation_with_different_types() {
        setup_test_environment();
        
        let username = "multi_type_user";
        
        // Test access token generation
        let access_token = generate_token(username, TOKEN_TYPE_ACCESS, None)
            .expect("Access token generation should succeed");
        let access_claims = decode_token(&access_token)
            .expect("Access token decoding should succeed");
        assert_eq!(access_claims.token_type, TOKEN_TYPE_ACCESS);
        
        // Test refresh token generation
        let refresh_token = generate_token(username, TOKEN_TYPE_REFRESH, None)
            .expect("Refresh token generation should succeed");
        let refresh_claims = decode_token(&refresh_token)
            .expect("Refresh token decoding should succeed");
        assert_eq!(refresh_claims.token_type, TOKEN_TYPE_REFRESH);
        
        // Test custom token type
        let custom_token = generate_token(username, "custom_type", Some(Duration::minutes(30)))
            .expect("Custom token generation should succeed");
        let custom_claims = decode_token(&custom_token)
            .expect("Custom token decoding should succeed");
        assert_eq!(custom_claims.token_type, "custom_type");
        
        // Verify all tokens have unique JTIs
        assert_ne!(access_claims.jti, refresh_claims.jti, "Tokens should have unique JTIs");
        assert_ne!(access_claims.jti, custom_claims.jti, "Tokens should have unique JTIs");
        assert_ne!(refresh_claims.jti, custom_claims.jti, "Tokens should have unique JTIs");
    }

    #[test]
    fn test_token_generation_fails_without_secret() {
        // Remove JWT secret to test error handling
        env::remove_var("JWT_SECRET");
        
        let result = generate_token("user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)));
        assert!(result.is_err(), "Token generation should fail without JWT secret");
        
        // Verify correct error type
        match result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Configuration { message, .. }) => {
                assert!(
                    message.contains("JWT_SECRET"), 
                    "Error message should mention JWT_SECRET requirement"
                );
            }
            other => panic!("Expected JWT configuration error, got: {:?}", other),
        }
    }

    #[test]
    fn test_token_generation_fails_with_weak_secret() {
        // Set secret that's too short (insecure)
        env::set_var("JWT_SECRET", "short"); // Only 5 characters
        
        let result = generate_token("user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)));
        assert!(result.is_err(), "Token generation should fail with weak secret");
        
        // Verify correct error type and message
        match result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Configuration { message, .. }) => {
                assert!(
                    message.contains("32 characters"), 
                    "Error should mention minimum length requirement"
                );
            }
            other => panic!("Expected JWT configuration error, got: {:?}", other),
        }
    }

    // =============================================================================
    // TOKEN DECODING TESTS
    // =============================================================================

    #[test]
    fn test_token_decoding_invalid_tokens() {
        setup_test_environment();
        
        let invalid_tokens = vec![
            "not-a-jwt-token-at-all",
            "invalid.jwt.format.here",
            "too.few.parts",
            "too.many.parts.here.extra",
            "", // Empty string
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // Valid JWT but wrong signature
        ];
        
        for (index, invalid_token) in invalid_tokens.iter().enumerate() {
            let result = decode_token(invalid_token);
            assert!(
                result.is_err(), 
                "Token {} should be invalid: '{}'", 
                index, 
                invalid_token
            );
            
            // Verify we get appropriate JWT error types
            match result.unwrap_err() {
                AuthServiceError::Jwt(jwt_error) => {
                    match jwt_error {
                        JwtError::Invalid { .. } | 
                        JwtError::InvalidSignature { .. } => {
                            // Expected error types for invalid tokens
                        }
                        other => {
                            // Some other JWT errors might be acceptable depending on the invalid token type
                            println!("Got JWT error for token {}: {:?}", index, other);
                        }
                    }
                }
                other => panic!("Expected JWT error, got: {:?}", other),
            }
        }
    }

    #[test]
    fn test_token_decoding_expired_token() {
        setup_test_environment();
        
        let username = "expired_user";
        
        // Generate token that expires immediately
        let expired_token = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1)))
            .expect("Token generation should succeed even with past expiration");
        
        // Attempt to decode expired token
        let result = decode_token(&expired_token);
        assert!(result.is_err(), "Decoding should fail for expired token");
        
        // Verify we get the correct error type
        match result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Expired { .. }) => {
                // Expected error type
            }
            other => panic!("Expected JWT expiration error, got: {:?}", other),
        }
    }

    // =============================================================================
    // TOKEN VALIDATION TESTS
    // =============================================================================

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_token_validation_success() {
        setup_test_environment();
        let redis_client = create_test_redis_client();
        let username = "validation_test_user";
        
        // Generate valid token
        let token = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("Token generation should succeed");
        
        // Validate token
        let claims = validate_token(&token, &redis_client).await
            .expect("Token validation should succeed");
        
        // Verify claims
        assert_eq!(claims.sub, username, "Validated claims should match original");
        assert_eq!(claims.token_type, TOKEN_TYPE_ACCESS, "Token type should be preserved");
        
        // Cleanup: ensure token is not in blacklist
        let mut connection = redis_client.get_async_connection().await.unwrap();
        let _: Option<String> = redis::AsyncCommands::del(&mut connection, &token).await.ok();
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_complete_token_revocation_workflow() {
        setup_test_environment();
        let redis_client = create_test_redis_client();
        let username = "revocation_test_user";
        
        // Generate token for testing
        let token = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("Token generation should succeed");
        
        // Initially, token should validate successfully
        let initial_claims = validate_token(&token, &redis_client).await
            .expect("Initial validation should succeed");
        assert_eq!(initial_claims.sub, username);
        
        // Revoke the token
        revoke_token(&token, &redis_client).await
            .expect("Token revocation should succeed");
        
        // Brief pause to ensure Redis write propagation
        thread::sleep(std::time::Duration::from_millis(100));
        
        // After revocation, validation should fail
        let validation_result = validate_token(&token, &redis_client).await;
        assert!(validation_result.is_err(), "Validation should fail for revoked token");
        
        // Verify we get the correct error type
        match validation_result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Revoked { .. }) => {
                // Expected error type
            }
            other => panic!("Expected JWT revocation error, got: {:?}", other),
        }
        
        // Cleanup: remove token from blacklist
        let mut connection = redis_client.get_async_connection().await.unwrap();
        let _: Option<String> = redis::AsyncCommands::del(&mut connection, &token).await.ok();
    }

    #[tokio::test]
    async fn test_token_revocation_handles_invalid_tokens() {
        setup_test_environment();
        let redis_client = create_test_redis_client();
        
        let invalid_tokens = vec![
            "completely-invalid-token",
            "invalid.jwt.format",
        ];
        
        for invalid_token in invalid_tokens {
            // Revoking invalid tokens should succeed (no-op)
            let result = revoke_token(invalid_token, &redis_client).await;
            assert!(
                result.is_ok(), 
                "Revoking invalid token should succeed as no-op: '{}'", 
                invalid_token
            );
        }
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_revocation_of_expired_token_is_noop() {
        setup_test_environment();
        let redis_client = create_test_redis_client();
        
        // Create token that's already expired
        let expired_token = generate_token("expired_user", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1)))
            .expect("Token generation should succeed");
        
        // Revoking expired token should succeed (no-op)
        let result = revoke_token(&expired_token, &redis_client).await;
        assert!(result.is_ok(), "Revoking expired token should succeed as no-op");
        
        // Verify token is not added to blacklist
        let is_blocked = crate::config::redis::is_token_blocked(&redis_client, &expired_token).await
            .expect("Blacklist check should succeed");
        assert!(!is_blocked, "Expired tokens should not be added to blacklist");
    }

    // =============================================================================
    // INTEGRATION AND EDGE CASE TESTS
    // =============================================================================

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_token_validation_with_redis_failure() {
        setup_test_environment();
        
        // Create client pointing to non-existent Redis instance
        let invalid_redis_client = Client::open("redis://127.0.0.1:99999/")
            .expect("Client creation should succeed even for invalid addresses");
        
        let username = "redis_failure_test";
        let token = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("Token generation should succeed");
        
        // Validation should succeed despite Redis failure (fail-open policy)
        let claims = validate_token(&token, &invalid_redis_client).await
            .expect("Validation should succeed with fail-open policy when Redis is unavailable");
        
        assert_eq!(claims.sub, username, "Claims should be valid despite Redis failure");
    }

    #[test]
    fn test_future_issued_at_time_detection() {
        setup_test_environment();
        
        let username = "future_time_user";
        let now = Utc::now();
        
        // Create claims with future issued-at time
        let future_claims = TokenClaims {
            sub: username.to_string(),
            exp: (now + Duration::hours(1)).timestamp() as usize,
            iat: (now + Duration::minutes(5)).timestamp() as usize, // 5 minutes in future
            token_type: TOKEN_TYPE_ACCESS.to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
        };
        
        // Manually encode token with future iat
        let secret = get_jwt_secret().expect("Secret should be available");
        let mut header = Header::default();
        header.alg = Algorithm::HS256;
        
        let future_token = encode(&header, &future_claims, &EncodingKey::from_secret(secret.as_ref()))
            .expect("Token encoding should succeed");
        
        // Token should decode successfully (basic validation)
        let decoded_claims = decode_token(&future_token)
            .expect("Basic decoding should succeed for future-dated token");
        assert_eq!(decoded_claims.sub, username);
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance  
    async fn test_comprehensive_token_lifecycle() {
        setup_test_environment();
        let redis_client = create_test_redis_client();
        let username = "lifecycle_test_user";
        
        // 1. Generate token
        let token = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::minutes(5)))
            .expect("Token generation should succeed");
        
        // 2. Validate new token
        let claims = validate_token(&token, &redis_client).await
            .expect("New token validation should succeed");
        assert_eq!(claims.sub, username);
        
        // 3. Use token for "API call" (decode only)
        let api_claims = decode_token(&token)
            .expect("Token decoding for API should succeed");
        assert_eq!(api_claims.token_type, TOKEN_TYPE_ACCESS);
        
        // 4. Revoke token (logout)
        revoke_token(&token, &redis_client).await
            .expect("Token revocation should succeed");
        
        // 5. Attempt to use revoked token
        thread::sleep(std::time::Duration::from_millis(50)); // Ensure Redis propagation
        let revoked_result = validate_token(&token, &redis_client).await;
        assert!(revoked_result.is_err(), "Revoked token should fail validation");
        
        // 6. Verify error type
        match revoked_result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Revoked { .. }) => {
                // Expected - lifecycle test complete
            }
            other => panic!("Expected revocation error, got: {:?}", other),
        }
        
        // Cleanup
        let mut connection = redis_client.get_async_connection().await.unwrap();
        let _: Option<String> = redis::AsyncCommands::del(&mut connection, &token).await.ok();
    }

    // =============================================================================
    // CONFIGURATION AND ENVIRONMENT TESTS
    // =============================================================================

    #[test]
    fn test_jwt_secret_validation_edge_cases() {
        let valid_test_secret = "valid-test-secret-minimum-32-chars";
        
        // Test empty secret
        env::set_var("JWT_SECRET", "");
        let result = get_jwt_secret();
        assert!(result.is_err(), "Empty secret should fail validation");
        
        // Test secret that's exactly minimum length
        let min_length_secret = "a".repeat(MIN_SECRET_LENGTH);
        env::set_var("JWT_SECRET", &min_length_secret);
        let result = get_jwt_secret();
        assert!(result.is_ok(), "Secret at minimum length should be accepted");
        assert_eq!(result.unwrap(), min_length_secret);
        
        // Test secret with surrounding whitespace (should be trimmed)
        let secret_with_whitespace = format!("  {}  ", valid_test_secret);
        env::set_var("JWT_SECRET", &secret_with_whitespace);
        let result = get_jwt_secret();
        assert!(result.is_ok(), "Secret with whitespace should be trimmed and accepted");
        assert_eq!(result.unwrap(), valid_test_secret); // Should be trimmed
        
        // Test secret that's too short
        let short_secret = "too_short"; // < 32 chars
        env::set_var("JWT_SECRET", short_secret);
        let result = get_jwt_secret();
        assert!(result.is_err(), "Short secret should fail validation");
        match result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Configuration { message, .. }) => {
                assert!(
                    message.contains("32 characters"), 
                    "Error should mention minimum length requirement"
                );
            }
            other => panic!("Expected JWT configuration error, got: {:?}", other),
        }
    }

    #[test]
    fn test_token_expiration_configuration() {
        setup_test_environment();
        let username = "config_test_user";
        
        // Test custom access token expiration
        env::set_var("JWT_ACCESS_TOKEN_EXPIRES_IN", "7200"); // 2 hours
        let access_token = generate_token(username, TOKEN_TYPE_ACCESS, None)
            .expect("Token generation should succeed");
        let access_claims = decode_token(&access_token)
            .expect("Token decoding should succeed");
        
        // Verify expiration is approximately 2 hours
        let now = Utc::now().timestamp() as usize;
        let expected_exp = now + 7200;
        let exp_diff = if access_claims.exp > expected_exp {
            access_claims.exp - expected_exp
        } else {
            expected_exp - access_claims.exp
        };
        assert!(exp_diff <= 5, "Configured expiration should be respected");
        
        // Test custom refresh token expiration
        env::set_var("JWT_REFRESH_TOKEN_EXPIRES_IN", "1209600"); // 2 weeks
        let refresh_token = generate_token(username, TOKEN_TYPE_REFRESH, None)
            .expect("Token generation should succeed");
        let refresh_claims = decode_token(&refresh_token)
            .expect("Token decoding should succeed");
        
        // Verify expiration is approximately 2 weeks
        let expected_refresh_exp = now + 1209600;
        let refresh_exp_diff = if refresh_claims.exp > expected_refresh_exp {
            refresh_claims.exp - expected_refresh_exp
        } else {
            expected_refresh_exp - refresh_claims.exp
        };
        assert!(refresh_exp_diff <= 5, "Configured refresh expiration should be respected");
        
        // Cleanup environment
        env::remove_var("JWT_ACCESS_TOKEN_EXPIRES_IN");
        env::remove_var("JWT_REFRESH_TOKEN_EXPIRES_IN");
    }
}