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

use crate::metricss::jwt_metrics::{generate, revoke, validate};
use crate::utils::error_new::{AuthServiceError, JwtError};
use crate::utils::log_new::Log;
use crate::utils::telemetry::{business_operation_span, SpanExt};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::Client as RedisClient;
use serde::{Deserialize, Serialize};
use std::env;
use tracing::Instrument;
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
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Default token expiration times in seconds when not configured via environment.
const DEFAULT_ACCESS_TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour
const DEFAULT_REFRESH_TOKEN_EXPIRY_SECS: i64 = 604800; // 7 days

/// Clock skew tolerance in seconds for distributed systems.
const LEEWAY_SECONDS: u64 = 5;

/// Minimum recommended JWT secret length for security.
const MIN_SECRET_LENGTH: usize = 32;

/// Environment variable name for JWT secret
const JWT_SECRET_ENV: &str = "JWT_SECRET";

/// Environment variable for access token expiry
const JWT_ACCESS_EXPIRY_ENV: &str = "JWT_ACCESS_TOKEN_EXPIRES_IN";

/// Environment variable for refresh token expiry
const JWT_REFRESH_EXPIRY_ENV: &str = "JWT_REFRESH_TOKEN_EXPIRES_IN";

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
fn get_jwt_secret() -> Result<String, AuthServiceError> {
    // Create span for JWT secret retrieval
    let span = business_operation_span("get_jwt_secret");

    // Use the span to wrap the secret retrieval logic
    span.in_scope(|| match env::var(JWT_SECRET_ENV) {
        Ok(secret) => {
            let trimmed_secret = secret.trim();

            if trimmed_secret.is_empty() {
                Log::event(
                    "ERROR",
                    "JWT Configuration",
                    "JWT secret is empty or contains only whitespace",
                    "failure",
                    "get_jwt_secret",
                );
                span.record("result", &"failure");
                span.record("failure_reason", &"empty_secret");
                return Err(AuthServiceError::Jwt(JwtError::Configuration {
                    message: "JWT secret cannot be empty".to_string(),
                    span: SpanTrace::capture(),
                }));
            }

            if trimmed_secret.len() < MIN_SECRET_LENGTH {
                Log::event(
                    "ERROR",
                    "JWT Configuration",
                    &format!(
                        "JWT secret is too short ({} chars), minimum {} required",
                        trimmed_secret.len(),
                        MIN_SECRET_LENGTH
                    ),
                    "failure",
                    "get_jwt_secret",
                );
                span.record("result", &"failure");
                span.record("failure_reason", &"weak_secret");
                span.record("secret_length", &trimmed_secret.len());
                span.record("min_required_length", &MIN_SECRET_LENGTH);
                return Err(AuthServiceError::Jwt(JwtError::Configuration {
                    message: format!(
                        "JWT secret must be at least {} characters for security",
                        MIN_SECRET_LENGTH
                    ),
                    span: SpanTrace::capture(),
                }));
            }

            span.record("result", &"success");
            span.record("secret_length", &trimmed_secret.len());
            Ok(trimmed_secret.to_string())
        }
        Err(e) => {
            Log::event(
                "ERROR",
                "JWT Configuration",
                &format!("JWT_SECRET environment variable not found: {}", e),
                "failure",
                "get_jwt_secret",
            );
            span.record("result", &"failure");
            span.record("failure_reason", &"missing_env_var");
            span.record_error(&e);
            Err(AuthServiceError::Jwt(JwtError::Configuration {
                message: "JWT_SECRET environment variable is required".to_string(),
                span: SpanTrace::capture(),
            }))
        }
    })
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
///
/// # Example
///
/// ```
/// use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
/// use chrono::Duration;
///
/// let token = generate_token(
///     "user123",
///     TOKEN_TYPE_ACCESS,
///     Some(Duration::hours(1))
/// )?;
/// ```
pub fn generate_token(
    username: &str,
    token_type: &str,
    expires_in: Option<Duration>,
) -> Result<String, AuthServiceError> {
    // Create span for token generation
    let span = business_operation_span("generate_token");
    span.record("username", &username);
    span.record("token_type", &token_type);

    // Use timer API to measure operation time
    let _timer = generate::time();

    // Use the span to wrap the token generation logic
    span.in_scope(|| {
        // Calculate token expiration based on type and configuration
        let now = Utc::now();
        let expiration = match expires_in {
            Some(duration) => {
                span.record("custom_duration", &duration.num_seconds());
                now + duration
            }
            None => {
                let seconds = match token_type {
                    TOKEN_TYPE_ACCESS => env::var(JWT_ACCESS_EXPIRY_ENV)
                        .ok()
                        .and_then(|val| val.parse::<i64>().ok())
                        .unwrap_or(DEFAULT_ACCESS_TOKEN_EXPIRY_SECS),
                    TOKEN_TYPE_REFRESH => env::var(JWT_REFRESH_EXPIRY_ENV)
                        .ok()
                        .and_then(|val| val.parse::<i64>().ok())
                        .unwrap_or(DEFAULT_REFRESH_TOKEN_EXPIRY_SECS),
                    _ => {
                        Log::event(
                            "WARN",
                            "JWT Generation",
                            &format!("Unknown token type '{}'", token_type),
                            "warning",
                            "generate_token",
                        );
                        span.record("warning", &"unknown_token_type");
                        DEFAULT_ACCESS_TOKEN_EXPIRY_SECS
                    }
                };

                span.record("expiry_seconds", &seconds);
                now + Duration::seconds(seconds)
            }
        };

        // Record expiration timestamp in span
        span.record("expiry_timestamp", &(expiration.timestamp() as usize));

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
        span.record("algorithm", &"HS256");

        // Retrieve signing secret with security validation
        match get_jwt_secret() {
            Ok(secret) => {
                // Generate and sign the JWT token
                encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
                    .map_err(|e| {
                        Log::event(
                            "ERROR",
                            "JWT Generation",
                            &format!("Token encoding failed: {}", e),
                            "failure",
                            "generate_token",
                        );
                        generate::record_failure();
                        span.record("result", &"failure");
                        span.record("failure_reason", &"encoding_failed");
                        span.record_error(&e);

                        AuthServiceError::Jwt(JwtError::Internal {
                            message: "Failed to encode JWT token".to_string(),
                            span: SpanTrace::capture(),
                        })
                    })
                    .map(|token| {
                        generate::record_success();
                        span.record("result", &"success");
                        span.record("token_length", &token.len());
                        token
                    })
            }
            Err(e) => {
                generate::record_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"secret_retrieval_failed");
                Err(e)
            }
        }
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
///
/// # Example
///
/// ```
/// use crate::utils::jwt::decode_token;
///
/// match decode_token(&token_string) {
///     Ok(claims) => println!("Token belongs to user: {}", claims.sub),
///     Err(e) => println!("Token validation failed: {:?}", e),
/// }
/// ```
pub fn decode_token(token: &str) -> Result<TokenClaims, AuthServiceError> {
    // Create span for token decoding
    let span = business_operation_span("decode_token");
    span.record("token_length", &token.len());

    // Use timer API to measure operation time
    let _timer = validate::time();

    // Use the span to wrap the token decoding logic
    span.in_scope(|| {
        // Retrieve verification secret
        match get_jwt_secret() {
            Ok(secret) => {
                // Configure comprehensive validation rules
                let mut validation = Validation::new(Algorithm::HS256);
                validation.validate_exp = true;
                validation.leeway = LEEWAY_SECONDS;
                validation.set_required_spec_claims(&["exp", "iat", "sub"]);

                span.record("validate_expiration", &true);
                span.record("leeway_seconds", &LEEWAY_SECONDS);

                // Decode and validate token
                decode::<TokenClaims>(
                    token,
                    &DecodingKey::from_secret(secret.as_bytes()),
                    &validation,
                )
                .map_err(|e| {
                    match e.kind() {
                        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                            validate::record_expired();
                            span.record("result", &"failure");
                            span.record("failure_reason", &"expired");
                        }
                        jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                            validate::record_invalid_signature();
                            span.record("result", &"failure");
                            span.record("failure_reason", &"invalid_signature");
                        }
                        jsonwebtoken::errors::ErrorKind::InvalidToken
                        | jsonwebtoken::errors::ErrorKind::Json(_)
                        | jsonwebtoken::errors::ErrorKind::Base64(_) => {
                            validate::record_invalid_format();
                            span.record("result", &"failure");
                            span.record("failure_reason", &"invalid_format");
                        }
                        _ => {
                            validate::record_invalid_format();
                            span.record("result", &"failure");
                            span.record("failure_reason", &"other_error");
                        }
                    }

                    span.record_error(&e);
                    let jwt_error: JwtError = e.into();
                    AuthServiceError::Jwt(jwt_error)
                })
                .map(|data| {
                    validate::record_success();
                    span.record("result", &"success");
                    span.record("user.id", &data.claims.sub);
                    span.record("token_type", &data.claims.token_type);
                    data.claims
                })
            }
            Err(e) => {
                validate::record_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"secret_retrieval_failed");
                Err(e)
            }
        }
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
///
/// # Example
///
/// ```
/// use crate::utils::jwt::validate_token;
///
/// async fn check_auth(token: &str, redis: &redis::Client) -> bool {
///     match validate_token(token, redis).await {
///         Ok(claims) => true, // Token is valid
///         Err(_) => false,    // Token is invalid or revoked
///     }
/// }
/// ```
pub async fn validate_token(
    token: &str,
    redis_client: &RedisClient,
) -> Result<TokenClaims, AuthServiceError> {
    // Create span for token validation
    let span = business_operation_span("validate_token");
    span.record("token_length", &token.len());

    // Clone span before moving it into async operation
    let span_clone = span.clone();

    // Use timer API to measure operation time
    let _timer = validate::time();

    // Wrap the token validation in the span
    async move {
        // First decode the token
        let claims = match decode_token(token) {
            Ok(claims) => {
                // Record user info in span
                span.record("user.id", &claims.sub);
                span.record("token_type", &claims.token_type);
                claims
            }
            Err(e) => {
                span.record("result", &"failure");
                span.record("failure_reason", &"decode_failed");
                return Err(e);
            }
        };

        // Check revocation status
        match crate::config::redis::is_token_blocked(redis_client, token).await {
            Ok(is_blocked) => {
                span.record("revocation_check.success", &true);
                span.record("token_revoked", &is_blocked);

                if is_blocked {
                    validate::record_revoked();
                    span.record("result", &"failure");
                    span.record("failure_reason", &"revoked");
                    return Err(AuthServiceError::Jwt(JwtError::Revoked {
                        span: SpanTrace::capture(),
                    }));
                }
            }
            Err(e) => {
                validate::record_redis_failure();
                span.record("revocation_check.success", &false);
                span.record_error(&e);
                // Continue with fail-open policy
            }
        }

        // Additional security validations beyond basic decoding
        let now = Utc::now().timestamp() as usize;
        span.record("current_time", &now);
        span.record("token_exp", &claims.exp);
        span.record("token_iat", &claims.iat);

        // Double-check expiration (decoder should have caught this, but be defensive)
        if claims.exp <= now {
            validate::record_expired();
            span.record("result", &"failure");
            span.record("failure_reason", &"expired");

            return Err(AuthServiceError::Jwt(JwtError::Expired {
                span: SpanTrace::capture(),
            }));
        }

        // Check for tokens issued in the future (clock skew or tampering)
        if claims.iat > now + 60 {
            // Allow up to 1 minute of clock skew
            Log::event(
                "WARN",
                "JWT Validation",
                &format!(
                    "Token for {} has future issue time (iat: {}, now: {}) - possible tampering",
                    claims.sub, claims.iat, now
                ),
                "security_alert",
                "validate_token",
            );
            validate::record_invalid_iat();
            span.record("result", &"failure");
            span.record("failure_reason", &"future_iat");
            span.record("clock_skew_seconds", &(claims.iat as i64 - now as i64));

            return Err(AuthServiceError::Jwt(JwtError::InvalidIat {
                span: SpanTrace::capture(),
            }));
        }

        validate::record_success();
        span.record("result", &"success");
        Ok(claims)
    }
    .instrument(span_clone)
    .await
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
///
/// # Example
///
/// ```
/// use crate::utils::jwt::revoke_token;
///
/// async fn logout(token: &str, redis: &redis::Client) -> Result<(), AuthServiceError> {
///     // Invalidate the token
///     revoke_token(token, redis).await?;
///     Ok(())
/// }
/// ```
pub async fn revoke_token(token: &str, redis_client: &RedisClient) -> Result<(), AuthServiceError> {
    // Create span for token revocation
    let span = business_operation_span("revoke_token");
    span.record("token_length", &token.len());

    // Clone span before moving it into async operation
    let span_clone = span.clone();

    // Use timer API to measure operation time
    let _timer = revoke::time();

    // Wrap the token revocation in the span
    async move {
        let claims = match decode_token(token) {
            Ok(claims) => {
                // Record user info in span
                span.record("user.id", &claims.sub);
                span.record("token_type", &claims.token_type);
                claims
            }
            Err(AuthServiceError::Jwt(jwt_error)) => {
                match jwt_error {
                    JwtError::Expired { .. } => {
                        // For expired tokens, revocation is no-op but still success
                        span.record("result", &"success");
                        span.record("reason", &"already_expired");
                        revoke::record_success();
                        return Ok(());
                    }
                    _ => {
                        // Invalid tokens also no-op but still success
                        span.record("result", &"success");
                        span.record("reason", &"invalid_token");
                        revoke::record_success();
                        return Ok(());
                    }
                }
            }
            Err(other_error) => {
                span.record("result", &"failure");
                span.record("failure_reason", &"decode_failed");
                revoke::record_failure();
                return Err(other_error);
            }
        };

        // Check if already expired
        let now = Utc::now().timestamp() as usize;
        span.record("current_time", &now);
        span.record("token_exp", &claims.exp);

        if claims.exp <= now {
            span.record("result", &"success");
            span.record("reason", &"already_expired");
            revoke::record_success(); // expired = success/no-op
            return Ok(());
        }

        // Calculate TTL for Redis
        let ttl = claims.exp - now;
        span.record("ttl_seconds", &ttl);

        // Revoke in Redis
        match crate::config::redis::block_token(redis_client, token, ttl).await {
            Ok(_) => {
                Log::event(
                    "INFO",
                    "JWT Revocation",
                    &format!("Successfully revoked token for user: {}", claims.sub),
                    "success",
                    "revoke_token",
                );
                revoke::record_success();
                span.record("result", &"success");
                span.record("reason", &"revoked");
                Ok(())
            }
            Err(cache_error) => {
                Log::event(
                    "ERROR",
                    "JWT Revocation",
                    &format!("Failed to revoke token for {}: {}", claims.sub, cache_error),
                    "failure",
                    "revoke_token",
                );
                revoke::record_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"redis_error");
                span.record_error(&cache_error);

                Err(AuthServiceError::Jwt(JwtError::Internal {
                    message: format!("Failed to revoke token: {}", cache_error),
                    span: SpanTrace::capture(),
                }))
            }
        }
    }
    .instrument(span_clone)
    .await
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::env;

    /// Sets up test environment with a secure test JWT secret.
    fn setup_test_environment() {
        env::set_var(
            JWT_SECRET_ENV,
            "test-secret-key-minimum-32-characters-for-security-compliance",
        );
    }

    /// Creates a Redis client for integration testing.
    ///
    /// This function creates a Redis client configured for testing purposes.
    /// It expects Redis to be running on the default local port.
    ///
    /// # Returns
    ///
    /// A configured Redis client ready for testing
    ///
    /// # Panics
    ///
    /// If Redis connection cannot be established on localhost:6379
    fn create_test_redis_client() -> RedisClient {
        RedisClient::open("redis://127.0.0.1:6379/")
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
        let claims = decode_token(&token).expect("Token decoding should succeed");

        // Verify claim contents
        assert_eq!(claims.sub, username, "Subject should match input username");
        assert_eq!(
            claims.token_type, token_type,
            "Token type should match input"
        );
        assert!(
            claims.jti.is_some(),
            "JWT ID should be present for revocation"
        );

        // Verify timing constraints
        let now = Utc::now().timestamp() as usize;
        assert!(
            claims.iat <= now,
            "Issue time should be in the past or present"
        );
        assert!(claims.exp > now, "Expiration should be in the future");

        // Verify custom expiration is approximately correct (within 5 seconds)
        let expected_exp = now + custom_duration.num_seconds() as usize;
        let exp_diff = if claims.exp > expected_exp {
            claims.exp - expected_exp
        } else {
            expected_exp - claims.exp
        };
        assert!(
            exp_diff <= 5,
            "Expiration should match custom duration within timing tolerance"
        );
    }

    #[test]
    fn test_token_generation_with_different_types() {
        setup_test_environment();

        let username = "multi_type_user";

        // Test access token generation
        let access_token = generate_token(username, TOKEN_TYPE_ACCESS, None)
            .expect("Access token generation should succeed");
        let access_claims =
            decode_token(&access_token).expect("Access token decoding should succeed");
        assert_eq!(access_claims.token_type, TOKEN_TYPE_ACCESS);

        // Test refresh token generation
        let refresh_token = generate_token(username, TOKEN_TYPE_REFRESH, None)
            .expect("Refresh token generation should succeed");
        let refresh_claims =
            decode_token(&refresh_token).expect("Refresh token decoding should succeed");
        assert_eq!(refresh_claims.token_type, TOKEN_TYPE_REFRESH);

        // Test custom token type
        let custom_token = generate_token(username, "custom_type", Some(Duration::minutes(30)))
            .expect("Custom token generation should succeed");
        let custom_claims =
            decode_token(&custom_token).expect("Custom token decoding should succeed");
        assert_eq!(custom_claims.token_type, "custom_type");

        // Verify all tokens have unique JTIs
        assert_ne!(
            access_claims.jti, refresh_claims.jti,
            "Tokens should have unique JTIs"
        );
        assert_ne!(
            access_claims.jti, custom_claims.jti,
            "Tokens should have unique JTIs"
        );
        assert_ne!(
            refresh_claims.jti, custom_claims.jti,
            "Tokens should have unique JTIs"
        );
    }

    #[test]
    fn test_token_generation_fails_without_secret() {
        // Remove JWT secret to test error handling
        env::remove_var(JWT_SECRET_ENV);

        let result = generate_token("user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)));
        assert!(
            result.is_err(),
            "Token generation should fail without JWT secret"
        );

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
        env::set_var(JWT_SECRET_ENV, "short"); // Only 5 characters

        let result = generate_token("user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)));
        assert!(
            result.is_err(),
            "Token generation should fail with weak secret"
        );

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
    // TOKEN VALIDATION TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_validate_token_with_redis() {
        setup_test_environment();
        let redis_client = create_test_redis_client();

        let username = "redis_test_user";
        let token = generate_token(username, TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("Token generation should succeed");

        // Token should be valid initially
        let claims = validate_token(&token, &redis_client)
            .await
            .expect("Token validation should succeed");
        assert_eq!(claims.sub, username);

        // Revoke token
        revoke_token(&token, &redis_client)
            .await
            .expect("Token revocation should succeed");

        // Token should now be invalid
        let result = validate_token(&token, &redis_client).await;
        assert!(result.is_err(), "Revoked token should be invalid");

        // Verify correct error type
        match result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::Revoked { .. }) => {
                // Expected error type
            }
            other => panic!("Expected revoked token error, got: {:?}", other),
        }
    }

    #[test]
    fn test_decode_token_with_tampered_signature() {
        setup_test_environment();

        let username = "security_test_user";
        let token = generate_token(username, TOKEN_TYPE_ACCESS, None)
            .expect("Token generation should succeed");

        // Tamper with the signature (last part after the second dot)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have three parts");

        let tampered_token = format!("{}.{}.invalid_signature", parts[0], parts[1]);

        // Decoding should fail with invalid signature
        let result = decode_token(&tampered_token);
        assert!(result.is_err(), "Tampered token should be rejected");

        // Verify correct error type
        match result.unwrap_err() {
            AuthServiceError::Jwt(JwtError::InvalidSignature { .. }) => {
                // Expected error type
            }
            other => panic!("Expected invalid signature error, got: {:?}", other),
        }
    }
}
