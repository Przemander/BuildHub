//! # Redis Configuration and Cache Management
//!
//! This module provides production-ready Redis infrastructure for the BuildHub
//! authentication service. It handles connection management, token operations,
//! and comprehensive caching strategies with a focus on security, performance,
//! and observability.
//!
//! ## Features
//!
//! - **Secure Connection Management**: URL masking and credential protection
//! - **JWT Token Blacklisting**: Secure token invalidation for logout/security
//! - **Account Activation Flow**: Time-limited activation codes with auto-cleanup
//! - **Password Reset Tokens**: Secure, expiring reset token management
//! - **Health Monitoring**: Built-in connection health checks and diagnostics
//! - **Comprehensive Observability**: Detailed metrics and structured logging
//! - **Error Resilience**: Structured error handling with context preservation
//! - **Production Optimization**: Configurable TTLs and connection pooling
//!
//! ## Architecture
//!
//! The module follows a layered approach:
//! - **Connection Layer**: Redis client initialization and health checking
//! - **Security Layer**: JWT token blacklisting and validation
//! - **Authentication Layer**: Activation codes and password reset tokens
//! - **Observability Layer**: Comprehensive metrics and logging
//!
//! ## Security Model
//!
//! All sensitive operations use time-limited storage with automatic expiration:
//! - **Activation Codes**: 24-hour expiration for account activation
//! - **Reset Tokens**: 30-minute expiration for password reset security
//! - **Blocked Tokens**: Expiration matches JWT remaining lifetime
//!
//! ## Configuration
//!
//! Requires the `REDIS_URL` environment variable:
//! ```
//! REDIS_URL=redis://username:password@host:port/database
//! REDIS_URL=redis://localhost:6379  # Development
//! ```

use crate::utils::error_new::CacheError;
use crate::{
    metricss::redis_metrics::{
        // Core API
        set_redis_health, time_redis_operation, record_redis_operation,
        init_redis_metrics, sanitize_rate_limit_key, spawn_metrics_collector,
        // Constants
        operations, results, health, jwt, rate_limit, activation, reset,
    },
    log_debug, log_error, log_info, log_warn,
};
use redis::{AsyncCommands, Client};
use std::env;
use tracing_error::SpanTrace;

// =============================================================================
// TYPE DEFINITIONS AND CONSTANTS
// =============================================================================

/// Type alias for Redis async connection with comprehensive error handling.
///
/// This connection type provides async operations with automatic connection
/// management and error propagation to the application's error handling system.
pub type RedisConnection = redis::aio::Connection;

/// Environment variable name for Redis connection URL configuration.
///
/// This constant ensures consistent environment variable naming across
/// the application and prevents typos in configuration management.
const REDIS_URL_ENV: &str = "REDIS_URL";

/// Value stored in Redis to indicate a JWT token is blocked/invalidated.
///
/// Using a consistent marker value allows for efficient token validation
/// and provides clear semantics for token blacklist operations.
const TOKEN_BLOCKED_VALUE: &str = "blocked";

/// TTL (Time To Live) in seconds for activation codes stored in Redis.
///
/// 24-hour expiration provides a balance between user convenience and
/// security requirements for account activation workflows.
const ACTIVATION_CODE_TTL: u64 = 86_400; // 24 hours

/// TTL (Time To Live) in seconds for password reset tokens.
///
/// 30-minute expiration ensures tight security for password reset operations
/// while providing sufficient time for users to complete the reset process.
const PASSWORD_RESET_TTL: u64 = 1_800; // 30 minutes

// =============================================================================
// REDIS CLIENT INITIALIZATION AND HEALTH MANAGEMENT
// =============================================================================

/// Initializes the Redis client with production-ready configuration and security.
pub fn init_redis() -> Result<Client, CacheError> {
    // Initialize Redis metrics system first
    init_redis_metrics();
    
    let redis_url = env::var(REDIS_URL_ENV).map_err(|e| {
        log_error!(
            "Redis Configuration", 
            &format!("Missing {} environment variable: {}", REDIS_URL_ENV, e), 
            "initialization_error"
        );
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    log_info!(
        "Redis Configuration", 
        &format!("Initializing Redis client with URL: {}", mask_redis_url(&redis_url)), 
        "initialization_attempt"
    );

    let client = Client::open(redis_url).map_err(|e| {
        log_error!(
            "Redis Configuration", 
            &format!("Invalid Redis URL configuration: {}", e), 
            "initialization_error"
        );
        // Record client initialization failure
        record_redis_operation(operations::CLIENT_INIT, results::FAILURE);
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    log_info!("Redis Configuration", "Redis client initialized successfully", "initialization_success");
    // Record client initialization success
    record_redis_operation(operations::CLIENT_INIT, results::SUCCESS);
    
    Ok(client)
}

/// Starts background Redis metrics collection for observability
#[allow(dead_code)]
pub fn start_redis_metrics_collection(client: Client) {
    spawn_metrics_collector(client);
}

/// Performs comprehensive Redis connection health check with detailed diagnostics.
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::HEALTH_CHECK);
    
    let mut connection = match redis_client.get_async_connection().await {
        Ok(conn) => {
            log_debug!("Redis Health", "Successfully acquired connection for health check", "connection_success");
            conn
        }
        Err(e) => {
            log_error!(
                "Redis Health", 
                &format!("Failed to acquire connection for health check: {}", e), 
                "health_check_connection_failure"
            );
            // Record connection failure
            health::record_connection_failure();
            set_redis_health(false);
            return false;
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut connection).await {
        Ok(response) if response == "PONG" => {
            log_info!("Redis Health", "Health check successful - Redis responding correctly", "health_success");
            // Record health check success
            health::record_success();
            set_redis_health(true);
            true
        }
        Ok(unexpected_response) => {
            log_error!(
                "Redis Health", 
                &format!("Unexpected PING response: expected 'PONG', got '{}'", unexpected_response), 
                "health_check_unexpected_response"
            );
            // Record unexpected response
            health::record_unexpected_response();
            set_redis_health(false);
            false
        }
        Err(e) => {
            log_error!(
                "Redis Health", 
                &format!("PING command failed: {}", e), 
                "health_check_command_failure"
            );
            // Record command failure
            health::record_command_failure();
            set_redis_health(false);
            false
        }
    }
}

/// Acquires a Redis connection with comprehensive error handling and instrumentation.
pub async fn get_redis_connection(client: &Client) -> Result<RedisConnection, CacheError> {
    // Use timer API to measure connection acquisition time
    let _timer = time_redis_operation(operations::CONNECTION_ACQUISITION);
    
    client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Redis Connection", 
            &format!("Failed to acquire Redis connection: {}", e), 
            "connection_acquisition_error"
        );
        // Record connection acquisition failure
        record_redis_operation(operations::CONNECTION_ACQUISITION, results::FAILURE);
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })
}

// =============================================================================
// JWT TOKEN BLACKLISTING AND SECURITY OPERATIONS
// =============================================================================

/// Blocks a JWT token by storing it in Redis with automatic expiration.
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), CacheError> {
    log_debug!(
        "Token Security", 
        &format!("Blocking JWT token (length: {}, expiration: {}s)", token.len(), exp), 
        "security_operation_attempt"
    );
    
    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::BLOCK_TOKEN);
    let mut connection = get_redis_connection(redis).await?;
    
    connection.set_ex::<&str, &str, ()>(token, TOKEN_BLOCKED_VALUE, exp)
        .await
        .map_err(|e| {
            log_error!(
                "Token Security", 
                &format!("Failed to block token in Redis: {}", e), 
                "security_operation_failure"
            );
            // Record block token failure
            jwt::record_block_failure();
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

    log_info!(
        "Token Security", 
        &format!("JWT token successfully blocked (expires in {}s)", exp), 
        "security_operation_success"
    );
    // Record block token success
    jwt::record_block_success();
    
    Ok(())
}

/// Checks if a JWT token is blocked with high-performance validation.
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, CacheError> {
    log_debug!(
        "Token Validation", 
        &format!("Checking blacklist status for token (length: {})", token.len()), 
        "security_check_attempt"
    );
    
    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::TOKEN_VALIDATION);
    let mut connection = get_redis_connection(redis).await?;
    
    let is_blocked: bool = connection.exists(token).await.map_err(|e| {
        log_error!(
            "Token Validation", 
            &format!("Token blacklist check failed: {}", e), 
            "security_check_failure"
        );
        // Record token validation failure
        jwt::record_validation_failure();
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    let status = if is_blocked { "blocked" } else { "valid" };
    log_debug!(
        "Token Validation", 
        &format!("Token blacklist check complete: {}", status), 
        "security_check_success"
    );
    
    // Record token validation result
    if is_blocked {
        jwt::record_validation_blocked();
    } else {
        jwt::record_validation_valid();
    }
    
    Ok(is_blocked)
}

// =============================================================================
// ACCOUNT ACTIVATION CODE MANAGEMENT
// =============================================================================

/// Stores an account activation code with secure, time-limited expiration.
pub async fn store_activation_code(
    redis_client: &Client,
    email: &str,
    code: &str,
) -> Result<(), CacheError> {
    log_debug!(
        "Account Activation", 
        &format!("Storing activation code for {} (expires in {}h)", email, ACTIVATION_CODE_TTL / 3600), 
        "activation_storage_attempt"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::ACTIVATION_STORE);
    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for activation code
    let key = format!("activation:code:{}", code);
    
    connection.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_TTL as usize)
        .await
        .map_err(|e| {
            log_error!(
                "Account Activation", 
                &format!("Failed to store activation code in Redis: {}", e), 
                "activation_storage_failure"
            );
            // Record activation storage failure - using helper for consistency
            activation::record_store_failure();
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

    log_info!(
        "Account Activation", 
        &format!("Activation code for {} stored successfully (24h expiration)", email), 
        "activation_storage_success"
    );
    // Record activation storage success
    activation::record_store_success();
    
    Ok(())
}

/// Verifies and consumes an activation code with atomic single-use semantics.
pub async fn verify_activation_code(
    redis_client: &Client,
    code: &str,
) -> Result<String, CacheError> {
    log_debug!(
        "Account Activation", 
        &format!("Verifying activation code: {}", code), 
        "activation_verification_attempt"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::ACTIVATION_VERIFY);
    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for activation code lookup
    let key = format!("activation:code:{}", code);
    
    // Retrieve email associated with activation code
    let email: Option<String> = connection.get(&key).await.map_err(|e| {
        log_error!(
            "Account Activation", 
            &format!("Failed to retrieve activation code from Redis: {}", e), 
            "activation_verification_failure"
        );
        // Record verification failure - using helper for consistency
        activation::record_verify_failure();
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    match email {
        Some(email) => {
            log_debug!(
                "Account Activation", 
                &format!("Valid activation code found for {}", email), 
                "activation_verification_success"
            );
            
            // Delete the code immediately to ensure single-use semantics
            // Use timer API to measure cleanup operation time
            let _cleanup_timer = time_redis_operation(operations::ACTIVATION_CLEANUP);
            let _: () = connection.del(&key).await.map_err(|e| {
                log_error!(
                    "Account Activation", 
                    &format!("Failed to delete used activation code: {}", e), 
                    "activation_cleanup_failure"
                );
                // Record cleanup failure - using helper for consistency
                activation::record_cleanup_failure();
                CacheError::Operation {
                    source: Box::new(e),
                    span: SpanTrace::capture(),
                }
            })?;
            
            log_info!(
                "Account Activation", 
                &format!("Account for {} successfully activated and code consumed", email), 
                "activation_complete"
            );
            // Record verification and cleanup success
            activation::record_verify_success();
            activation::record_cleanup_success();
            
            Ok(email)
        }
        None => {
            log_warn!(
                "Account Activation", 
                &format!("Invalid or expired activation code attempted: {}", code), 
                "activation_verification_invalid"
            );
            // Record not found result
            activation::record_verify_not_found();
            
            Err(CacheError::KeyNotFound {
                key: format!("activation:code:{}", code),
                span: SpanTrace::capture(),
            })
        }
    }
}

// =============================================================================
// PASSWORD RESET TOKEN MANAGEMENT
// =============================================================================

/// Stores a password reset token with secure, time-limited expiration.
pub async fn store_password_reset_token(
    redis_client: &Client,
    email: &str,
    token: &str,
) -> Result<(), CacheError> {
    log_debug!(
        "Password Reset", 
        &format!("Storing password reset token for {} (expires in {}m)", email, PASSWORD_RESET_TTL / 60), 
        "reset_storage_attempt"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RESET_STORE);
    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for password reset token
    let key = format!("password_reset:token:{}", token);
    
    connection.set_ex::<_, _, ()>(key, email, PASSWORD_RESET_TTL as usize)
        .await
        .map_err(|e| {
            log_error!(
                "Password Reset", 
                &format!("Failed to store reset token in Redis: {}", e), 
                "reset_storage_failure"
            );
            // Record storage failure - using helper for consistency
            reset::record_store_failure();
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

    log_info!(
        "Password Reset", 
        &format!("Reset token for {} stored successfully (30m expiration)", email), 
        "reset_storage_success"
    );
    // Record storage success
    reset::record_store_success();
    
    Ok(())
}

/// Verifies a password reset token without consuming it for validation.
pub async fn verify_reset_token(
    redis_client: &Client,
    token: &str,
) -> Result<String, CacheError> {
    log_debug!(
        "Password Reset", 
        &format!("Verifying reset token: {}", token), 
        "reset_verification_attempt"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RESET_VERIFY);
    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for reset token lookup
    let key = format!("password_reset:token:{}", token);
    
    let email: Option<String> = connection.get(&key).await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Failed to retrieve reset token from Redis: {}", e), 
            "reset_verification_failure"
        );
        // Record verification failure - using helper for consistency
        reset::record_verify_failure();
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;
    
    match email {
        Some(email) => {
            log_debug!(
                "Password Reset", 
                &format!("Valid reset token found for {}", email), 
                "reset_verification_success"
            );
            // Record verification success
            reset::record_verify_success();
            
            Ok(email)
        }
        None => {
            log_warn!(
                "Password Reset", 
                &format!("Invalid or expired reset token attempted: {}", token), 
                "reset_verification_invalid"
            );
            // Record not found result
            reset::record_verify_not_found();
            
            Err(CacheError::KeyNotFound {
                key: format!("password_reset:token:{}", token),
                span: SpanTrace::capture(),
            })
        }
    }
}

/// Invalidates a password reset token after successful password update.
pub async fn invalidate_reset_token(
    redis_client: &Client,
    token: &str,
) -> Result<(), CacheError> {
    log_debug!(
        "Password Reset", 
        &format!("Invalidating used reset token: {}", token), 
        "reset_cleanup_attempt"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RESET_CLEANUP);
    let mut connection = get_redis_connection(redis_client).await?;

    // Generate namespaced Redis key for reset token cleanup
    let key = format!("password_reset:token:{}", token);
    
    let _: () = connection.del(&key).await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Failed to delete used reset token: {}", e), 
            "reset_cleanup_failure"
        );
        // Record cleanup failure - using helper for consistency
        reset::record_cleanup_failure();
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;
    
    log_info!(
        "Password Reset", 
        &format!("Reset token {} successfully invalidated", token), 
        "reset_cleanup_success"
    );
    // Record cleanup success
    reset::record_cleanup_success();
    
    Ok(())
}

// =============================================================================
// RATE LIMITING OPERATIONS
// =============================================================================

/// Performs atomic rate limit check and increment with sliding window implementation.
pub async fn check_and_increment_rate_limit(
    redis_client: &Client,
    key: &str,
    max_attempts: u32,
    window_seconds: usize,
) -> Result<bool, CacheError> {
    // Sanitize the key to prevent cardinality explosion
    let sanitized_key = sanitize_rate_limit_key(key);
    
    log_debug!(
        "Rate Limiting",
        &format!("Checking rate limit for key: {} (max: {}, window: {}s)", 
                sanitized_key, max_attempts, window_seconds),
        "rate_limit_check_attempt"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RATE_LIMIT_CHECK);
    let mut connection = get_redis_connection(redis_client).await?;

    // Atomically increment the counter
    let current_count: u32 = connection.incr(&sanitized_key, 1).await.map_err(|e| {
        log_error!(
            "Rate Limiting",
            &format!("Failed to increment rate limit counter for {}: {}", sanitized_key, e),
            "rate_limit_increment_failure"
        );
        // Record rate limit check failure
        rate_limit::record_failure();
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    // On first increment, set the expiration time for the sliding window
    if current_count == 1 {
        // Use timer API to measure expiration operation time
        let _expire_timer = time_redis_operation(operations::RATE_LIMIT_EXPIRE);
        let _: () = connection.expire(&sanitized_key, window_seconds).await.map_err(|e| {
            log_error!(
                "Rate Limiting",
                &format!("Failed to set expiration for rate limit key {}: {}", sanitized_key, e),
                "rate_limit_expiration_failure"
            );
            // Record rate limit expiration failure
            rate_limit::record_failure();
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;
        
        log_debug!(
            "Rate Limiting",
            &format!("Set expiration for new rate limit window: {} ({}s)", sanitized_key, window_seconds),
            "rate_limit_window_created"
        );
    }

    let within_limit = current_count <= max_attempts;
    let status = if within_limit { "allowed" } else { "blocked" };

    log_debug!(
        "Rate Limiting",
        &format!(
            "Rate limit check complete: {} - {}/{} attempts ({})",
            sanitized_key, current_count, max_attempts, status
        ),
        "rate_limit_check_complete"
    );

    // Record rate limit check result
    if within_limit {
        rate_limit::record_allowed();
    } else {
        rate_limit::record_blocked();
        
        log_warn!(
            "Rate Limiting",
            &format!(
                "Rate limit exceeded: {} - {}/{} attempts in window",
                sanitized_key, current_count, max_attempts
            ),
            "rate_limit_exceeded"
        );
    }

    Ok(within_limit)
}

// =============================================================================
// SECURITY AND UTILITY FUNCTIONS
// =============================================================================

/// Masks sensitive information in Redis URLs for secure logging and monitoring.
fn mask_redis_url(url: &str) -> String {
    // Handle URLs with potential credentials (redis://user:password@host:port)
    if let Some(at_position) = url.find('@') {
        if let Some(protocol_end) = url.find("://") {
            let protocol_end = protocol_end + 3; // Skip past "://"
            
            // Ensure @ comes after protocol and there's a credentials section
            if at_position > protocol_end {
                if let Some(password_start) = url[protocol_end..at_position].find(':') {
                    let password_start = protocol_end + password_start + 1;
                    
                    // Reconstruct URL with masked password
                    let masked_credentials = format!(
                        "{}{}{}",
                        &url[0..password_start], // protocol://username:
                        "****",                  // masked password
                        &url[at_position..]      // @host:port/database
                    );
                    
                    // Handle query parameters if present
                    if let Some(query_position) = masked_credentials.find('?') {
                        return format!("{}?[PARAMS_REDACTED]", &masked_credentials[0..query_position]);
                    }
                    
                    return masked_credentials;
                }
            }
        }
    }
    
    // Handle URLs without credentials but with query parameters
    if let Some(query_position) = url.find('?') {
        return format!("{}?[PARAMS_REDACTED]", &url[0..query_position]);
    }
    
    // Return URL unchanged if no sensitive information detected
    url.to_string()
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use redis::{Client, AsyncCommands};
    use std::env;
    use tokio;

    /// Creates a Redis client configured for a non-existent server for testing failure scenarios.
    fn create_unavailable_redis_client() -> Client {
        // Use a non-standard port to ensure connection failures
        Client::open("redis://127.0.0.1:63999/")
            .expect("Client creation should succeed even for invalid addresses")
    }
    
    /// Sets up test environment with proper Redis URL configuration.
    fn setup_test_environment() {
        env::set_var(REDIS_URL_ENV, "redis://127.0.0.1:6379/");
    }

    /// Creates a Redis client for integration testing.
    async fn create_test_redis_client() -> Client {
        Client::open("redis://127.0.0.1:6379/")
            .expect("Redis must be running on localhost:6379 for integration tests")
    }

    // =============================================================================
    // URL MASKING AND SECURITY TESTS
    // =============================================================================

    #[test]
    fn test_redis_url_masking_comprehensive() {
        // Test authenticated URL with password masking
        assert_eq!(
            mask_redis_url("redis://username:secretpassword@127.0.0.1:6379/0"),
            "redis://username:****@127.0.0.1:6379/0",
            "Passwords should be masked with asterisks"
        );
        
        // Test TLS authenticated URL
        assert_eq!(
            mask_redis_url("rediss://admin:admin123@secure.redis.com:6380/1"),
            "rediss://admin:****@secure.redis.com:6380/1",
            "TLS URLs should also mask passwords"
        );
        
        // Test URL without credentials (should remain unchanged)
        assert_eq!(
            mask_redis_url("redis://localhost:6379/0"),
            "redis://localhost:6379/0",
            "URLs without credentials should remain unchanged"
        );
        
        // Test URL with query parameters but no credentials
        assert_eq!(
            mask_redis_url("redis://localhost:6379/0?timeout=5000&retry=3"),
            "redis://localhost:6379/0?[PARAMS_REDACTED]",
            "Query parameters should be redacted for security"
        );
        
        // Test URL with both credentials and query parameters
        assert_eq!(
            mask_redis_url("redis://user:pass@host:6379/0?secret=value"),
            "redis://user:****@host:6379/0?[PARAMS_REDACTED]",
            "Both passwords and query parameters should be masked"
        );
        
        // Test edge case: empty string
        assert_eq!(
            mask_redis_url(""),
            "",
            "Empty string should be handled gracefully"
        );
        
        // Test edge case: malformed URL
        assert_eq!(
            mask_redis_url("not-a-valid-url"),
            "not-a-valid-url",
            "Malformed URLs should be returned unchanged"
        );
    }

    // =============================================================================
    // REDIS INITIALIZATION TESTS
    // =============================================================================

    #[test]
    fn test_init_redis_requires_environment_variable() {
        // Remove environment variable to test error handling
        env::remove_var(REDIS_URL_ENV);
        
        let result = init_redis();
        assert!(result.is_err(), "init_redis should fail without REDIS_URL environment variable");
        
        // Verify error type is correct
        match result.unwrap_err() {
            CacheError::Connection { source: _, span: _ } => {
                // Expected error type - test passes
            }
            other => panic!("Expected CacheError::Connection, got: {:?}", other),
        }
    }

    #[test]
    fn test_init_redis_validates_url_format() {
        // Set invalid Redis URL to test validation
        env::set_var(REDIS_URL_ENV, "invalid-url-format");
        
        let result = init_redis();
        assert!(result.is_err(), "init_redis should fail with invalid URL format");
        
        // Verify error type is correct
        match result.unwrap_err() {
            CacheError::Connection { source: _, span: _ } => {
                // Expected error type - test passes
            }
            other => panic!("Expected CacheError::Connection, got: {:?}", other),
        }
    }

    #[test]
    #[ignore] // Requires running Redis instance
    fn test_init_redis_success_with_valid_configuration() {
        setup_test_environment();
        
        let result = init_redis();
        assert!(result.is_ok(), "init_redis should succeed with valid REDIS_URL");
    }

    // =============================================================================
    // REDIS HEALTH CHECK TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_redis_health_check_handles_connection_failure() {
        let unavailable_client = create_unavailable_redis_client();
        
        let is_healthy = check_redis_connection(&unavailable_client).await;
        assert!(!is_healthy, "Health check should return false for unavailable Redis");
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_redis_health_check_success_with_available_redis() {
        setup_test_environment();
        let client = init_redis().expect("Redis client initialization should succeed");
        
        let is_healthy = check_redis_connection(&client).await;
        assert!(is_healthy, "Health check should return true for available Redis");
    }

    // =============================================================================
    // CONNECTION ACQUISITION TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_get_redis_connection_handles_failure_appropriately() {
        let unavailable_client = create_unavailable_redis_client();
        
        let result = get_redis_connection(&unavailable_client).await;
        assert!(result.is_err(), "Connection acquisition should fail for unavailable Redis");
        
        match result {
            Err(CacheError::Connection { source: _, span: _ }) => {
                // Expected error type - test passes
            }
            Err(other) => panic!("Expected CacheError::Connection, got different error type: {:?}", other),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_get_redis_connection_success_with_available_redis() {
        let client = create_test_redis_client().await;
        
        let result = get_redis_connection(&client).await;
        assert!(result.is_ok(), "Connection acquisition should succeed with available Redis");
    }

    // =============================================================================
    // RATE LIMITING TESTS
    // =============================================================================

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_rate_limiting_workflow_with_sanitization() {
        let client = create_test_redis_client().await;
        
        // Test with a very long key that will be sanitized
        let long_key = format!("test:rate_limit:{}", "x".repeat(200));
        
        // First request should be allowed
        let first_result = check_and_increment_rate_limit(&client, &long_key, 2, 60).await
            .expect("Rate limit check should succeed");
        assert!(first_result, "First request should be allowed");
        
        // Second request should be allowed
        let second_result = check_and_increment_rate_limit(&client, &long_key, 2, 60).await
            .expect("Rate limit check should succeed");
        assert!(second_result, "Second request should be allowed");
        
        // Third request should be blocked
        let third_result = check_and_increment_rate_limit(&client, &long_key, 2, 60).await
            .expect("Rate limit check should succeed");
        assert!(!third_result, "Third request should be blocked");
        
        // Cleanup: Remove test key (using sanitized version)
        let sanitized_key = sanitize_rate_limit_key(&long_key);
        let mut connection = client.get_async_connection().await
            .expect("Connection acquisition should succeed");
        let _: () = connection.del(&sanitized_key).await
            .expect("Test cleanup should succeed");
    }

    // =============================================================================
    // INTEGRATION AND CONFIGURATION TESTS
    // =============================================================================

    #[test]
    fn test_redis_configuration_constants() {
        // Verify TTL constants are reasonable
        assert!(ACTIVATION_CODE_TTL > 0, "Activation code TTL must be positive");
        assert!(PASSWORD_RESET_TTL > 0, "Password reset TTL must be positive");
        
        // Verify security-appropriate TTL values
        assert!(
            ACTIVATION_CODE_TTL >= 3600, // At least 1 hour
            "Activation code TTL should provide reasonable user experience"
        );
        assert!(
            PASSWORD_RESET_TTL <= 3600, // At most 1 hour  
            "Password reset TTL should maintain security"
        );
        
        // Verify environment variable name
        assert_eq!(REDIS_URL_ENV, "REDIS_URL", "Environment variable name should be consistent");
        
        // Verify token blocked value
        assert!(!TOKEN_BLOCKED_VALUE.is_empty(), "Token blocked value should not be empty");
    }
}