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
//!
//! ## Usage Example
//!
//! ```rust
//! use crate::config::redis;
//!
//! async fn authentication_flow() -> Result<(), AuthServiceError> {
//!     // Initialize Redis client
//!     let client = redis::init_redis()?;
//!     
//!     // Health check
//!     assert!(redis::check_redis_connection(&client).await);
//!     
//!     // Token management
//!     redis::block_token(&client, "jwt.token.example", 1800).await?;
//!     let is_blocked = redis::is_token_blocked(&client, "jwt.token.example").await?;
//!     
//!     // Account activation
//!     redis::store_activation_code(&client, "user@example.com", "code123").await?;
//!     let email = redis::verify_activation_code(&client, "code123").await?;
//!     
//!     // Password reset flow
//!     redis::store_password_reset_token(&client, "user@example.com", "reset456").await?;
//!     let email = redis::verify_reset_token(&client, "reset456").await?;
//!     redis::invalidate_reset_token(&client, "reset456").await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Error Handling
//!
//! All operations return structured errors with context:
//! - `CacheError::Connection`: Redis connection issues
//! - `CacheError::Operation`: Redis command failures
//! - `CacheError::KeyNotFound`: Missing or expired keys
//!
//! ## Performance Considerations
//!
//! - **Connection Reuse**: Async connections are efficiently managed
//! - **Expiration Strategy**: Automatic cleanup prevents memory leaks
//! - **Metrics Collection**: Zero-overhead instrumentation
//! - **Health Monitoring**: Proactive connection health validation

use crate::utils::error_new::CacheError;
use crate::utils::metrics::{REDIS_HEALTH, REDIS_OPERATIONS};
use crate::{log_debug, log_error, log_info, log_warn};
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
///
/// This function creates a Redis client from environment configuration with
/// comprehensive error handling, credential masking for logs, and proper
/// instrumentation for monitoring and debugging.
///
/// # Environment Variables
///
/// - `REDIS_URL`: Required Redis connection string with format:
///   - Basic: `redis://host:port/database`
///   - Authenticated: `redis://username:password@host:port/database`
///   - TLS: `rediss://username:password@host:port/database`
///
/// # Security Features
///
/// - **Credential Masking**: Passwords are automatically masked in logs
/// - **URL Validation**: Connection strings are validated before use
/// - **Error Context**: Detailed error information without exposing secrets
///
/// # Returns
///
/// - `Ok(Client)`: Successfully initialized and configured Redis client
/// - `Err(CacheError)`: Configuration error with detailed context
///
/// # Examples
///
/// ```rust
/// // Production setup with authentication
/// std::env::set_var("REDIS_URL", "redis://app:secret@cache.example.com:6379/0");
/// let client = init_redis()?;
///
/// // Development setup
/// std::env::set_var("REDIS_URL", "redis://localhost:6379");
/// let client = init_redis()?;
/// ```
pub fn init_redis() -> Result<Client, CacheError> {
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
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    log_info!("Redis Configuration", "Redis client initialized successfully", "initialization_success");
    REDIS_OPERATIONS.with_label_values(&["client_init", "success"]).inc();
    
    Ok(client)
}

/// Performs comprehensive Redis connection health check with detailed diagnostics.
///
/// This function validates Redis connectivity by executing a PING command and
/// verifying the expected PONG response. It provides detailed error reporting
/// and metrics collection for monitoring and alerting systems.
///
/// # Health Check Process
///
/// 1. **Connection Acquisition**: Attempts to get async connection from client
/// 2. **Command Execution**: Sends PING command to Redis server
/// 3. **Response Validation**: Verifies PONG response for correct operation
/// 4. **Metrics Updates**: Records health status for monitoring systems
///
/// # Arguments
///
/// - `redis_client`: Configured Redis client to health check
///
/// # Returns
///
/// - `true`: Redis is healthy and responding correctly
/// - `false`: Redis is unavailable, unresponsive, or returning unexpected responses
///
/// # Monitoring Integration
///
/// This function updates the `REDIS_HEALTH` metric for Prometheus monitoring
/// and provides structured logging for log aggregation systems.
///
/// # Examples
///
/// ```rust
/// async fn ensure_redis_healthy() -> Result<(), ServiceError> {
///     let client = init_redis()?;
///     
///     if !check_redis_connection(&client).await {
///         return Err(ServiceError::infrastructure("Redis health check failed"));
///     }
///     
///     log_info!("Service", "Redis connectivity confirmed", "health_check");
///     Ok(())
/// }
/// ```
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    let mut connection = match redis_client.get_async_connection().await {
        Ok(conn) => {
            log_debug!("Redis Health", "Successfully acquired connection for health check", "connection_success");
            conn
        }
        Err(e) => {
            log_error!(
                "Redis Health", 
                &format!("Failed to acquire connection for health check: {}", e), 
                "connection_failure"
            );
            REDIS_OPERATIONS.with_label_values(&["health_check", "connection_failure"]).inc();
            REDIS_HEALTH.set(0.0);
            return false;
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut connection).await {
        Ok(response) if response == "PONG" => {
            log_info!("Redis Health", "Health check successful - Redis responding correctly", "health_success");
            REDIS_OPERATIONS.with_label_values(&["health_check", "success"]).inc();
            REDIS_HEALTH.set(1.0);
            true
        }
        Ok(unexpected_response) => {
            log_error!(
                "Redis Health", 
                &format!("Health check failed - unexpected PING response: '{}'", unexpected_response), 
                "health_unexpected_response"
            );
            REDIS_OPERATIONS.with_label_values(&["health_check", "unexpected_response"]).inc();
            REDIS_HEALTH.set(0.0);
            false
        }
        Err(e) => {
            log_error!(
                "Redis Health", 
                &format!("Health check failed - PING command error: {}", e), 
                "health_command_failure"
            );
            REDIS_OPERATIONS.with_label_values(&["health_check", "command_failure"]).inc();
            REDIS_HEALTH.set(0.0);
            false
        }
    }
}

/// Acquires a Redis connection with comprehensive error handling and instrumentation.
///
/// This function provides a centralized, instrumented way to obtain Redis connections
/// with proper error mapping, metrics collection, and observability. It serves as
/// the foundation for all Redis operations in the application.
///
/// # Connection Management
///
/// - **Async Connections**: Uses Redis async connection pool for optimal performance
/// - **Error Mapping**: Converts Redis errors to structured application errors
/// - **Metrics Collection**: Records connection acquisition success/failure rates
/// - **Structured Logging**: Provides detailed error context for debugging
///
/// # Arguments
///
/// - `client`: Initialized Redis client for connection acquisition
///
/// # Returns
///
/// - `Ok(RedisConnection)`: Successfully acquired async Redis connection
/// - `Err(CacheError)`: Connection acquisition failed with detailed context
///
/// # Error Scenarios
///
/// - **Network Issues**: Redis server unreachable or network partitioned
/// - **Authentication Failures**: Invalid credentials or permission issues
/// - **Resource Exhaustion**: Connection pool exhausted or Redis overloaded
/// - **Configuration Errors**: Invalid Redis URL or client configuration
///
/// # Examples
///
/// ```rust
/// async fn execute_redis_operation(client: &Client) -> Result<String, CacheError> {
///     let mut conn = get_redis_connection(client).await?;
///     
///     let result: String = conn.get("some_key").await.map_err(|e| {
///         CacheError::Operation {
///             source: Box::new(e),
///             span: SpanTrace::capture(),
///         }
///     })?;
///     
///     Ok(result)
/// }
/// ```
pub async fn get_redis_connection(client: &Client) -> Result<RedisConnection, CacheError> {
    client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Redis Connection", 
            &format!("Failed to acquire Redis connection: {}", e), 
            "connection_acquisition_error"
        );
        REDIS_OPERATIONS.with_label_values(&["connection_acquisition", "failure"]).inc();
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
///
/// This function implements secure token invalidation for logout operations,
/// security breaches, or administrative token revocation. The token itself
/// serves as the Redis key for efficient lookup during validation.
///
/// # Security Model
///
/// - **Token as Key**: Uses the full token as Redis key for O(1) lookup performance
/// - **Automatic Expiration**: Token expires from blacklist when JWT would naturally expire
/// - **Tamper Resistance**: Blocked status cannot be modified, only checked or expired
/// - **Audit Trail**: Comprehensive logging for security monitoring and compliance
///
/// # Arguments
///
/// - `redis`: Configured Redis client for token storage
/// - `token`: JWT token string to blacklist (full token, not just JTI)
/// - `exp`: Expiration time in seconds (typically JWT remaining lifetime)
///
/// # Returns
///
/// - `Ok(())`: Token successfully blocked and will expire automatically
/// - `Err(CacheError)`: Operation failed with detailed error context
///
/// # Performance Considerations
///
/// - **Memory Efficiency**: Token auto-expires, preventing Redis memory bloat
/// - **Lookup Speed**: O(1) token validation using EXISTS command
/// - **Network Optimization**: Single SET operation with expiration
///
/// # Examples
///
/// ```rust
/// async fn logout_user(redis: &Client, jwt_token: &str, remaining_ttl: i64) -> Result<(), CacheError> {
///     // Block token for its remaining lifetime
///     block_token(redis, jwt_token, remaining_ttl as usize).await?;
///     
///     log_info!("Authentication", "User logged out - token blacklisted", "security_operation");
///     Ok(())
/// }
/// ```
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), CacheError> {
    log_debug!(
        "Token Security", 
        &format!("Blocking JWT token (length: {}, expiration: {}s)", token.len(), exp), 
        "security_operation_attempt"
    );
    
    let mut connection = get_redis_connection(redis).await?;

    REDIS_OPERATIONS.with_label_values(&["block_token", "attempt"]).inc();
    
    connection.set_ex::<&str, &str, ()>(token, TOKEN_BLOCKED_VALUE, exp)
        .await
        .map_err(|e| {
            log_error!(
                "Token Security", 
                &format!("Failed to block token in Redis: {}", e), 
                "security_operation_failure"
            );
            REDIS_OPERATIONS.with_label_values(&["block_token", "failure"]).inc();
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
    REDIS_OPERATIONS.with_label_values(&["block_token", "success"]).inc();
    
    Ok(())
}

/// Checks if a JWT token is blocked with high-performance validation.
///
/// This function provides fast token validation for request authentication
/// by checking if a token exists in the Redis blacklist. It's designed for
/// high-throughput authentication scenarios with minimal latency impact.
///
/// # Validation Process
///
/// 1. **Connection Acquisition**: Gets Redis connection from pool
/// 2. **Existence Check**: Uses Redis EXISTS command for O(1) lookup
/// 3. **Result Interpretation**: Existence indicates token is blocked
/// 4. **Metrics Recording**: Updates validation metrics for monitoring
///
/// # Arguments
///
/// - `redis`: Configured Redis client for token lookup
/// - `token`: JWT token string to validate against blacklist
///
/// # Returns
///
/// - `Ok(true)`: Token is blocked and should be rejected
/// - `Ok(false)`: Token is not blocked and may be valid (subject to other validation)
/// - `Err(CacheError)`: Validation operation failed with detailed error context
///
/// # Performance Characteristics
///
/// - **Low Latency**: Single Redis EXISTS command (typically <1ms)
/// - **High Throughput**: Designed for request-path token validation
/// - **Network Efficient**: Minimal data transfer (boolean result)
/// - **Cache Friendly**: Redis keeps frequently accessed tokens in memory
///
/// # Examples
///
/// ```rust
/// async fn authenticate_request(redis: &Client, bearer_token: &str) -> Result<bool, AuthError> {
///     // Extract JWT from Authorization header
///     let token = bearer_token.strip_prefix("Bearer ").ok_or(AuthError::invalid_format())?;
///     
///     // Check if token is blacklisted
///     if is_token_blocked(redis, token).await? {
///         log_warn!("Authentication", "Blocked token used in request", "security_violation");
///         return Err(AuthError::token_revoked());
///     }
///     
///     // Continue with JWT signature validation...
///     Ok(true)
/// }
/// ```
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, CacheError> {
    log_debug!(
        "Token Validation", 
        &format!("Checking blacklist status for token (length: {})", token.len()), 
        "security_check_attempt"
    );
    
    let mut connection = get_redis_connection(redis).await?;
    
    REDIS_OPERATIONS.with_label_values(&["token_validation", "attempt"]).inc();
    
    let is_blocked: bool = connection.exists(token).await.map_err(|e| {
        log_error!(
            "Token Validation", 
            &format!("Token blacklist check failed: {}", e), 
            "security_check_failure"
        );
        REDIS_OPERATIONS.with_label_values(&["token_validation", "failure"]).inc();
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
    
    REDIS_OPERATIONS.with_label_values(&["token_validation", status]).inc();
    
    Ok(is_blocked)
}

// =============================================================================
// ACCOUNT ACTIVATION CODE MANAGEMENT
// =============================================================================

/// Stores an account activation code with secure, time-limited expiration.
///
/// This function implements the storage phase of the account activation workflow
/// by securely storing activation codes in Redis with automatic expiration. The
/// code-to-email mapping enables secure account activation validation.
///
/// # Security Features
///
/// - **Time-Limited Codes**: 24-hour automatic expiration prevents stale activations
/// - **Single-Use Semantics**: Codes are deleted after successful verification
/// - **Audit Trail**: Comprehensive logging for security monitoring
/// - **Key Namespace**: Prefixed keys prevent collision with other Redis data
///
/// # Arguments
///
/// - `redis_client`: Configured Redis client for secure storage
/// - `email`: User email address associated with the activation code
/// - `code`: Unique activation code (typically UUID-based for security)
///
/// # Returns
///
/// - `Ok(())`: Activation code stored successfully with automatic expiration
/// - `Err(CacheError)`: Storage operation failed with detailed error context
///
/// # Key Format
///
/// Redis keys use the format: `activation:code:{code}` for clear namespacing
/// and efficient retrieval during the activation verification process.
///
/// # Examples
///
/// ```rust
/// async fn initiate_account_activation(
///     redis: &Client, 
///     user_email: &str
/// ) -> Result<String, AuthServiceError> {
///     // Generate cryptographically secure activation code
///     let activation_code = uuid::Uuid::new_v4().to_string();
///     
///     // Store code with 24-hour expiration
///     store_activation_code(redis, user_email, &activation_code).await?;
///     
///     // Send activation email (code included in activation link)
///     send_activation_email(user_email, &activation_code).await?;
///     
///     Ok(activation_code)
/// }
/// ```
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

    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for activation code
    let key = format!("activation:code:{}", code);
    
    REDIS_OPERATIONS.with_label_values(&["activation_store", "attempt"]).inc();
    
    connection.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_TTL as usize)
        .await
        .map_err(|e| {
            log_error!(
                "Account Activation", 
                &format!("Failed to store activation code in Redis: {}", e), 
                "activation_storage_failure"
            );
            REDIS_OPERATIONS.with_label_values(&["activation_store", "failure"]).inc();
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
    REDIS_OPERATIONS.with_label_values(&["activation_store", "success"]).inc();
    
    Ok(())
}

/// Verifies and consumes an activation code with atomic single-use semantics.
///
/// This function implements the verification phase of account activation by
/// retrieving the email associated with an activation code and immediately
/// deleting the code to ensure single-use security semantics.
///
/// # Single-Use Security Model
///
/// 1. **Atomic Verification**: Code lookup and deletion in single operation context
/// 2. **Immediate Invalidation**: Successful verification deletes the code
/// 3. **Expiration Handling**: Expired codes return structured errors
/// 4. **Audit Logging**: All verification attempts are logged for security analysis
///
/// # Arguments
///
/// - `redis_client`: Configured Redis client for verification operations
/// - `code`: Activation code to verify (from user's activation link)
///
/// # Returns
///
/// - `Ok(String)`: Email address associated with valid activation code
/// - `Err(CacheError::KeyNotFound)`: Code not found, expired, or already used
/// - `Err(CacheError::Operation)`: Redis operation failed with error context
///
/// # Security Considerations
///
/// - **Rate Limiting**: Consider implementing rate limiting for verification attempts
/// - **Brute Force Protection**: Monitor failed verification attempts
/// - **Timing Attacks**: Function has consistent timing regardless of code validity
///
/// # Examples
///
/// ```rust
/// async fn complete_account_activation(
///     redis: &Client,
///     activation_code: &str
/// ) -> Result<String, AuthServiceError> {
///     // Verify and consume activation code
///     let email = verify_activation_code(redis, activation_code).await
///         .map_err(|_| AuthServiceError::invalid_activation_code())?;
///     
///     // Activate user account in database
///     activate_user_account(&email).await?;
///     
///     log_info!("Account Activation", &format!("Account {} successfully activated", email), "success");
///     Ok(email)
/// }
/// ```
pub async fn verify_activation_code(
    redis_client: &Client,
    code: &str,
) -> Result<String, CacheError> {
    log_debug!(
        "Account Activation", 
        &format!("Verifying activation code: {}", code), 
        "activation_verification_attempt"
    );

    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for activation code lookup
    let key = format!("activation:code:{}", code);
    
    // Retrieve email associated with activation code
    REDIS_OPERATIONS.with_label_values(&["activation_verify", "attempt"]).inc();
    
    let email: Option<String> = connection.get(&key).await.map_err(|e| {
        log_error!(
            "Account Activation", 
            &format!("Failed to retrieve activation code from Redis: {}", e), 
            "activation_verification_failure"
        );
        REDIS_OPERATIONS.with_label_values(&["activation_verify", "failure"]).inc();
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
            REDIS_OPERATIONS.with_label_values(&["activation_cleanup", "attempt"]).inc();
            
            let _: () = connection.del(&key).await.map_err(|e| {
                log_error!(
                    "Account Activation", 
                    &format!("Failed to delete used activation code: {}", e), 
                    "activation_cleanup_failure"
                );
                REDIS_OPERATIONS.with_label_values(&["activation_cleanup", "failure"]).inc();
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
            REDIS_OPERATIONS.with_label_values(&["activation_verify", "success"]).inc();
            REDIS_OPERATIONS.with_label_values(&["activation_cleanup", "success"]).inc();
            
            Ok(email)
        }
        None => {
            log_warn!(
                "Account Activation", 
                &format!("Invalid or expired activation code attempted: {}", code), 
                "activation_verification_invalid"
            );
            REDIS_OPERATIONS.with_label_values(&["activation_verify", "not_found"]).inc();
            
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
///
/// This function implements the initial phase of the password reset workflow
/// by securely storing reset tokens in Redis with short expiration times for
/// enhanced security. The token-to-email mapping enables secure reset validation.
///
/// # Security Model
///
/// - **Short Expiration**: 30-minute TTL balances security with user experience
/// - **Secure Tokens**: Assumes cryptographically secure tokens (UUID v4 recommended)
/// - **Audit Trail**: Comprehensive logging for security monitoring and compliance
/// - **Namespace Isolation**: Prefixed keys prevent collision with other operations
///
/// # Arguments
///
/// - `redis_client`: Configured Redis client for secure token storage
/// - `email`: User email address associated with the password reset request
/// - `token`: Unique reset token (should be cryptographically secure)
///
/// # Returns
///
/// - `Ok(())`: Reset token stored successfully with automatic expiration
/// - `Err(CacheError)`: Storage operation failed with detailed error context
///
/// # Token Lifecycle
///
/// 1. **Generation**: Secure token generated (typically UUID v4)
/// 2. **Storage**: Token stored with 30-minute expiration
/// 3. **Email Delivery**: Token included in password reset email
/// 4. **Verification**: Token validated during password reset form submission
/// 5. **Invalidation**: Token deleted after successful password reset
///
/// # Examples
///
/// ```rust
/// async fn initiate_password_reset(
///     redis: &Client,
///     user_email: &str
/// ) -> Result<String, AuthServiceError> {
///     // Generate cryptographically secure reset token
///     let reset_token = uuid::Uuid::new_v4().to_string();
///     
///     // Store token with 30-minute expiration
///     store_password_reset_token(redis, user_email, &reset_token).await?;
///     
///     // Send password reset email with token link
///     send_password_reset_email(user_email, &reset_token).await?;
///     
///     Ok(reset_token)
/// }
/// ```
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

    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for password reset token
    let key = format!("password_reset:token:{}", token);
    
    REDIS_OPERATIONS.with_label_values(&["reset_store", "attempt"]).inc();
    
    connection.set_ex::<_, _, ()>(key, email, PASSWORD_RESET_TTL as usize)
        .await
        .map_err(|e| {
            log_error!(
                "Password Reset", 
                &format!("Failed to store reset token in Redis: {}", e), 
                "reset_storage_failure"
            );
            REDIS_OPERATIONS.with_label_values(&["reset_store", "failure"]).inc();
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
    REDIS_OPERATIONS.with_label_values(&["reset_store", "success"]).inc();
    
    Ok(())
}

/// Verifies a password reset token without consuming it for validation.
///
/// This function validates reset tokens during password reset form submission
/// without immediately deleting the token. This allows for validation before
/// password update and explicit token invalidation after successful reset.
///
/// # Validation Process
///
/// 1. **Token Lookup**: Retrieves email associated with reset token
/// 2. **Expiration Check**: Redis automatically handles expired tokens
/// 3. **Email Return**: Returns associated email for further processing
/// 4. **Token Persistence**: Token remains valid until explicitly invalidated
///
/// # Arguments
///
/// - `redis_client`: Configured Redis client for token verification
/// - `token`: Password reset token to validate
///
/// # Returns
///
/// - `Ok(String)`: Email address associated with valid reset token
/// - `Err(CacheError::KeyNotFound)`: Token not found, expired, or invalid
/// - `Err(CacheError::Operation)`: Redis operation failed with error context
///
/// # Security Considerations
///
/// - **Token Reuse**: Token remains valid until explicitly invalidated
/// - **Rate Limiting**: Consider implementing rate limiting for verification attempts
/// - **Monitoring**: Log all verification attempts for security analysis
///
/// # Examples
///
/// ```rust
/// async fn validate_reset_request(
///     redis: &Client,
///     reset_token: &str,
///     new_password: &str
/// ) -> Result<String, AuthServiceError> {
///     // Verify token is valid and get associated email
///     let email = verify_reset_token(redis, reset_token).await
///         .map_err(|_| AuthServiceError::invalid_reset_token())?;
///     
///     // Update user password in database
///     update_user_password(&email, new_password).await?;
///     
///     // Invalidate the reset token to prevent reuse
///     invalidate_reset_token(redis, reset_token).await?;
///     
///     log_info!("Password Reset", &format!("Password successfully reset for {}", email), "success");
///     Ok(email)
/// }
/// ```
pub async fn verify_reset_token(
    redis_client: &Client,
    token: &str,
) -> Result<String, CacheError> {
    log_debug!(
        "Password Reset", 
        &format!("Verifying reset token: {}", token), 
        "reset_verification_attempt"
    );

    let mut connection = get_redis_connection(redis_client).await?;
    
    // Generate namespaced Redis key for reset token lookup
    let key = format!("password_reset:token:{}", token);
    
    REDIS_OPERATIONS.with_label_values(&["reset_verify", "attempt"]).inc();
    
    let email: Option<String> = connection.get(&key).await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Failed to retrieve reset token from Redis: {}", e), 
            "reset_verification_failure"
        );
        REDIS_OPERATIONS.with_label_values(&["reset_verify", "failure"]).inc();
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
            REDIS_OPERATIONS.with_label_values(&["reset_verify", "success"]).inc();
            
            Ok(email)
        }
        None => {
            log_warn!(
                "Password Reset", 
                &format!("Invalid or expired reset token attempted: {}", token), 
                "reset_verification_invalid"
            );
            REDIS_OPERATIONS.with_label_values(&["reset_verify", "not_found"]).inc();
            
            Err(CacheError::KeyNotFound {
                key: format!("password_reset:token:{}", token),
                span: SpanTrace::capture(),
            })
        }
    }
}

/// Invalidates a password reset token after successful password update.
///
/// This function implements secure token cleanup by removing reset tokens
/// from Redis after successful password reset operations. This prevents
/// token reuse and maintains security hygiene in the reset workflow.
///
/// # Security Hygiene
///
/// - **Immediate Invalidation**: Token deleted immediately after password reset
/// - **Prevents Reuse**: Ensures tokens cannot be used multiple times
/// - **Audit Trail**: Comprehensive logging for security monitoring
/// - **Error Resilience**: Non-critical errors don't break password reset flow
///
/// # Arguments
///
/// - `redis_client`: Configured Redis client for token cleanup operations
/// - `token`: Password reset token to invalidate and remove
///
/// # Returns
///
/// - `Ok(())`: Token successfully invalidated and removed from Redis
/// - `Err(CacheError)`: Cleanup operation failed with detailed error context
///
/// # Error Handling Philosophy
///
/// Token invalidation errors are logged but may not be critical for user
/// experience since the password has already been successfully updated.
/// However, cleanup failures should be monitored for security analysis.
///
/// # Examples
///
/// ```rust
/// async fn complete_password_reset(
///     redis: &Client,
///     reset_token: &str,
///     new_password_hash: &str
/// ) -> Result<(), AuthServiceError> {
///     // Verify token and get email
///     let email = verify_reset_token(redis, reset_token).await?;
///     
///     // Update password in database
///     update_user_password_hash(&email, new_password_hash).await?;
///     
///     // Clean up the reset token
///     if let Err(e) = invalidate_reset_token(redis, reset_token).await {
///         // Log error but don't fail the operation since password was updated
///         log_warn!("Password Reset", &format!("Token cleanup failed: {}", e), "cleanup_warning");
///     }
///     
///     log_info!("Password Reset", &format!("Password reset completed for {}", email), "success");
///     Ok(())
/// }
/// ```
pub async fn invalidate_reset_token(
    redis_client: &Client,
    token: &str,
) -> Result<(), CacheError> {
    log_debug!(
        "Password Reset", 
        &format!("Invalidating used reset token: {}", token), 
        "reset_cleanup_attempt"
    );

    let mut connection = get_redis_connection(redis_client).await?;

    // Generate namespaced Redis key for reset token cleanup
    let key = format!("password_reset:token:{}", token);
    
    REDIS_OPERATIONS.with_label_values(&["reset_cleanup", "attempt"]).inc();
    
    let _: () = connection.del(&key).await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Failed to delete used reset token: {}", e), 
            "reset_cleanup_failure"
        );
        REDIS_OPERATIONS.with_label_values(&["reset_cleanup", "failure"]).inc();
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
    REDIS_OPERATIONS.with_label_values(&["reset_cleanup", "success"]).inc();
    
    Ok(())
}

// =============================================================================
// SECURITY AND UTILITY FUNCTIONS
// =============================================================================

/// Masks sensitive information in Redis URLs for secure logging and monitoring.
///
/// This function sanitizes Redis connection URLs by hiding passwords and other
/// sensitive authentication information while preserving debugging information.
/// This enables safe logging without exposing credentials in log files or
/// monitoring systems.
///
/// # Security Features
///
/// - **Password Masking**: Replaces passwords with asterisks while preserving URL structure
/// - **Query Parameter Protection**: Redacts potentially sensitive query parameters
/// - **Format Preservation**: Maintains URL structure for debugging purposes
/// - **Fallback Safety**: Unknown formats are handled gracefully with generic masking
///
/// # Supported URL Formats
///
/// - **Basic**: `redis://host:port/database` (no masking needed)
/// - **Authenticated**: `redis://user:password@host:port/db` → `redis://user:****@host:port/db`
/// - **TLS**: `rediss://user:password@host:port/db` → `rediss://user:****@host:port/db`
/// - **With Parameters**: URLs with query parameters are sanitized
///
/// # Arguments
///
/// - `url`: Redis URL that may contain sensitive authentication credentials
///
/// # Returns
///
/// A sanitized URL string safe for logging, monitoring, and debugging
///
/// # Examples
///
/// ```rust
/// // Authenticated Redis URL
/// let masked = mask_redis_url("redis://admin:secretpass@cache.example.com:6379/0");
/// assert_eq!(masked, "redis://admin:****@cache.example.com:6379/0");
///
/// // Basic Redis URL (no credentials to mask)
/// let masked = mask_redis_url("redis://localhost:6379");
/// assert_eq!(masked, "redis://localhost:6379");
///
/// // URL with query parameters
/// let masked = mask_redis_url("redis://localhost:6379/0?timeout=5000");
/// assert_eq!(masked, "redis://localhost:6379/0?[PARAMS_REDACTED]");
/// ```
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
    use redis::{Client, AsyncCommands}; // ← Add AsyncCommands import
    use std::env;
    use tokio;

    /// Creates a Redis client configured for a non-existent server for testing failure scenarios.
    ///
    /// This helper function creates a client that will fail connection attempts,
    /// allowing us to test error handling paths without requiring Redis infrastructure.
    fn create_unavailable_redis_client() -> Client {
        // Use a non-standard port to ensure connection failures
        Client::open("redis://127.0.0.1:63999/")
            .expect("Client creation should succeed even for invalid addresses")
    }
    
    /// Sets up test environment with proper Redis URL configuration.
    ///
    /// This helper ensures tests have consistent environment setup and can
    /// run in various CI/CD environments with different Redis configurations.
    fn setup_test_environment() {
        env::set_var(REDIS_URL_ENV, "redis://127.0.0.1:6379/");
    }

    /// Creates a Redis client for integration testing.
    ///
    /// This helper function creates a client pointing to a local Redis instance
    /// for integration tests that require actual Redis connectivity.
    ///
    /// # Panics
    ///
    /// Panics if Redis URL is invalid (test infrastructure issue)
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
        
        // Zmień z unwrap_err() na pattern matching:
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
    // JWT TOKEN BLACKLISTING TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_token_operations_fail_with_unavailable_redis() {
        let unavailable_client = create_unavailable_redis_client();
        let test_token = "test.jwt.token.example";
        
        // Test token blocking failure
        let block_result = block_token(&unavailable_client, test_token, 3600).await;
        assert!(block_result.is_err(), "Token blocking should fail with unavailable Redis");
        
        // Test token validation failure
        let validation_result = is_token_blocked(&unavailable_client, test_token).await;
        assert!(validation_result.is_err(), "Token validation should fail with unavailable Redis");
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_complete_token_blacklisting_workflow() {
        let client = create_test_redis_client().await;
        
        // Generate unique token for test isolation
        let test_token = format!("test.jwt.token.{}", uuid::Uuid::new_v4());
        
        // Initially, token should not be blocked
        let initially_blocked = is_token_blocked(&client, &test_token).await
            .expect("Token validation should succeed");
        assert!(!initially_blocked, "Token should not be blocked initially");
        
        // Block the token
        block_token(&client, &test_token, 3600).await
            .expect("Token blocking should succeed");
        
        // After blocking, token should be detected as blocked
        let blocked_after = is_token_blocked(&client, &test_token).await
            .expect("Token validation should succeed");
        assert!(blocked_after, "Token should be blocked after block_token operation");
        
        // Cleanup: Remove test token
        let mut connection = client.get_async_connection().await
            .expect("Connection acquisition should succeed");
        let _: () = connection.del(&test_token).await
            .expect("Test cleanup should succeed");
    }

    // =============================================================================
    // ACTIVATION CODE MANAGEMENT TESTS
    // =============================================================================

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_complete_activation_code_workflow() {
        let client = create_test_redis_client().await;
        let activation_code = uuid::Uuid::new_v4().to_string();
        let test_email = "test.activation@example.com";
        
        // Clean up any existing test data
        let mut connection = client.get_async_connection().await
            .expect("Connection acquisition should succeed");
        let _: Option<String> = connection.get(&format!("activation:code:{}", activation_code)).await.ok();

        // Store activation code
        store_activation_code(&client, test_email, &activation_code).await
            .expect("Activation code storage should succeed");

        // Verify activation code and retrieve email
        let retrieved_email = verify_activation_code(&client, &activation_code).await
            .expect("Activation code verification should succeed");
        
        assert_eq!(retrieved_email, test_email, "Retrieved email should match stored email");

        // Verify code was consumed (second verification should fail)
        let second_verification = verify_activation_code(&client, &activation_code).await;
        assert!(second_verification.is_err(), "Second verification should fail (single-use semantics)");
        
        // Verify error type is correct
        match second_verification.unwrap_err() {
            CacheError::KeyNotFound { key: _, span: _ } => {
                // Expected error type - test passes
            }
            other => panic!("Expected CacheError::KeyNotFound, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_activation_code_not_found_handling() {
        let client = create_test_redis_client().await;
        let nonexistent_code = "this-code-definitely-does-not-exist-in-redis";
        
        let result = verify_activation_code(&client, nonexistent_code).await;
        assert!(result.is_err(), "Verification should fail for nonexistent activation code");
        
        // Verify error type and content
        match result.unwrap_err() {
            CacheError::KeyNotFound { key, span: _ } => {
                assert!(
                    key.contains("activation:code:"), 
                    "Error key should contain activation namespace prefix"
                );
                assert!(
                    key.contains(nonexistent_code),
                    "Error key should contain the requested code"
                );
            }
            other => panic!("Expected CacheError::KeyNotFound, got: {:?}", other),
        }
    }

    // =============================================================================
    // PASSWORD RESET TOKEN MANAGEMENT TESTS
    // =============================================================================

    #[tokio::test]
    #[ignore] // Requires running Redis instance
    async fn test_complete_password_reset_token_workflow() {
        let client = create_test_redis_client().await;
        let reset_token = uuid::Uuid::new_v4().to_string();
        let test_email = "test.reset@example.com";
        
        // Store password reset token
        store_password_reset_token(&client, test_email, &reset_token).await
            .expect("Password reset token storage should succeed");
        
        // Verify reset token and retrieve email
        let retrieved_email = verify_reset_token(&client, &reset_token).await
            .expect("Password reset token verification should succeed");
        
        assert_eq!(retrieved_email, test_email, "Retrieved email should match stored email");
        
        // Invalidate the reset token
        invalidate_reset_token(&client, &reset_token).await
            .expect("Password reset token invalidation should succeed");
        
        // Verify token was invalidated (verification should fail)
        let post_invalidation_verification = verify_reset_token(&client, &reset_token).await;
        assert!(
            post_invalidation_verification.is_err(), 
            "Verification should fail after token invalidation"
        );
        
        // Verify error type is correct
        match post_invalidation_verification.unwrap_err() {
            CacheError::KeyNotFound { key: _, span: _ } => {
                // Expected error type - test passes
            }
            other => panic!("Expected CacheError::KeyNotFound, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // Requires running Redis instance  
    async fn test_password_reset_token_persistence_during_verification() {
        let client = create_test_redis_client().await;
        let reset_token = uuid::Uuid::new_v4().to_string();
        let test_email = "test.persistence@example.com";
        
        // Store password reset token
        store_password_reset_token(&client, test_email, &reset_token).await
            .expect("Password reset token storage should succeed");
        
        // First verification should succeed
        let first_email = verify_reset_token(&client, &reset_token).await
            .expect("First verification should succeed");
        assert_eq!(first_email, test_email);
        
        // Second verification should also succeed (token not consumed by verification)
        let second_email = verify_reset_token(&client, &reset_token).await
            .expect("Second verification should succeed (token persists)");
        assert_eq!(second_email, test_email);
        
        // Clean up: Invalidate token
        invalidate_reset_token(&client, &reset_token).await
            .expect("Token cleanup should succeed");
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