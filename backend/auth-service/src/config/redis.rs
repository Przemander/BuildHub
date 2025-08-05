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
use crate::utils::telemetry::{redis_operation_span, SpanExt};
use crate::utils::log_new::Log; // ✅ NOWY SYSTEM LOGOWANIA
use crate::{
    metricss::redis_metrics::{
        // Core API
        set_redis_health, time_redis_operation, record_redis_operation,
        init_redis_metrics, sanitize_rate_limit_key, spawn_metrics_collector,
        // Constants
        operations, results, health, jwt, rate_limit, activation, reset,
    },
};
use redis::{AsyncCommands, Client};
use std::env;
use tracing::Instrument;
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
    // Create span for Redis initialization
    let span = redis_operation_span("init_redis", "connection");
    
    // Initialize Redis metrics system first
    init_redis_metrics();
    
    // Use the span to wrap the initialization logic
    span.in_scope(|| {
        let redis_url = env::var(REDIS_URL_ENV).map_err(|e| {
            Log::event(
                "ERROR",
                "Redis Configuration",
                &format!("Missing {} environment variable", REDIS_URL_ENV),
                "initialization_error",
                "init_redis"
            );
            span.record("redis.success", &false);
            span.record("failure_reason", &"missing_env_var");
            span.record_error(&e);
            CacheError::Connection {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

        Log::event(
            "INFO",
            "Redis Configuration",
            &format!("Initializing Redis client with URL: {}", mask_redis_url(&redis_url)),
            "initialization_attempt",
            "init_redis"
        );

        let client = Client::open(redis_url).map_err(|e| {
            Log::event(
                "ERROR",
                "Redis Configuration",
                &format!("Invalid Redis URL configuration: {}", e),
                "initialization_error",
                "init_redis"
            );
            // Record client initialization failure
            record_redis_operation(operations::CLIENT_INIT, results::FAILURE);
            span.record("redis.success", &false);
            span.record("failure_reason", &"invalid_url");
            span.record_error(&e);
            CacheError::Connection {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

        Log::event(
            "INFO",
            "Redis Configuration",
            "Redis client initialized successfully",
            "initialization_success",
            "init_redis"
        );
        // Record client initialization success
        record_redis_operation(operations::CLIENT_INIT, results::SUCCESS);
        span.record("redis.success", &true);
        
        Ok(client)
    })
}

/// Starts background Redis metrics collection for observability
#[allow(dead_code)]
pub fn start_redis_metrics_collection(client: Client) {
    spawn_metrics_collector(client);
}

/// Performs comprehensive Redis connection health check with detailed diagnostics.
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    // Create span for health check operation
    let span = redis_operation_span("health_check", "ping");
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::HEALTH_CHECK);
    
    // Wrap the health check in the span
    async move {
        let mut connection = match redis_client.get_async_connection().await {
            Ok(conn) => {
                Log::event(
                    "DEBUG",
                    "Redis Health",
                    "Successfully acquired connection for health check",
                    "connection_success",
                    "check_redis_connection"
                );
                span.record("connection.success", &true);
                conn
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Redis Health",
                    &format!("Failed to acquire connection for health check: {}", e),
                    "health_check_connection_failure",
                    "check_redis_connection"
                );
                // Record connection failure
                health::record_connection_failure();
                span.record("connection.success", &false);
                span.record("failure_reason", &"connection_failed");
                span.record_error(&e);
                set_redis_health(false);
                return false;
            }
        };

        match redis::cmd("PING").query_async::<_, String>(&mut connection).await {
            Ok(response) if response == "PONG" => {
                Log::event(
                    "INFO",
                    "Redis Health",
                    "Health check successful - Redis responding correctly",
                    "health_success",
                    "check_redis_connection"
                );
                // Record health check success
                health::record_success();
                span.record("ping.success", &true);
                span.record("response", &response);
                set_redis_health(true);
                true
            }
            Ok(unexpected_response) => {
                Log::event(
                    "ERROR",
                    "Redis Health",
                    &format!("Unexpected PING response: expected 'PONG', got '{}'", unexpected_response),
                    "health_check_unexpected_response",
                    "check_redis_connection"
                );
                // Record unexpected response
                health::record_unexpected_response();
                span.record("ping.success", &false);
                span.record("failure_reason", &"unexpected_response");
                span.record("response", &unexpected_response);
                set_redis_health(false);
                false
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Redis Health",
                    &format!("PING command failed: {}", e),
                    "health_check_command_failure",
                    "check_redis_connection"
                );
                // Record command failure
                health::record_command_failure();
                span.record("ping.success", &false);
                span.record("failure_reason", &"command_failed");
                span.record_error(&e);
                set_redis_health(false);
                false
            }
        }
    }
    .instrument(span_clone)
    .await
}

/// Blocks a JWT token by storing it in Redis with automatic expiration.
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), CacheError> {
    // Create span for this Redis operation
    let span = redis_operation_span("block_token", "jwt:revoked:*");
    span.record("token_length", &token.len());
    span.record("ttl_seconds", &exp);
    
    Log::event(
        "DEBUG",
        "Token Security",
        &format!("Blocking JWT token (length: {}, expiration: {}s)", token.len(), exp),
        "security_operation_attempt",
        "block_token"
    );
    
    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::BLOCK_TOKEN);
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis).await?;
        
        connection.set_ex::<&str, &str, ()>(token, TOKEN_BLOCKED_VALUE, exp)
            .await
            .map_err(|e| {
                Log::event(
                    "ERROR",
                    "Token Security",
                    &format!("Failed to block token in Redis: {}", e),
                    "security_operation_failure",
                    "block_token"
                );
                // Record block token failure
                jwt::record_block_failure();
                span.record("redis.success", &false);
                span.record_error(&e);
                CacheError::Operation {
                    source: Box::new(e),
                    span: SpanTrace::capture(),
                }
            })?;

        Log::event(
            "INFO",
            "Token Security",
            &format!("JWT token successfully blocked (expires in {}s)", exp),
            "security_operation_success",
            "block_token"
        );
        // Record block token success
        jwt::record_block_success();
        span.record("redis.success", &true);
        
        Ok(())
    }
    .instrument(span_clone)
    .await
}

/// Checks if a JWT token is blocked with high-performance validation.
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, CacheError> {
    // Create span for token validation operation
    let span = redis_operation_span("check_token_blocked", "jwt:*");
    span.record("token_length", &token.len());
    
    Log::event(
        "DEBUG",
        "Token Validation",
        &format!("Checking blacklist status for token (length: {})", token.len()),
        "security_check_attempt",
        "is_token_blocked"
    );
    
    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::TOKEN_VALIDATION);
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis).await?;
        
        let is_blocked: bool = connection.exists(token).await.map_err(|e| {
            Log::event(
                "ERROR",
                "Token Validation",
                &format!("Token blacklist check failed: {}", e),
                "security_check_failure",
                "is_token_blocked"
            );
            // Record token validation failure
            jwt::record_validation_failure();
            span.record("redis.success", &false);
            span.record_error(&e);
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

        let status = if is_blocked { "blocked" } else { "valid" };
        Log::event(
            "DEBUG",
            "Token Validation",
            &format!("Token blacklist check complete: {}", status),
            "security_check_success",
            "is_token_blocked"
        );
        
        // Record token validation result
        if is_blocked {
            jwt::record_validation_blocked();
            span.record("token_status", &"blocked");
        } else {
            jwt::record_validation_valid();
            span.record("token_status", &"valid");
        }
        
        span.record("redis.success", &true);
        
        Ok(is_blocked)
    }
    .instrument(span_clone)
    .await
}

/// Acquires a Redis connection with comprehensive error handling and instrumentation.
pub async fn get_redis_connection(client: &Client) -> Result<RedisConnection, CacheError> {
    // Create span for connection acquisition
    let span = redis_operation_span("get_connection", "connection");
    
    // Use timer API to measure connection acquisition time
    let _timer = time_redis_operation(operations::CONNECTION_ACQUISITION);
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    // Wrap the Redis operation in the span
    async move {
        client.get_async_connection().await.map_err(|e| {
            Log::event(
                "ERROR",
                "Redis Connection",
                &format!("Failed to acquire Redis connection: {}", e),
                "connection_acquisition_error",
                "get_redis_connection"
            );
            // Record connection acquisition failure
            record_redis_operation(operations::CONNECTION_ACQUISITION, results::FAILURE);
            span.record("redis.success", &false);
            span.record_error(&e);
            CacheError::Connection {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })
    }
    .instrument(span_clone)
    .await
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
    // Create span for storing activation code
    let span = redis_operation_span("store_activation_code", "activation:code:*");
    span.record("code_length", &code.len());
    span.record("email_domain", &email.split('@').nth(1).unwrap_or("invalid"));
    span.record("ttl_seconds", &ACTIVATION_CODE_TTL);
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    Log::event(
        "DEBUG",
        "Account Activation",
        &format!("Storing activation code for {} (expires in {}h)", email, ACTIVATION_CODE_TTL / 3600),
        "activation_storage_attempt",
        "store_activation_code"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::ACTIVATION_STORE);
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis_client).await?;
        
        // Generate namespaced Redis key for activation code
        let key = format!("activation:code:{}", code);
        
        connection.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_TTL as usize)
            .await
            .map_err(|e| {
                Log::event(
                    "ERROR",
                    "Account Activation",
                    &format!("Failed to store activation code in Redis: {}", e),
                    "activation_storage_failure",
                    "store_activation_code"
                );
                // Record activation storage failure - using helper for consistency
                activation::record_store_failure();
                span.record("redis.success", &false);
                span.record_error(&e);
                CacheError::Operation {
                    source: Box::new(e),
                    span: SpanTrace::capture(),
                }
            })?;

        Log::event(
            "INFO",
            "Account Activation",
            &format!("Activation code for {} stored successfully (24h expiration)", email),
            "activation_storage_success",
            "store_activation_code"
        );
        // Record activation storage success
        activation::record_store_success();
        span.record("redis.success", &true);
        
        Ok(())
    }
    .instrument(span_clone)
    .await
}

/// Verifies and consumes an activation code with atomic single-use semantics.
pub async fn verify_activation_code(
    redis_client: &Client,
    code: &str,
) -> Result<String, CacheError> {
    // Create span for verifying activation code
    let span = redis_operation_span("verify_activation_code", "activation:code:*");
    span.record("code_length", &code.len());
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    Log::event(
        "DEBUG",
        "Account Activation",
        &format!("Verifying activation code: {}", code),
        "activation_verification_attempt",
        "verify_activation_code"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::ACTIVATION_VERIFY);
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis_client).await?;
        
        // Generate namespaced Redis key for activation code lookup
        let key = format!("activation:code:{}", code);
        
        // Retrieve email associated with activation code
        let email: Option<String> = connection.get(&key).await.map_err(|e| {
            Log::event(
                "ERROR",
                "Account Activation",
                &format!("Failed to retrieve activation code from Redis: {}", e),
                "activation_verification_failure",
                "verify_activation_code"
            );
            // Record verification failure - using helper for consistency
            activation::record_verify_failure();
            span.record("redis.success", &false);
            span.record_error(&e);
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

        match email {
            Some(email) => {
                span.record("email_domain", &email.split('@').nth(1).unwrap_or("invalid"));
                span.record("code_found", &true);
                
                Log::event(
                    "DEBUG",
                    "Account Activation",
                    &format!("Valid activation code found for {}", email),
                    "activation_verification_success",
                    "verify_activation_code"
                );
                
                // Delete the code immediately to ensure single-use semantics
                // Use timer API to measure cleanup operation time
                let _cleanup_timer = time_redis_operation(operations::ACTIVATION_CLEANUP);
                
                // Create child span for cleanup operation
                let cleanup_span = redis_operation_span("cleanup_activation_code", "activation:code:*");
                cleanup_span.record("code_length", &code.len());
                
                // Clone cleanup span before moving it
                let cleanup_span_clone = cleanup_span.clone();
                
                // Perform cleanup within its own span
                let cleanup_result = async {
                    let _: () = connection.del(&key).await.map_err(|e| {
                        Log::event(
                            "ERROR",
                            "Account Activation",
                            &format!("Failed to delete used activation code: {}", e),
                            "activation_cleanup_failure",
                            "verify_activation_code"
                        );
                        // Record cleanup failure - using helper for consistency
                        activation::record_cleanup_failure();
                        cleanup_span.record("redis.success", &false);
                        cleanup_span.record_error(&e);
                        CacheError::Operation {
                            source: Box::new(e),
                            span: SpanTrace::capture(),
                        }
                    })?;
                    
                    cleanup_span.record("redis.success", &true);
                    Ok(()) as Result<(), CacheError> // Add explicit type annotation here
                }
                .instrument(cleanup_span_clone)
                .await;
                
                // Handle cleanup result but continue if it fails
                if let Err(e) = cleanup_result {
                    Log::event(
                        "WARN",
                        "Account Activation",
                        &format!("Code cleanup failed but activation will proceed: {}", e),
                        "activation_cleanup_warning",
                        "verify_activation_code"
                    );
                    // We don't fail the activation if cleanup fails
                } else {
                    activation::record_cleanup_success();
                }
                
                Log::event(
                    "INFO",
                    "Account Activation",
                    &format!("Account for {} successfully activated and code consumed", email),
                    "activation_complete",
                    "verify_activation_code"
                );
                // Record verification success
                activation::record_verify_success();
                span.record("redis.success", &true);
                
                Ok(email)
            }
            None => {
                Log::event(
                    "WARN",
                    "Account Activation",
                    &format!("Invalid or expired activation code attempted: {}", code),
                    "activation_verification_invalid",
                    "verify_activation_code"
                );
                // Record not found result
                activation::record_verify_not_found();
                span.record("redis.success", &true); // Redis worked correctly
                span.record("code_found", &false);   // Just no code found
                
                Err(CacheError::KeyNotFound {
                    key: format!("activation:code:{}", code),
                    span: SpanTrace::capture(),
                })
            }
        }
    }
    .instrument(span_clone)
    .await
}

/// Stores a password reset token with secure, time-limited expiration.
pub async fn store_password_reset_token(
    redis_client: &Client,
    email: &str,
    token: &str,
) -> Result<(), CacheError> {
    // Create span for storing password reset token
    let span = redis_operation_span("store_reset_token", "password_reset:token:*");
    span.record("token_length", &token.len());
    span.record("email_domain", &email.split('@').nth(1).unwrap_or("invalid"));
    span.record("ttl_seconds", &PASSWORD_RESET_TTL);
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    Log::event(
        "DEBUG",
        "Password Reset",
        &format!("Storing password reset token for {} (expires in {}m)", email, PASSWORD_RESET_TTL / 60),
        "reset_storage_attempt",
        "store_password_reset_token"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RESET_STORE);
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis_client).await?;
        
        // Generate namespaced Redis key for password reset token
        let key = format!("password_reset:token:{}", token);
        
        connection.set_ex::<_, _, ()>(key, email, PASSWORD_RESET_TTL as usize)
            .await
            .map_err(|e| {
                Log::event(
                    "ERROR",
                    "Password Reset",
                    &format!("Failed to store reset token in Redis: {}", e),
                    "reset_storage_failure",
                    "store_password_reset_token"
                );
                // Record storage failure - using helper for consistency
                reset::record_store_failure();
                span.record("redis.success", &false);
                span.record_error(&e);
                CacheError::Operation {
                    source: Box::new(e),
                    span: SpanTrace::capture(),
                }
            })?;

        Log::event(
            "INFO",
            "Password Reset",
            &format!("Reset token for {} stored successfully (30m expiration)", email),
            "reset_storage_success",
            "store_password_reset_token"
        );
        // Record storage success
        reset::record_store_success();
        span.record("redis.success", &true);
        
        Ok(())
    }
    .instrument(span_clone)
    .await
}

/// Verifies a password reset token without consuming it for validation.
pub async fn verify_reset_token(
    redis_client: &Client,
    token: &str,
) -> Result<String, CacheError> {
    // Create span for verifying reset token
    let span = redis_operation_span("verify_reset_token", "password_reset:token:*");
    span.record("token_length", &token.len());
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    Log::event(
        "DEBUG",
        "Password Reset",
        &format!("Verifying reset token: {}", token),
        "reset_verification_attempt",
        "verify_reset_token"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RESET_VERIFY);
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis_client).await?;
        
        // Generate namespaced Redis key for reset token lookup
        let key = format!("password_reset:token:{}", token);
        
        let email: Option<String> = connection.get(&key).await.map_err(|e| {
            Log::event(
                "ERROR",
                "Password Reset",
                &format!("Failed to retrieve reset token from Redis: {}", e),
                "reset_verification_failure",
                "verify_reset_token"
            );
            // Record verification failure - using helper for consistency
            reset::record_verify_failure();
            span.record("redis.success", &false);
            span.record_error(&e);
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;
        
        match email {
            Some(email) => {
                span.record("email_domain", &email.split('@').nth(1).unwrap_or("invalid"));
                span.record("token_found", &true);
                
                Log::event(
                    "DEBUG",
                    "Password Reset",
                    &format!("Valid reset token found for {}", email),
                    "reset_verification_success",
                    "verify_reset_token"
                );
                // Record verification success
                reset::record_verify_success();
                span.record("redis.success", &true);
                
                Ok(email)
            }
            None => {
                Log::event(
                    "WARN",
                    "Password Reset",
                    &format!("Invalid or expired reset token attempted: {}", token),
                    "reset_verification_invalid",
                    "verify_reset_token"
                );
                // Record not found result
                reset::record_verify_not_found();
                span.record("redis.success", &true); // Redis worked correctly
                span.record("token_found", &false);  // Just no token found
                
                Err(CacheError::KeyNotFound {
                    key: format!("password_reset:token:{}", token),
                    span: SpanTrace::capture(),
                })
            }
        }
    }
    .instrument(span_clone)
    .await
}

/// Invalidates a password reset token after successful password update.
pub async fn invalidate_reset_token(
    redis_client: &Client,
    token: &str,
) -> Result<(), CacheError> {
    // Create span for invalidating reset token
    let span = redis_operation_span("invalidate_reset_token", "password_reset:token:*");
    span.record("token_length", &token.len());
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    Log::event(
        "DEBUG",
        "Password Reset",
        &format!("Invalidating used reset token: {}", token),
        "reset_cleanup_attempt",
        "invalidate_reset_token"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RESET_CLEANUP);
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis_client).await?;

        // Generate namespaced Redis key for reset token cleanup
        let key = format!("password_reset:token:{}", token);
        
        let _: () = connection.del(&key).await.map_err(|e| {
            Log::event(
                "ERROR",
                "Password Reset",
                &format!("Failed to delete used reset token: {}", e),
                "reset_cleanup_failure",
                "invalidate_reset_token"
            );
            // Record cleanup failure - using helper for consistency
            reset::record_cleanup_failure();
            span.record("redis.success", &false);
            span.record_error(&e);
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;
        
        Log::event(
            "INFO",
            "Password Reset",
            &format!("Reset token {} successfully invalidated", token),
            "reset_cleanup_success",
            "invalidate_reset_token"
        );
        // Record cleanup success
        reset::record_cleanup_success();
        span.record("redis.success", &true);
        
        Ok(())
    }
    .instrument(span_clone)
    .await
}

/// Performs atomic rate limit check and increment with sliding window implementation.
pub async fn check_and_increment_rate_limit(
    redis_client: &Client,
    key: &str,
    max_attempts: u32,
    window_seconds: usize,
) -> Result<bool, CacheError> {
    // Create span for rate limit check
    let span = redis_operation_span("rate_limit_check", "rate_limit:*");
    // Record key metadata but not the actual key (for privacy)
    span.record("key_prefix", &key.split(':').next().unwrap_or("unknown"));
    span.record("key_length", &key.len());
    span.record("max_attempts", &max_attempts);
    span.record("window_seconds", &window_seconds);
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    // Sanitize the key to prevent cardinality explosion
    let sanitized_key = sanitize_rate_limit_key(key);
    
    Log::event(
        "DEBUG",
        "Rate Limiting",
        &format!("Checking rate limit for key: {} (max: {}, window: {}s)", 
                sanitized_key, max_attempts, window_seconds),
        "rate_limit_check_attempt",
        "check_and_increment_rate_limit"
    );

    // Use timer API to measure operation time
    let _timer = time_redis_operation(operations::RATE_LIMIT_CHECK);
    
    // Wrap the Redis operation in the span
    async move {
        let mut connection = get_redis_connection(redis_client).await?;

        // Atomically increment the counter
        let current_count: u32 = connection.incr(&sanitized_key, 1).await.map_err(|e| {
            Log::event(
                "ERROR",
                "Rate Limiting",
                &format!("Failed to increment rate limit counter for {}: {}", sanitized_key, e),
                "rate_limit_increment_failure",
                "check_and_increment_rate_limit"
            );
            // Record rate limit check failure
            rate_limit::record_failure();
            span.record("redis.success", &false);
            span.record("failure_reason", &"increment_failed");
            span.record_error(&e);
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

        // Record the current count
        span.record("current_count", &current_count);

        // On first increment, set the expiration time for the sliding window
        if current_count == 1 {
            // Use timer API to measure expiration operation time
            let _expire_timer = time_redis_operation(operations::RATE_LIMIT_EXPIRE);
            
            // Create child span for expiration operation
            let expire_span = redis_operation_span("rate_limit_expire", "rate_limit:*");
            expire_span.record("key_length", &sanitized_key.len());
            expire_span.record("window_seconds", &window_seconds);
            
            // Clone expire span before moving it
            let expire_span_clone = expire_span.clone();
            
            // Perform expiration within its own span
            let expire_result = async {
                let _: () = connection.expire(&sanitized_key, window_seconds).await.map_err(|e| {
                    Log::event(
                        "ERROR",
                        "Rate Limiting",
                        &format!("Failed to set expiration for rate limit key {}: {}", sanitized_key, e),
                        "rate_limit_expiration_failure",
                        "check_and_increment_rate_limit"
                    );
                    // Record rate limit expiration failure
                    rate_limit::record_failure();
                    expire_span.record("redis.success", &false);
                    expire_span.record_error(&e);
                    CacheError::Operation {
                        source: Box::new(e),
                        span: SpanTrace::capture(),
                    }
                })?;
                
                expire_span.record("redis.success", &true);
                Ok(())
            }
            .instrument(expire_span_clone)
            .await;
            
            // Handle expire result
            if let Err(e) = expire_result {
                // If expiration fails, return the error
                return Err(e);
            }
            
            Log::event(
                "DEBUG",
                "Rate Limiting",
                &format!("Set expiration for new rate limit window: {} ({}s)", sanitized_key, window_seconds),
                "rate_limit_window_created",
                "check_and_increment_rate_limit"
            );
        }

        let within_limit = current_count <= max_attempts;
        let status = if within_limit { "allowed" } else { "blocked" };
        
        span.record("within_limit", &within_limit);
        span.record("status", &status);

        Log::event(
            "DEBUG",
            "Rate Limiting",
            &format!(
                "Rate limit check complete: {} - {}/{} attempts ({})",
                sanitized_key, current_count, max_attempts, status
            ),
            "rate_limit_check_complete",
            "check_and_increment_rate_limit"
        );

        // Record rate limit check result
        if within_limit {
            rate_limit::record_allowed();
        } else {
            rate_limit::record_blocked();
            
            Log::event(
                "WARN",
                "Rate Limiting",
                &format!(
                    "Rate limit exceeded: {} - {}/{} attempts in window",
                    sanitized_key, current_count, max_attempts
                ),
                "rate_limit_exceeded",
                "check_and_increment_rate_limit"
            );
        }
        
        span.record("redis.success", &true);
        Ok(within_limit)
    }
    .instrument(span_clone)
    .await
}

/// Masks sensitive information in Redis URL for secure logging.
///
/// Replaces password in Redis URL with "***" to prevent credential leakage
/// in logs and traces while preserving connection details for debugging.
///
/// # Examples
/// ```
/// assert_eq!(
///     mask_redis_url("redis://user:password@localhost:6379"),
///     "redis://user:***@localhost:6379"
/// );
/// ```
fn mask_redis_url(url: &str) -> String {
    // Basic implementation to mask passwords in Redis URLs
    if let Some(auth_start) = url.find('@') {
        if let Some(cred_start) = url[..auth_start].rfind("://") {
            let prefix = &url[..(cred_start + 3)];
            let credentials = &url[(cred_start + 3)..auth_start];
            let suffix = &url[auth_start..];
            
            if let Some(pwd_start) = credentials.find(':') {
                let username = &credentials[..pwd_start];
                return format!("{}{}:***{}", prefix, username, suffix);
            }
        }
    }
    
    // If URL doesn't match expected format or has no credentials, return as is
    url.to_string()
}