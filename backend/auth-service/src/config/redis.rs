//! Redis connection and utility functions.
//!
//! This module provides functionality for connecting to Redis and
//! performing common operations such as key-value storage, deletion,
//! setting expiration, and token blacklisting. 
//!
//! # Features
//!
//! - Connection initialization with error handling
//! - Health checking via PING commands
//! - Token blacklisting for JWT invalidation
//! - Comprehensive instrumentation (metrics and tracing)
//! - Structured error handling with context preservation
//!
//! # Usage Example
//!
//! ```
//! use app::config::redis;
//!
//! async fn example() -> Result<(), redis::CacheError> {
//!     let client = redis::init_redis()?;
//!     let is_healthy = redis::check_redis_connection(&client).await;
//!
//!     // Block a JWT token for 30 minutes
//!     redis::block_token(&client, "jwt.token.example", 1800).await?;
//!
//!     // Check if token is blocked
//!     let is_blocked = redis::is_token_blocked(&client, "jwt.token.example").await?;
//!     assert!(is_blocked);
//!
//!     Ok(())
//! }
//! ```

use crate::utils::errors::CacheError;
use crate::utils::metrics::{REDIS_HEALTH, REDIS_OPERATIONS};
use crate::{log_debug, log_error, log_info};
use redis::{AsyncCommands, Client};
use std::env;
use tracing_error::SpanTrace;

/// Type alias for Redis async connection.
pub type RedisConnection = redis::aio::Connection;

/// Environment variable name for Redis URL.
const REDIS_URL_ENV: &str = "REDIS_URL";

/// Value stored in Redis to indicate a token is blocked.
const TOKEN_BLOCKED_VALUE: &str = "blocked";

/// Initializes the Redis client using the REDIS_URL environment variable.
///
/// # Returns
/// * `Ok(Client)` if successfully initialized.
/// * `Err(CacheError)` if the environment variable is missing or the URL is invalid.
///
/// # Environment Variables
/// * `REDIS_URL`: Required. The Redis connection string.
pub fn init_redis() -> Result<Client, CacheError> {
    let redis_url = env::var(REDIS_URL_ENV).map_err(|e| {
        log_error!("Redis", &format!("Missing REDIS_URL: {}", e), "initialization_error");
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    log_info!("Redis", &format!("Connecting to Redis: {}", mask_redis_url(&redis_url)), "initialization");

    let client = Client::open(redis_url).map_err(|e| {
        log_error!("Redis", &format!("Invalid Redis URL: {}", e), "initialization_error");
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    log_debug!("Redis", "Client initialized successfully", "initialization");
    REDIS_OPERATIONS
        .with_label_values(&["init", "success"])
        .inc();
    Ok(client)
}

/// Checks the Redis connection by sending a PING command.
///
/// Returns true only if the server replies with PONG.
///
/// # Arguments
/// * `redis_client` - The Redis client to check.
///
/// # Returns
/// * `true` if the connection is healthy (PING → PONG).
/// * `false` if there are connection issues or unexpected responses.
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    let mut con = match redis_client.get_async_connection().await {
        Ok(con) => con,
        Err(e) => {
            log_error!("Redis", &format!("Failed to connect to server: {}", e), "connectivity_error");
            REDIS_OPERATIONS
                .with_label_values(&["connection", "failure"])
                .inc();
            REDIS_HEALTH.set(0.0);
            return false;
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut con).await {
        Ok(resp) if resp == "PONG" => {
            log_info!("Redis", "Redis connection check successful", "health_check");
            REDIS_OPERATIONS
                .with_label_values(&["ping", "success"])
                .inc();
            REDIS_HEALTH.set(1.0);
            true
        }
        Ok(unexpected) => {
            log_error!("Redis", &format!("Unexpected PING response: {}", unexpected), "health_check_error");
            REDIS_OPERATIONS
                .with_label_values(&["ping", "unexpected_response"])
                .inc();
            REDIS_HEALTH.set(0.0);
            false
        }
        Err(e) => {
            log_error!("Redis", &format!("PING command failed: {}", e), "health_check_error");
            REDIS_OPERATIONS
                .with_label_values(&["ping", "failure"])
                .inc();
            REDIS_HEALTH.set(0.0);
            false
        }
    }
}

/// Gets a Redis connection from the client.
///
/// # Arguments
/// * `client` - The Redis client.
///
/// # Returns
/// * `Ok(Connection)` if connection succeeded.
/// * `Err(CacheError)` if connection failed.
pub async fn get_redis_connection(client: &Client) -> Result<RedisConnection, CacheError> {
    client.get_async_connection().await.map_err(|e| {
        log_error!("Redis", &format!("Connection acquisition failed: {}", e), "connection_error");
        REDIS_OPERATIONS
            .with_label_values(&["get_connection", "failure"])
            .inc();
        CacheError::Connection {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })
}

/// Blocks a token by storing it in Redis with an expiration time.
/// The token itself is used as the key and "blocked" as the value.
///
/// # Arguments
/// * `redis` - The Redis client.
/// * `token` - The token to block.
/// * `exp` - Expiration time in seconds (usually set to the remaining token lifetime).
///
/// # Returns
/// * `Ok(())` if token was successfully blocked.
/// * `Err(CacheError)` if operation failed.
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), CacheError> {
    log_debug!("Token Management", &format!("Blocking token (length: {})", token.len()), "security_operation");
    let mut conn = get_redis_connection(redis).await?;

    conn.set_ex::<&str, &str, ()>(token, TOKEN_BLOCKED_VALUE, exp)
        .await
        .map_err(|e| {
            log_error!("Redis", &format!("Failed to block token: {}", e), "token_operation_error");
            REDIS_OPERATIONS
                .with_label_values(&["block_token", "failure"])
                .inc();
            CacheError::Operation {
                source: Box::new(e),
                span: SpanTrace::capture(),
            }
        })?;

    log_debug!("Token Management", "Token successfully blocked", "security_operation");
    REDIS_OPERATIONS
        .with_label_values(&["block_token", "success"])
        .inc();
    Ok(())
}

/// Checks if a token is blocked by searching for it in Redis.
///
/// Returns true if the token exists (i.e. is blocked).
///
/// # Arguments
/// * `redis` - The Redis client.
/// * `token` - The token to check.
///
/// # Returns
/// * `Ok(bool)` - true if token is blocked, false otherwise.
/// * `Err(CacheError)` if operation failed.
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, CacheError> {
    log_debug!("Token Management", &format!("Checking if token is blocked (length: {})", token.len()), "security_check");
    let mut conn = get_redis_connection(redis).await?;
    
    let exists: bool = conn.exists(token).await.map_err(|e| {
        log_error!("Redis", &format!("Token validation check failed: {}", e), "token_operation_error");
        REDIS_OPERATIONS
            .with_label_values(&["is_token_blocked", "failure"])
            .inc();
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    if exists {
        log_debug!("Token Management", "Token found in block list", "security_check");
    } else {
        log_debug!("Token Management", "Token not found in block list", "security_check");
    }
    
    REDIS_OPERATIONS
        .with_label_values(&[
            "is_token_blocked",
            if exists { "blocked" } else { "not_blocked" },
        ])
        .inc();
    
    Ok(exists)
}

/// Removes sensitive information from Redis URLs for safe logging.
///
/// # Arguments
/// * `url` - Redis URL possibly containing auth credentials
///
/// # Returns
/// * String with passwords masked with asterisks
fn mask_redis_url(url: &str) -> String {
    // Simple regex-free approach to mask passwords in Redis URLs
    // redis://user:password@host:port -> redis://user:****@host:port
    if let Some(at_pos) = url.find('@') {
        if let Some(auth_start) = url.find("://") {
            let auth_start = auth_start + 3;
            if at_pos > auth_start {
                if let Some(pwd_start) = url[auth_start..at_pos].find(':') {
                    let pwd_start = auth_start + pwd_start + 1;
                    return format!(
                        "{}{}{}",
                        &url[0..pwd_start],
                        "****",
                        &url[at_pos..]
                    );
                }
            }
        }
    }
    // If no password to mask or format not recognized, return original
    // but strip any query parameters which might contain secrets
    if let Some(query_pos) = url.find('?') {
        return format!("{}?[PARAMS_REDACTED]", &url[0..query_pos]);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use std::env;
    use tokio;

    /// Create a test Redis client for a non-existent server
    fn get_invalid_client() -> Client {
        // Use a non-standard port to ensure it doesn't connect
        Client::open("redis://127.0.0.1:63999/").unwrap()
    }
    
    /// Set up the Redis URL environment variable
    fn setup_test_env() {
        env::set_var(REDIS_URL_ENV, "redis://127.0.0.1:6379/");
    }

    #[test]
    fn test_mask_redis_url() {
        // Test with password
        let masked = mask_redis_url("redis://user:secretpwd@127.0.0.1:6379/0");
        assert_eq!(masked, "redis://user:****@127.0.0.1:6379/0");
        
        // Test without credentials
        let masked = mask_redis_url("redis://127.0.0.1:6379/0");
        assert_eq!(masked, "redis://127.0.0.1:6379/0");
        
        // Test with query parameters
        let masked = mask_redis_url("redis://127.0.0.1:6379/0?secret=value");
        assert_eq!(masked, "redis://127.0.0.1:6379/0?[PARAMS_REDACTED]");
    }

    /// Ensure init_redis errors if REDIS_URL is not set.
    #[test]
    fn init_redis_missing_url() {
        env::remove_var(REDIS_URL_ENV);
        let err = init_redis().unwrap_err();
        match err {
            CacheError::Connection { .. } => {}
            _ => panic!("expected CacheError::Connection"),
        }
    }

    /// Ensure init_redis errors on invalid URL.
    #[test]
    fn init_redis_invalid_url() {
        env::set_var(REDIS_URL_ENV, "not-a-valid-url");
        let err = init_redis().unwrap_err();
        match err {
            CacheError::Connection { .. } => {}
            _ => panic!("expected CacheError::Connection"),
        }
    }

    /// Happy path when REDIS_URL is valid (requires local Redis).
    #[test]
    #[ignore] // requires a running Redis on REDIS_URL
    fn init_redis_success() {
        setup_test_env();
        init_redis().unwrap();
    }

    /// PING returns false for unreachable server.
    #[tokio::test]
    async fn check_redis_ping_failure() {
        let client = get_invalid_client();
        assert_eq!(check_redis_connection(&client).await, false);
    }

    /// PING returns true when Redis is up.
    #[tokio::test]
    #[ignore] // requires a running Redis on REDIS_URL
    async fn check_redis_ping_success() {
        setup_test_env();
        let client = init_redis().unwrap();
        assert_eq!(check_redis_connection(&client).await, true);
    }

    /// get_redis_connection maps errors properly.
    #[tokio::test]
    async fn get_redis_connection_failure() {
        let client = get_invalid_client();
        let result = get_redis_connection(&client).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            CacheError::Connection { .. } => {}
            _ => panic!("expected CacheError::Connection"),
        }
    }

    /// block_token and is_token_blocked roundtrip (requires Redis).
    #[tokio::test]
    #[ignore] // requires a running Redis on REDIS_URL
    async fn block_and_check_token() {
        setup_test_env();
        let client = init_redis().unwrap();
        
        // Generate a unique token for testing
        let token = format!("test_token_{}", uuid::Uuid::new_v4());
        
        // Initially token should not be blocked
        let initially_blocked = is_token_blocked(&client, &token).await.unwrap();
        assert!(!initially_blocked, "Token should not be blocked initially");
        
        // Block the token
        block_token(&client, &token, 30).await.unwrap();
        
        // Now token should be blocked
        let blocked_after = is_token_blocked(&client, &token).await.unwrap();
        assert!(blocked_after, "Token should be blocked after calling block_token");
        
        // Clean up
        let mut conn = client.get_async_connection().await.unwrap();
        let _: () = conn.del(&token).await.unwrap();
    }
    
    /// Test that block_token fails appropriately with unavailable Redis
    #[tokio::test]
    async fn block_token_fails_with_unavailable_redis() {
        let client = get_invalid_client();
        let result = block_token(&client, "any-token", 60).await;
        assert!(result.is_err(), "block_token should fail with unavailable Redis");
    }
    
    /// Test that is_token_blocked fails appropriately with unavailable Redis
    #[tokio::test]
    async fn is_token_blocked_fails_with_unavailable_redis() {
        let client = get_invalid_client();
        let result = is_token_blocked(&client, "any-token").await;
        assert!(result.is_err(), "is_token_blocked should fail with unavailable Redis");
    }
}