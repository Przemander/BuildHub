//! Redis configuration and cache management.
//!
//! Provides reliable Redis connectivity with essential caching operations,
//! rate limiting, and token management capabilities.

use redis::{AsyncCommands, Client, Script};
use std::env;
use tracing::{error, info, warn};

use crate::{
    metrics,
    utils::errors::CacheError,
};

// =============================================================================
// CONFIGURATION CONSTANTS
// =============================================================================

const REDIS_URL_ENV: &str = "REDIS_URL";
const TOKEN_BLOCKED_VALUE: &str = "blocked";
const ACTIVATION_CODE_TTL: u64 = 86_400; // 24 hours
const PASSWORD_RESET_TTL: u64 = 1_800; // 30 minutes


// =============================================================================
// CLIENT INITIALIZATION
// =============================================================================

/// Initializes Redis client with proper error handling.
///
/// Returns `Ok(Client)` if successful, or `Err(CacheError)` if:
/// - REDIS_URL environment variable is missing
/// - Redis URL is invalid
pub fn init_redis() -> Result<Client, CacheError> {
    let redis_url = env::var(REDIS_URL_ENV).map_err(|e| {
        error!("Missing {} environment variable", REDIS_URL_ENV);
        CacheError::Connection {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    info!("Initializing Redis client");

    let client = Client::open(redis_url).map_err(|e| {
        error!("Invalid Redis URL: {}", e);
        CacheError::Connection {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    info!("Redis client initialized successfully");
    Ok(client)
}

/// Checks Redis connection health.
///
/// Performs a PING command to verify connectivity.
/// Returns `true` if healthy, `false` otherwise.
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    let mut connection = match redis_client.get_async_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to acquire Redis connection: {}", e);
            metrics::external::redis_failure("health_check");
            return false;
        }
    };

    match redis::cmd("PING")
        .query_async::<_, String>(&mut connection)
        .await
    {
        Ok(response) if response == "PONG" => {
            metrics::external::redis_success("health_check");
            true
        }
        Ok(response) => {
            warn!("Unexpected PING response: {}", response);
            metrics::external::redis_failure("health_check");
            false
        }
        Err(e) => {
            error!("PING command failed: {}", e);
            metrics::external::redis_failure("health_check");
            false
        }
    }
}

// =============================================================================
// JWT TOKEN MANAGEMENT
// =============================================================================

/// Blocks a JWT token until its expiration.
///
/// Used for logout functionality to invalidate tokens before they expire naturally.
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), CacheError> {
    let mut conn = get_connection(redis).await?;

    conn.set_ex::<&str, &str, ()>(token, TOKEN_BLOCKED_VALUE, exp)
        .await
        .map_err(|e| {
            error!("Failed to block token: {}", e);
            metrics::external::redis_failure("block_token");
            CacheError::Operation {
                source: Box::new(e),
                span: tracing_error::SpanTrace::capture(),
            }
        })?;

    metrics::external::redis_success("block_token");
    info!("Token blocked successfully");
    Ok(())
}

/// Checks if a JWT token is blocked.
///
/// Returns `true` if the token is in the blocklist, `false` otherwise.
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, CacheError> {
    let mut conn = get_connection(redis).await?;

    let is_blocked: bool = conn.exists(token).await.map_err(|e| {
        error!("Token blacklist check failed: {}", e);
        metrics::external::redis_failure("check_token_blocked");
        CacheError::Operation {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    metrics::external::redis_success("check_token_blocked");
    Ok(is_blocked)
}

// =============================================================================
// ACTIVATION CODES
// =============================================================================

/// Stores an activation code with 24-hour expiration.
///
/// The code is linked to an email address for account activation.
pub async fn store_activation_code(
    redis: &Client,
    email: &str,
    code: &str,
) -> Result<(), CacheError> {
    let mut conn = get_connection(redis).await?;
    let key = format!("activation:code:{}", code);

    conn.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_TTL as usize)
        .await
        .map_err(|e| {
            error!("Failed to store activation code: {}", e);
            metrics::external::redis_failure("store_activation_code");
            CacheError::Operation {
                source: Box::new(e),
                span: tracing_error::SpanTrace::capture(),
            }
        })?;

    metrics::external::redis_success("store_activation_code");
    info!("Activation code stored for email");
    Ok(())
}

/// Verifies and consumes an activation code.
///
/// Returns the associated email if valid, error if expired or invalid.
/// The code is deleted after successful verification (single-use).
pub async fn verify_activation_code(redis: &Client, code: &str) -> Result<String, CacheError> {
    let mut conn = get_connection(redis).await?;
    let key = format!("activation:code:{}", code);

    // Get the email associated with the code
    let email: Option<String> = conn.get(&key).await.map_err(|e| {
        error!("Failed to retrieve activation code: {}", e);
        metrics::external::redis_failure("verify_activation_code");
        CacheError::Operation {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    match email {
        Some(email) => {
            // Delete code to ensure single use
            if let Err(e) = conn.del::<_, ()>(&key).await {
                warn!("Failed to delete activation code (non-critical): {}", e);
            }

            metrics::external::redis_success("verify_activation_code");
            Ok(email)
        }
        None => {
            metrics::external::redis_failure("verify_activation_code");
            Err(CacheError::KeyNotFound {
                key: code.to_string(),
                span: tracing_error::SpanTrace::capture(),
            })
        }
    }
}

// =============================================================================
// PASSWORD RESET TOKENS
// =============================================================================

/// Stores a password reset token with 30-minute expiration.
///
/// The token is linked to an email address for password reset.
pub async fn store_password_reset_token(
    redis: &Client,
    email: &str,
    token: &str,
) -> Result<(), CacheError> {
    let mut conn = get_connection(redis).await?;
    let key = format!("password_reset:token:{}", token);

    conn.set_ex::<_, _, ()>(key, email, PASSWORD_RESET_TTL as usize)
        .await
        .map_err(|e| {
            error!("Failed to store reset token: {}", e);
            metrics::external::redis_failure("store_reset_token");
            CacheError::Operation {
                source: Box::new(e),
                span: tracing_error::SpanTrace::capture(),
            }
        })?;

    metrics::external::redis_success("store_reset_token");
    info!("Reset token stored for email");
    Ok(())
}

/// Verifies a password reset token without consuming it.
///
/// Returns the associated email if valid, error if expired or invalid.
pub async fn verify_reset_token(redis: &Client, token: &str) -> Result<String, CacheError> {
    let mut conn = get_connection(redis).await?;
    let key = format!("password_reset:token:{}", token);

    let email: Option<String> = conn.get(&key).await.map_err(|e| {
        error!("Failed to retrieve reset token: {}", e);
        metrics::external::redis_failure("verify_reset_token");
        CacheError::Operation {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    match email {
        Some(email) => {
            metrics::external::redis_success("verify_reset_token");
            Ok(email)
        }
        None => {
            metrics::external::redis_failure("verify_reset_token");
            Err(CacheError::KeyNotFound {
                key: token.to_string(),
                span: tracing_error::SpanTrace::capture(),
            })
        }
    }
}

/// Invalidates a used password reset token.
///
/// Called after successful password reset to prevent token reuse.
pub async fn invalidate_reset_token(redis: &Client, token: &str) -> Result<(), CacheError> {
    let mut conn = get_connection(redis).await?;
    let key = format!("password_reset:token:{}", token);

    conn.del::<&str, ()>(&key).await.map_err(|e| {
        error!("Failed to delete reset token: {}", e);
        metrics::external::redis_failure("invalidate_reset_token");
        CacheError::Operation {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    metrics::external::redis_success("invalidate_reset_token");
    Ok(())
}

// =============================================================================
// RATE LIMITING
// =============================================================================

/// Checks and increments rate limit with sliding window using an atomic Lua script.
///
/// Returns `true` if within limit, `false` if limit exceeded.
/// The Lua script ensures that INCR and EXPIRE are performed atomically.
pub async fn check_and_increment_rate_limit(
    redis: &Client,
    key: &str,
    max_attempts: u32,
    window_seconds: usize,
) -> Result<bool, CacheError> {
    let mut conn = get_connection(redis).await?;
    let sanitized_key = sanitize_rate_limit_key(key);

    // Lua script for atomic INCR and EXPIRE.
    // 1. Increment the key.
    // 2. If the count is 1, set the expiration.
    // 3. Return the current count.
    let script = Script::new(r"
        local current = redis.call('INCR', KEYS[1])
        if tonumber(current) == 1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return current
    ");

    // Execute the script atomically.
    let current_count: u32 = script
        .key(&sanitized_key)
        .arg(window_seconds)
        .invoke_async(&mut conn)
        .await
        .map_err(|e| {
            error!("Rate limit Lua script failed: {}", e);
            metrics::external::redis_failure("rate_limit_check");
            CacheError::Operation {
                source: Box::new(e),
                span: tracing_error::SpanTrace::capture(),
            }
        })?;

    let within_limit = current_count <= max_attempts;

    if within_limit {
        metrics::external::redis_success("rate_limit_check");
    } else {
        // Log only when the limit is first exceeded to reduce noise.
        if current_count == max_attempts + 1 {
            warn!(
                "Rate limit exceeded for key: {} ({}/{})",
                sanitized_key, current_count, max_attempts
            );
        }
        metrics::external::redis_failure("rate_limit_exceeded");
    }

    Ok(within_limit)
}

/// Clears a rate limit counter for a given key.
///
/// Typically called after a successful operation (e.g., login) to reset
/// the failed attempts counter. This is often a "fire-and-forget" operation.
pub async fn clear_rate_limit_counter(redis: &Client, key: &str) -> Result<(), CacheError> {
    let mut conn = get_connection(redis).await?;
    let sanitized_key = sanitize_rate_limit_key(key);

    conn.del::<_, ()>(&sanitized_key).await.map_err(|e| {
        error!("Failed to clear rate limit counter: {}", e);
        metrics::external::redis_failure("clear_rate_limit");
        CacheError::Operation {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })?;

    metrics::external::redis_success("clear_rate_limit");
    info!("Cleared rate limit counter for key: {}", sanitized_key);
    Ok(())
}


// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Gets an async Redis connection with error handling.
async fn get_connection(client: &Client) -> Result<redis::aio::Connection, CacheError> {
    client.get_async_connection().await.map_err(|e| {
        error!("Failed to acquire Redis connection: {}", e);
        metrics::external::redis_failure("connection_acquisition");
        CacheError::Connection {
            source: Box::new(e),
            span: tracing_error::SpanTrace::capture(),
        }
    })
}

/// Sanitizes rate limit keys to prevent injection.
fn sanitize_rate_limit_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_alphanumeric() || *c == ':' || *c == '.' || *c == '_' || *c == '-')
        .take(128) // Limit key length
        .collect()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to prevent race conditions when setting environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_init_redis_without_url() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::remove_var(REDIS_URL_ENV);
        let result = init_redis();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CacheError::Connection { .. }));
    }

    #[test]
    fn test_init_redis_with_invalid_url() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var(REDIS_URL_ENV, "not-a-valid-url");
        let result = init_redis();
        assert!(result.is_err());
        env::remove_var(REDIS_URL_ENV);
    }

    #[test]
    fn test_sanitize_rate_limit_key() {
        assert_eq!(sanitize_rate_limit_key("valid:key.123"), "valid:key.123");
        assert_eq!(sanitize_rate_limit_key("bad<>key"), "badkey");
        assert_eq!(sanitize_rate_limit_key("user@domain.com"), "userdomain.com");
        
        let long_key = "a".repeat(200);
        assert_eq!(sanitize_rate_limit_key(&long_key).len(), 128);
    }
}