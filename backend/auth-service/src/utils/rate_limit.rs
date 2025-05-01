//! Redis-based rate limiting utility for BuildHub Auth Service.
//!
//! Provides async functions to check and increment rate limits for endpoints like login and registration.
//! Uses atomic Redis operations for accuracy and resilience in distributed environments.

use redis::AsyncCommands;
use redis::Client;

/// Checks and increments the rate limit counter for a given key in Redis.
///
/// Returns `Ok(true)` if the request is allowed, `Ok(false)` if the rate limit is exceeded, or a Redis error.
///
/// # Arguments
/// * `redis` - Redis client reference.
/// * `key` - The Redis key to use for rate limiting (e.g., "rate:login:{ip}").
/// * `max_attempts` - Maximum allowed attempts in the window.
/// * `window_secs` - Window size in seconds.
///
/// # Example
/// ```ignore
/// let allowed = check_and_increment(&redis, "rate:login:127.0.0.1", 5, 60).await?;
/// if !allowed { /* block request */ }
/// ```
pub async fn check_and_increment(
    redis: &Client,
    key: &str,
    max_attempts: u32,
    window_secs: usize,
) -> redis::RedisResult<bool> {
    let mut conn = redis.get_async_connection().await?;
    let count: u32 = conn.incr(key, 1).await?;
    if count == 1 {
        // Set expiry only on first increment to start the window
        let _: () = conn.expire(key, window_secs).await?;
    }
    Ok(count <= max_attempts)
}