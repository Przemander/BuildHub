//! Redis-based rate limiting utility.
//!
//! Provides functions to check and increment rate limits for endpoints like login and registration.

use redis::AsyncCommands;
use redis::Client;

/// Checks and increments the rate limit counter for a given key.
/// Returns `Ok(true)` if the request is allowed, `Ok(false)` if rate limit exceeded, or a Redis error.
///
/// # Arguments
/// * `redis` - Redis client reference.
/// * `key` - The Redis key to use for rate limiting (e.g., "rate:login:{ip}").
/// * `max_attempts` - Maximum allowed attempts in the window.
/// * `window_secs` - Window size in seconds.
pub async fn check_and_increment(
    redis: &Client,
    key: &str,
    max_attempts: u32,
    window_secs: usize,
) -> redis::RedisResult<bool> {
    let mut conn = redis.get_async_connection().await?;
    let count: u32 = conn.incr(key, 1).await?;
    if count == 1 {
        let _: () = conn.expire(key, window_secs).await?;
    }
    Ok(count <= max_attempts)
}