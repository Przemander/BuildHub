//! Redis-based rate limiting utility for BuildHub Auth Service.
//!
//! Provides async functions to check and increment rate limits for endpoints like login and registration.
//! Uses atomic Redis operations for accuracy and resilience in distributed environments.

use redis::AsyncCommands;

/// Returns `Ok(true)` if the hit‐count ≤ `max_attempts`, else `Ok(false)`.
/// Sets a TTL only on the very first hit.
pub async fn check_and_increment(
    client: &redis::Client,
    key: &str,
    max_attempts: u32,
    window_secs: usize,
) -> Result<bool, redis::RedisError> {
    // 1) get a connection
    let mut conn = client.get_async_connection().await?;
    // 2) atomically increment the counter
    let current: u32 = conn.incr(key, 1).await?;
    // 3) on first creation, set the TTL
    if current == 1 {
        let _: () = conn.expire(key, window_secs).await?;
    }
    // 4) allow only while count ≤ max_attempts
    Ok(current <= max_attempts)
}