//! Redis-based rate limiting utility for BuildHub Auth Service.
//!
//! Provides an async function to check and increment rate limits for endpoints like login and registration.
//! Uses atomic Redis operations for accuracy and resilience in distributed and concurrent environments.

use redis::AsyncCommands;

/// Checks and increments the rate-limit counter in Redis.
///
/// # Arguments
/// - `client`: Redis client instance.
/// - `key`: Unique key identifying the rate limit bucket (e.g., endpoint+user).
/// - `max_attempts`: Maximum allowed attempts in the window.
/// - `window_secs`: Duration of the rate-limit window in seconds.
///
/// # Returns
/// - `Ok(true)` if the attempt count is within the limit.
/// - `Ok(false)` if the limit has been exceeded.
/// - `Err(RedisError)` on Redis communication errors.
#[inline]
pub async fn check_and_increment(
    client: &redis::Client,
    key: &str,
    max_attempts: u32,
    window_secs: usize,
) -> Result<bool, redis::RedisError> {
    // Acquire an async connection
    let mut conn = client.get_async_connection().await?;

    // Atomically increment the counter
    let count: u32 = conn.incr(key, 1).await?;

    // On first hit, set the expiration (window)
    if count == 1 {
        let _: () = conn.expire(key, window_secs).await?;
    }

    // Return whether current count is within allowed attempts
    Ok(count <= max_attempts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use tokio::time::{sleep, Duration};
    use uuid::Uuid;

    /// Helper to create a Redis client pointing at localhost.
    async fn make_redis_client() -> Client {
        Client::open("redis://127.0.0.1/")
            .expect("Failed to connect to Redis; ensure Redis is running for tests")
    }

    #[tokio::test]
    async fn allows_within_limit() {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();

        // Allow up to 3 attempts within the window
        for _ in 0..3 {
            let ok = check_and_increment(&client, &key, 3, 60)
                .await
                .expect("Redis operation failed");
            assert!(ok, "Expected attempt to be allowed");
        }
    }

    #[tokio::test]
    async fn blocks_when_exceeding_limit() {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();

        // First attempt is allowed
        assert!(check_and_increment(&client, &key, 1, 60).await.unwrap());
        // Second attempt exceeds limit
        assert!(!check_and_increment(&client, &key, 1, 60).await.unwrap());
    }

    #[tokio::test]
    async fn resets_after_window() {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();

        // Use a short window to test expiration
        assert!(check_and_increment(&client, &key, 1, 1).await.unwrap());
        assert!(!check_and_increment(&client, &key, 1, 1).await.unwrap());

        // Wait for the window to expire
        sleep(Duration::from_secs(2)).await;

        // Counter should reset after TTL
        assert!(check_and_increment(&client, &key, 1, 1).await.unwrap());
    }
}
