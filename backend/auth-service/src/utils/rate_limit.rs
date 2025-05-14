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

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use tokio::time::{sleep, Duration};
    use uuid::Uuid;

    /// Helper to get a Redis client pointing at localhost.
    async fn make_redis_client() -> Client {
        Client::open("redis://127.0.0.1/").expect("Redis must be running")
    }

    #[tokio::test]
    async fn allows_within_limit() {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();
        // max_attempts = 3, window_secs = 60
        assert!(check_and_increment(&client, &key, 3, 60).await.unwrap());
        assert!(check_and_increment(&client, &key, 3, 60).await.unwrap());
        assert!(check_and_increment(&client, &key, 3, 60).await.unwrap());
    }

    #[tokio::test]
    async fn blocks_when_exceeding_limit() {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();
        // max_attempts = 1
        assert!(check_and_increment(&client, &key, 1, 60).await.unwrap());
        // second hit should be false
        assert!(!check_and_increment(&client, &key, 1, 60).await.unwrap());
    }

    #[tokio::test]
    async fn resets_after_window() {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();
        // max_attempts = 1, very short window
        assert!(check_and_increment(&client, &key, 1, 1).await.unwrap());
        // once more before expiry → blocked
        assert!(!check_and_increment(&client, &key, 1, 1).await.unwrap());
        // wait past the TTL
        sleep(Duration::from_secs(2)).await;
        // counter should have expired and reset
        assert!(check_and_increment(&client, &key, 1, 1).await.unwrap());
    }
}