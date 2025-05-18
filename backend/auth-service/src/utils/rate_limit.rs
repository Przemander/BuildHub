//! Redis-based rate limiting utility for BuildHub Auth Service.
//!
//! This module provides a robust, production-ready implementation of the token bucket
//! rate limiting algorithm using Redis as a backend store. It's designed for:
//!
//! - High concurrency environments with atomic Redis operations
//! - Distributed systems where multiple service instances share limits
//! - Precise rate control with configurable windows and attempt limits
//! - Resilience against Redis connection issues
//!
//! # Algorithm
//!
//! The implementation uses a sliding window approach:
//! 1. Each request atomically increments a counter for the specific rate limit key
//! 2. If it's the first hit, an expiration time is set for the window
//! 3. Once the window expires, the counter automatically resets
//!
//! # Usage Example
//!
//! ```rust
//! use crate::utils::rate_limit::check_and_increment;
//!
//! async fn handle_login(redis_client: &redis::Client, username: &str) -> Result<(), Error> {
//!     // Define a unique key combining the endpoint and identifier
//!     let key = format!("rate:login:{}", username);
//!     
//!     // Check if we're within rate limits (5 attempts per minute)
//!     let within_limits = check_and_increment(redis_client, &key, 5, 60).await?;
//!     
//!     if !within_limits {
//!         return Err(Error::RateLimitExceeded);
//!     }
//!     
//!     // Process login request...
//!     Ok(())
//! }
//! ```

use redis::AsyncCommands;

#[cfg(test)]
/// Redis key prefix for rate limiting counters.
pub const RATE_LIMIT_PREFIX: &str = "rate_limit:";

/// Checks and increments the rate-limit counter in Redis.
///
/// This function performs an atomic increment operation and checks if the 
/// current count exceeds the configured maximum attempts. It automatically
/// sets an expiration time on new counters to implement the sliding window.
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
///
/// # Examples
///
/// ```rust
/// let client = redis::Client::open("redis://127.0.0.1/")?;
/// let key = "rate_limit:login:127.0.0.1";
/// 
/// // Allow 5 login attempts per minute from this IP
/// match check_and_increment(&client, &key, 5, 60).await {
///     Ok(true) => println!("Request allowed, within rate limit"),
///     Ok(false) => println!("Request denied, rate limit exceeded"),
///     Err(e) => println!("Redis error: {}", e),
/// }
/// ```
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

    /// Retrieves the current rate limit counter value for a key.
    ///
    /// Testing utility function to verify rate limit behavior.
    async fn get_counter(
        client: &redis::Client,
        key: &str,
    ) -> Result<Option<u32>, redis::RedisError> {
        let mut conn = client.get_async_connection().await?;
        
        // Get the current count if the key exists
        let exists: bool = conn.exists(key).await?;
        if !exists {
            return Ok(None);
        }
        
        let count: u32 = conn.get(key).await?;
        Ok(Some(count))
    }

    /// Retrieves the time remaining (in seconds) before a rate limit expires.
    ///
    /// Testing utility function to verify rate limit expiration behavior.
    async fn get_time_to_reset(
        client: &redis::Client,
        key: &str,
    ) -> Result<Option<usize>, redis::RedisError> {
        let mut conn = client.get_async_connection().await?;
        
        // Get the TTL for the key
        let ttl: isize = conn.ttl(key).await?;
        
        // TTL of -2 means the key doesn't exist, -1 means it has no expiration
        match ttl {
            -2 => Ok(None),          // Key doesn't exist
            -1 => Ok(None),          // Key has no expiration (shouldn't happen with our usage)
            ttl if ttl > 0 => Ok(Some(ttl as usize)),
            _ => Ok(None),           // Handle unexpected values
        }
    }

    /// Resets the rate limit counter for a specific key.
    ///
    /// Testing utility function to clean up rate limits.
    async fn reset_counter(
        client: &redis::Client,
        key: &str,
    ) -> Result<bool, redis::RedisError> {
        let mut conn = client.get_async_connection().await?;
        let deleted: usize = conn.del(key).await?;
        Ok(deleted > 0)
    }

    /// Creates a rate limit key with consistent formatting.
    ///
    /// Testing utility function for key generation.
    fn create_rate_limit_key(namespace: &str, identifier: &str) -> String {
        format!("{}{}:{}", RATE_LIMIT_PREFIX, namespace, identifier)
    }

    /// Helper to create a Redis client pointing at localhost.
    async fn make_redis_client() -> Client {
        Client::open("redis://127.0.0.1/")
            .expect("Failed to connect to Redis; ensure Redis is running for tests")
    }

    /// Helper to generate a unique test key to prevent test interference.
    fn unique_test_key() -> String {
        format!("{}test:{}", RATE_LIMIT_PREFIX, Uuid::new_v4())
    }

    /// Helper to clean up keys after tests.
    async fn cleanup_key(client: &Client, key: &str) {
        if let Ok(mut conn) = client.get_async_connection().await {
            let _: Result<(), _> = conn.del(key).await;
        }
    }

    #[tokio::test]
    async fn allows_within_limit() {
        // Arrange
        let client = make_redis_client().await;
        let key = unique_test_key();

        // Act & Assert - Allow up to 3 attempts within the window
        for i in 1..=3 {
            let ok = check_and_increment(&client, &key, 3, 60)
                .await
                .expect("Redis operation failed");
            assert!(ok, "Expected attempt {} to be allowed", i);
        }

        // Clean up
        cleanup_key(&client, &key).await;
    }

    #[tokio::test]
    async fn blocks_when_exceeding_limit() {
        // Arrange
        let client = make_redis_client().await;
        let key = unique_test_key();

        // Act & Assert - First attempt is allowed
        assert!(
            check_and_increment(&client, &key, 1, 60).await.unwrap(),
            "First attempt should be allowed"
        );
        
        // Second attempt exceeds limit
        assert!(
            !check_and_increment(&client, &key, 1, 60).await.unwrap(),
            "Second attempt should be blocked"
        );

        // Clean up
        cleanup_key(&client, &key).await;
    }

    #[tokio::test]
    async fn resets_after_window() {
        // Arrange
        let client = make_redis_client().await;
        let key = unique_test_key();

        // Act & Assert - Use a short window to test expiration
        assert!(
            check_and_increment(&client, &key, 1, 1).await.unwrap(),
            "First attempt should be allowed"
        );
        assert!(
            !check_and_increment(&client, &key, 1, 1).await.unwrap(),
            "Second attempt should be blocked"
        );

        // Wait for the window to expire (add a little buffer)
        sleep(Duration::from_millis(1100)).await;

        // Counter should reset after TTL
        assert!(
            check_and_increment(&client, &key, 1, 1).await.unwrap(),
            "Attempt after expiration should be allowed"
        );

        // Clean up
        cleanup_key(&client, &key).await;
    }

    #[tokio::test]
    async fn get_counter_returns_correct_values() {
        // Arrange
        let client = make_redis_client().await;
        let key = unique_test_key();

        // Act & Assert - Key doesn't exist initially
        let count = get_counter(&client, &key).await.unwrap();
        assert_eq!(count, None, "Counter should not exist initially");

        // Increment counter
        check_and_increment(&client, &key, 5, 30).await.unwrap();
        let count = get_counter(&client, &key).await.unwrap();
        assert_eq!(count, Some(1), "Counter should be 1 after first increment");

        // Increment again
        check_and_increment(&client, &key, 5, 30).await.unwrap();
        let count = get_counter(&client, &key).await.unwrap();
        assert_eq!(count, Some(2), "Counter should be 2 after second increment");

        // Clean up
        cleanup_key(&client, &key).await;
    }

    #[tokio::test]
    async fn get_time_to_reset_returns_correct_values() {
        // Arrange
        let client = make_redis_client().await;
        let key = unique_test_key();

        // Act & Assert - Key doesn't exist initially
        let ttl = get_time_to_reset(&client, &key).await.unwrap();
        assert_eq!(ttl, None, "TTL should not exist for nonexistent key");

        // Set key with 2 second expiration
        check_and_increment(&client, &key, 5, 2).await.unwrap();
        
        // TTL should be approximately 2 seconds (allow for small timing differences)
        let ttl = get_time_to_reset(&client, &key).await.unwrap();
        assert!(ttl.is_some(), "TTL should exist after setting key");
        let ttl = ttl.unwrap();
        assert!(ttl > 0 && ttl <= 2, "TTL should be between 0 and 2 seconds");

        // Wait for expiration
        sleep(Duration::from_millis(2100)).await;
        
        // Key should be gone
        let ttl = get_time_to_reset(&client, &key).await.unwrap();
        assert_eq!(ttl, None, "TTL should not exist after expiration");

        // Clean up (not needed, but for consistency)
        cleanup_key(&client, &key).await;
    }

    #[tokio::test]
    async fn reset_counter_works_correctly() {
        // Arrange
        let client = make_redis_client().await;
        let key = unique_test_key();

        // Act & Assert - Key doesn't exist initially
        let reset = reset_counter(&client, &key).await.unwrap();
        assert!(!reset, "Resetting nonexistent key should return false");

        // Set key and verify it exists
        check_and_increment(&client, &key, 5, 60).await.unwrap();
        let count = get_counter(&client, &key).await.unwrap();
        assert_eq!(count, Some(1), "Counter should exist after increment");

        // Reset counter
        let reset = reset_counter(&client, &key).await.unwrap();
        assert!(reset, "Resetting existing key should return true");

        // Verify counter is gone
        let count = get_counter(&client, &key).await.unwrap();
        assert_eq!(count, None, "Counter should not exist after reset");
    }

    #[test]
    fn create_rate_limit_key_formats_correctly() {
        // Arrange
        let namespace = "login";
        let identifier = "test_user";
        
        // Act
        let key = create_rate_limit_key(namespace, identifier);
        
        // Assert
        assert_eq!(key, "rate_limit:login:test_user");
    }
}