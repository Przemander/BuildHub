//! Redis connection and utility functions.
//!
//! This module provides functionality for connecting to Redis and
//! performing common operations like token blacklisting,
//! key-value storage, and connection management.

use redis::{AsyncCommands, Client, RedisError};
use std::env;
use log::{error, info, debug};

use crate::utils::errors::ApiError;

/// Initialize the Redis client using the REDIS_URL environment variable.
///
/// # Returns
/// * `Ok(Client)` - Redis client if successfully initialized
/// * `Err(Box<dyn std::error::Error>)` - If URL is missing or invalid
pub fn init_redis() -> Result<Client, Box<dyn std::error::Error>> {
    let redis_url = env::var("REDIS_URL")?;
    info!("Connecting to Redis at: {}", redis_url);
    
    let client = Client::open(redis_url)?;
    debug!("Redis client initialized successfully");
    
    Ok(client)
}

/// Checks the Redis connection by sending a PING command.
///
/// This is useful for verifying the Redis server is actually responding
/// and the connection is working properly. Returns true only if 
/// the server responds with PONG.
///
/// # Arguments
/// * `redis_client` - The Redis client to check
///
/// # Returns
/// `true` if connection is successful, `false` otherwise
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    let mut con = match redis_client.get_async_connection().await {
        Ok(con) => con,
        Err(e) => {
            error!("Failed to connect to Redis: {}", e);
            return false;
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut con).await {
        Ok(pong) => {
            info!("Redis connection successful: {}", pong);
            true
        }
        Err(e) => {
            error!("Failed to connect to Redis: {:?}", e);
            false
        }
    }
}

/// Blocks a token by storing it in Redis with an expiration time.
///
/// This function is used to blacklist revoked JWT tokens until they
/// would naturally expire. The token itself is used as the key, and 
/// "blocked" as the value.
///
/// # Arguments
/// * `redis` - The Redis client
/// * `token` - The token to block
/// * `exp` - Expiration time in seconds (usually set to remaining token lifetime)
///
/// # Returns
/// * `Ok(())` - If the token was successfully blocked
/// * `Err(RedisError)` - If the Redis operation failed
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), RedisError> {
    debug!("Blocking token with expiration of {} seconds", exp);
    
    let mut conn = redis.get_async_connection().await?;
    conn.set_ex::<&str, &str, ()>(token, "blocked", exp).await?;
    
    debug!("Token successfully blocked");
    Ok(())
}

/// Check if a token is blocked in Redis.
///
/// Returns true if the token exists in Redis, indicating it has been revoked.
///
/// # Arguments
/// * `redis` - The Redis client
/// * `token` - The token to check
///
/// # Returns
/// * `Ok(bool)` - True if token is blocked, false if not
/// * `Err(RedisError)` - If the Redis operation failed
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, RedisError> {
    debug!("Checking if token is blocked");
    
    let mut conn = redis.get_async_connection().await?;
    let exists: bool = conn.exists(token).await?;
    
    if exists {
        debug!("Token is blocked");
    } else {
        debug!("Token is not blocked");
    }
    
    Ok(exists)
}

/// Returns an async Redis connection or an ApiError if unable to connect.
///
/// # Arguments
/// * `redis_client` - The Redis client
///
/// # Returns
/// * `Ok(Connection)` - Redis async connection
/// * `Err(ApiError)` - If connection fails
pub async fn get_redis_connection(redis_client: &Client) -> Result<redis::aio::Connection, ApiError> {
    redis_client.get_async_connection().await.map_err(|e| {
        error!("Failed to get Redis connection: {}", e);
        ApiError::internal_error(&format!("Failed to connect to Redis: {}", e))
    })
}

/// Deletes a key from Redis.
///
/// # Arguments
/// * `redis_conn` - Redis connection
/// * `key` - The key to delete
///
/// # Returns
/// * `Ok(())` - If deletion was successful
/// * `Err(ApiError)` - If the Redis operation failed
pub async fn delete_from_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
) -> Result<(), ApiError> {
    debug!("Deleting key from Redis: {}", key);
    
    redis_conn.del(key).await.map_err(|e| {
        error!("Failed to delete key from Redis: {}", e);
        ApiError::internal_error(&format!("Failed to delete key from Redis: {}", e))
    })
}

/// Stores a key-value pair in Redis with expiration.
///
/// This function uses Redis pipeline to atomically set the key and its expiration,
/// ensuring that all keys have an expiration time set.
///
/// # Arguments
/// * `redis_conn` - Redis connection
/// * `key` - The key to store
/// * `value` - The value to store
/// * `expiration_seconds` - How long until the key expires, in seconds
///
/// # Returns
/// * `Ok(())` - If storage was successful
/// * `Err(ApiError)` - If the Redis operation failed
pub async fn store_in_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
    value: &str,
    expiration_seconds: usize,
) -> Result<(), ApiError> {
    debug!("Storing key in Redis with expiration of {} seconds: {}", expiration_seconds, key);
    
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(key)
        .arg(value)
        .cmd("EXPIRE")
        .arg(key)
        .arg(expiration_seconds)
        .query_async::<_, ()>(redis_conn)
        .await
        .map_err(|e| {
            error!("Failed to store key in Redis: {}", e);
            ApiError::internal_error(&format!("Failed to store key in Redis: {}", e))
        })
}

/// Retrieves a value from Redis for a given key.
///
/// # Arguments
/// * `redis_conn` - Redis connection
/// * `key` - The key to look up
///
/// # Returns
/// * `Ok(Option<String>)` - The value if found, None if key doesn't exist
/// * `Err(ApiError)` - If the Redis operation failed
pub async fn get_from_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
) -> Result<Option<String>, ApiError> {
    debug!("Getting value from Redis for key: {}", key);
    
    let result: Option<String> = redis_conn.get(key).await.map_err(|e| {
        error!("Failed to get value from Redis: {}", e);
        ApiError::internal_error(&format!("Failed to retrieve data from Redis: {}", e))
    })?;
    
    if result.is_some() {
        debug!("Value found in Redis for key: {}", key);
    } else {
        debug!("No value found in Redis for key: {}", key);
    }
    
    Ok(result)
}

/// Sets the expiration time on an existing Redis key.
///
/// # Arguments
/// * `redis_conn` - Redis connection
/// * `key` - The key to set expiration on
/// * `expiration_seconds` - Seconds until expiration
///
/// # Returns
/// * `Ok(bool)` - true if expiration was set, false if key doesn't exist
/// * `Err(ApiError)` - If the Redis operation failed
pub async fn set_expiration(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
    expiration_seconds: usize,
) -> Result<bool, ApiError> {
    debug!("Setting expiration of {} seconds on key: {}", expiration_seconds, key);
    
    let result: bool = redis_conn.expire(key, expiration_seconds).await.map_err(|e| {
        error!("Failed to set expiration on Redis key: {}", e);
        ApiError::internal_error(&format!("Failed to set expiration: {}", e))
    })?;
    
    if result {
        debug!("Expiration successfully set on key: {}", key);
    } else {
        debug!("Key not found, couldn't set expiration: {}", key);
    }
    
    Ok(result)
}