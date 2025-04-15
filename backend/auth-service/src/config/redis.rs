//! Redis connection and utility functions.
//!
//! This module provides functionality for connecting to Redis and
//! performing common operations such as key-value storage, deletion,
//! setting expiration, and token blacklisting. Logging focuses on
//! critical events and errors while metrics record operation attempts,
//! successes, and failures.

use redis::{AsyncCommands, Client, RedisError};
use std::env;
use crate::{log_info, log_warn, log_error, log_debug};
use crate::utils::errors::ApiError;
// Metrics: adjust these metric names per your implementation.
use crate::utils::metrics::{REDIS_OPERATIONS, REDIS_HEALTH};

/// Initialize the Redis client using the REDIS_URL environment variable.
///
/// # Returns
/// * `Ok(Client)` if successfully initialized.
/// * `Err(Box<dyn std::error::Error>)` if the environment variable is missing or the URL is invalid.
pub fn init_redis() -> Result<Client, Box<dyn std::error::Error>> {
    let redis_url = env::var("REDIS_URL")?;
    log_info!("Redis", "Connecting to Redis", "success");
    
    let client = Client::open(redis_url)?;
    log_debug!("Redis", "Client initialized", "success");
    
    REDIS_OPERATIONS.with_label_values(&["init", "success"]).inc();
    Ok(client)
}

/// Checks the Redis connection by sending a PING command.
///
/// Returns true only if the server replies with PONG.
///
/// # Arguments
/// * `redis_client` - The Redis client to check.
pub async fn check_redis_connection(redis_client: &Client) -> bool {
    let mut con = match redis_client.get_async_connection().await {
        Ok(con) => con,
        Err(_) => {
            log_error!("Redis", "Connect to server", "failure");
            REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            return false;
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut con).await {
        Ok(resp) if resp == "PONG" => {
            log_info!("Redis", "Connection check", "success");
            REDIS_OPERATIONS.with_label_values(&["ping", "success"]).inc();
            true
        },
        Ok(_) | Err(_) => {
            log_error!("Redis", "PING command", "failure");
            REDIS_OPERATIONS.with_label_values(&["ping", "failure"]).inc();
            false
        }
    }
}

/// Blocks a token by storing it in Redis with an expiration time.
/// The token itself is used as the key and "blocked" as the value.
///
/// # Arguments
/// * `redis` - The Redis client.
/// * `token` - The token to block.
/// * `exp` - Expiration time in seconds (usually set to the remaining token lifetime).
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), RedisError> {
    log_debug!("Token Management", "Block token", "attempt");
    
    let mut conn = redis.get_async_connection().await?;
    conn.set_ex::<&str, &str, ()>(token, "blocked", exp).await?;
    
    log_debug!("Token Management", "Token successfully blocked", "success");
    REDIS_OPERATIONS.with_label_values(&["block_token", "success"]).inc();
    Ok(())
}

/// Checks if a token is blocked by searching for it in Redis.
///
/// Returns true if the token exists (i.e. is blocked).
///
/// # Arguments
/// * `redis` - The Redis client.
/// * `token` - The token to check.
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, RedisError> {
    log_debug!("Token Management", "Check token status", "attempt");
    
    let mut conn = redis.get_async_connection().await?;
    let exists: bool = conn.exists(token).await?;
    
    if exists {
        log_debug!("Token Management", "Token is blocked", "success");
    } else {
        log_debug!("Token Management", "Token is valid", "success");
    }
    REDIS_OPERATIONS.with_label_values(&["is_token_blocked", if exists { "blocked" } else { "not_blocked" }]).inc();
    Ok(exists)
}

/// Returns an async Redis connection or an ApiError if unable to connect.
///
/// # Arguments
/// * `redis_client` - The Redis client.
pub async fn get_redis_connection(redis_client: &Client) -> Result<redis::aio::Connection, ApiError> {
    redis_client.get_async_connection().await.map_err(|e| {
        log_error!("Redis", "Get connection", "failure");
        REDIS_OPERATIONS.with_label_values(&["get_connection", "failure"]).inc();
        ApiError::internal_error(&format!("Failed to connect to Redis: {}", e))
    })
}

/// Deletes a key from Redis.
///
/// # Arguments
/// * `redis_conn` - Redis async connection.
/// * `key` - The key to delete.
pub async fn delete_from_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
) -> Result<(), ApiError> {
    log_debug!("Redis", "Delete key", "attempt");
    
    redis_conn.del(key).await.map_err(|e| {
        log_error!("Redis", "Delete key", "failure");
        REDIS_OPERATIONS.with_label_values(&["delete_key", "failure"]).inc();
        ApiError::internal_error(&format!("Failed to delete key from Redis: {}", e))
    })?;
    
    log_debug!("Redis", "Key deleted successfully", "success");
    REDIS_OPERATIONS.with_label_values(&["delete_key", "success"]).inc();
    Ok(())
}

/// Stores a key-value pair in Redis with an expiration time using a pipeline for atomicity.
///
/// # Arguments
/// * `redis_conn` - Redis async connection.
/// * `key` - The key to store.
/// * `value` - The value to store.
/// * `expiration_seconds` - Expiration time in seconds.
pub async fn store_in_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
    value: &str,
    expiration_seconds: usize,
) -> Result<(), ApiError> {
    log_debug!("Redis", "Store key with expiration", "attempt");
    
    redis::pipe()
        .atomic()
        .cmd("SET").arg(key).arg(value)
        .cmd("EXPIRE").arg(key).arg(expiration_seconds)
        .query_async::<_, ()>(redis_conn)
        .await
        .map_err(|e| {
            log_error!("Redis", "Store key", "failure");
            REDIS_OPERATIONS.with_label_values(&["store_key", "failure"]).inc();
            ApiError::internal_error(&format!("Failed to store key in Redis: {}", e))
        })?;
    
    log_debug!("Redis", "Key stored with expiration", "success");
    REDIS_OPERATIONS.with_label_values(&["store_key", "success"]).inc();
    Ok(())
}

/// Retrieves the value associated with a key from Redis.
///
/// # Arguments
/// * `redis_conn` - Redis async connection.
/// * `key` - The key to retrieve.
pub async fn get_from_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
) -> Result<Option<String>, ApiError> {
    log_debug!("Redis", "Get value", "attempt");
    
    let result: Option<String> = redis_conn.get(key).await.map_err(|e| {
        log_error!("Redis", "Get value", "failure");
        REDIS_OPERATIONS.with_label_values(&["get_value", "failure"]).inc();
        ApiError::internal_error(&format!("Failed to retrieve data from Redis: {}", e))
    })?;
    
    if result.is_some() {
        log_debug!("Redis", "Value found", "success");
        REDIS_OPERATIONS.with_label_values(&["get_value", "found"]).inc();
    } else {
        log_debug!("Redis", "No value found", "success");
        REDIS_OPERATIONS.with_label_values(&["get_value", "not_found"]).inc();
    }
    
    Ok(result)
}

/// Sets an expiration time on an existing Redis key.
///
/// # Arguments
/// * `redis_conn` - Redis async connection.
/// * `key` - The key for which to set expiration.
/// * `expiration_seconds` - Number of seconds until the key expires.
pub async fn set_expiration(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
    expiration_seconds: usize,
) -> Result<bool, ApiError> {
    log_debug!("Redis", "Set expiration", "attempt");
    
    let result: bool = redis_conn.expire(key, expiration_seconds).await.map_err(|e| {
        log_error!("Redis", "Set expiration", "failure");
        REDIS_OPERATIONS.with_label_values(&["set_expiration", "failure"]).inc();
        ApiError::internal_error(&format!("Failed to set expiration: {}", e))
    })?;
    
    if result {
        log_debug!("Redis", "Expiration set successfully", "success");
        REDIS_OPERATIONS.with_label_values(&["set_expiration", "success"]).inc();
    } else {
        log_warn!("Redis", "Key not found for expiration", "warning");
        REDIS_OPERATIONS.with_label_values(&["set_expiration", "not_found"]).inc();
    }
    
    Ok(result)
}