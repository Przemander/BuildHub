//! Redis connection and utility functions.
//!
//! This module provides functionality for connecting to Redis and
//! performing common operations such as key-value storage, deletion,
//! setting expiration, and token blacklisting. Logging focuses on
//! critical events and errors while metrics record operation attempts,
//! successes, and failures.

use redis::{AsyncCommands, Client};
use std::env;
use tracing_error::SpanTrace;
use crate::{log_info, log_error, log_debug};
use crate::utils::errors::CacheError;
use crate::utils::metrics::{REDIS_OPERATIONS, REDIS_HEALTH};

/// Initializes the Redis client using the REDIS_URL environment variable.
///
/// # Returns
/// * `Ok(Client)` if successfully initialized.
/// * `Err(CacheError)` if the environment variable is missing or the URL is invalid.
pub fn init_redis() -> Result<Client, CacheError> {
    let redis_url = env::var("REDIS_URL").map_err(|e| CacheError::Connection {
        source: Box::new(e),
        span: SpanTrace::capture(),
    })?;

    log_info!("Redis", "Connecting to Redis", "success");

    let client = Client::open(redis_url).map_err(|e| CacheError::Connection {
        source: Box::new(e),
        span: SpanTrace::capture(),
    })?;

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
        Err(e) => {
            log_error!("Redis", &format!("Connect to server: {}", e), "failure");
            REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
            REDIS_HEALTH.set(0.0); // Update health metric
            return false;
        }
    };

    match redis::cmd("PING").query_async::<_, String>(&mut con).await {
        Ok(resp) if resp == "PONG" => {
            log_info!("Redis", "Connection check", "success");
            REDIS_OPERATIONS.with_label_values(&["ping", "success"]).inc();
            REDIS_HEALTH.set(1.0); // Update health metric
            true
        },
        Ok(_) | Err(_) => {
            log_error!("Redis", "PING command", "failure");
            REDIS_OPERATIONS.with_label_values(&["ping", "failure"]).inc();
            REDIS_HEALTH.set(0.0); // Update health metric
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
pub async fn get_redis_connection(client: &Client) -> Result<redis::aio::Connection, CacheError> {
    client.get_async_connection().await.map_err(|e| {
        log_error!("Redis", &format!("Get connection: {}", e), "failure");
        REDIS_OPERATIONS.with_label_values(&["get_connection", "failure"]).inc();
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
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), CacheError> {
    log_debug!("Token Management", "Block token", "attempt");
    let mut conn = get_redis_connection(redis).await?;

    conn.set_ex::<&str, &str, ()>(token, "blocked", exp).await.map_err(|e| {
        log_error!("Redis", &format!("Block token failed: {}", e), "failure");
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

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
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, CacheError> {
    log_debug!("Token Management", "Check token status", "attempt");
    let mut conn = get_redis_connection(redis).await?;
    let exists: bool = conn.exists(token).await.map_err(|e| {
        log_error!("Redis", &format!("Token check failed: {}", e), "failure");
        CacheError::Operation {
            source: Box::new(e),
            span: SpanTrace::capture(),
        }
    })?;

    if exists {
        log_debug!("Token Management", "Token is blocked", "success");
    } else {
        log_debug!("Token Management", "Token is valid", "success");
    }
    REDIS_OPERATIONS.with_label_values(&["is_token_blocked", if exists { "blocked" } else { "not_blocked" }]).inc();
    Ok(exists)
}