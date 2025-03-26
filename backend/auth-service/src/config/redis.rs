use redis::{AsyncCommands, Client, RedisError};
use std::env;
use log::{error, info};

use crate::utils::errors::ApiError;

/// Initialize the Redis client using the REDIS_URL environment variable.
pub fn init_redis() -> Result<Client, Box<dyn std::error::Error>> {
    let redis_url = env::var("REDIS_URL")?;
    info!("Connecting to Redis at: {}", redis_url);
    let client = Client::open(redis_url)?;
    Ok(client)
}

/// Checks the Redis connection by sending a PING command.
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

/// Blocks a token by storing it in Redis with an expiration time (in seconds).
pub async fn block_token(redis: &Client, token: &str, exp: usize) -> Result<(), RedisError> {
    let mut conn = redis.get_async_connection().await?;
    conn.set_ex::<&str, &str, ()>(token, "blocked", exp).await?;
    Ok(())
}

/// Check if a token is blocked. Return true if the token is in Redis, falce otherwise.
pub async fn is_token_blocked(redis: &Client, token: &str) -> Result<bool, RedisError> {
    let mut conn = redis.get_async_connection().await?;
    let exists: bool = conn.exists(token).await?;
    Ok(exists)
}

/// Returns an async Redis connection or an ApiError if unable to connect.
pub async fn get_redis_connection(redis_client: &Client) -> Result<redis::aio::Connection, ApiError> {
    redis_client.get_async_connection().await.map_err(|e| {
        ApiError {
            status: "internal_error".to_string(),
            message: format!("Failed to connect to Redis: {}", e),
        }
    })
}

/// Deletes a key from Redis.
pub async fn delete_from_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
) -> Result<(), ApiError> {
    redis_conn.del(key).await.map_err(|e| {
        ApiError {
            status: "internal_error".to_string(),
            message: format!("Failed to delete key from Redis: {}", e),
        }
    })
}

/// Stores a (key, value) pair in Redis and sets its expiration (in seconds).
pub async fn store_in_redis(
    redis_conn: &mut redis::aio::Connection,
    key: &str,
    value: &str,
    expiration_seconds: usize,
) -> Result<(), ApiError> {
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(key)
        .arg(value)
        .cmd("EXPIRE")
        .arg(key)
        .arg(expiration_seconds)
        .query_async(redis_conn)
        .await
        .map_err(|e| {
            ApiError {
                status: "internal_error".to_string(),
                message: format!("Failed to store key in Redis: {}", e),
            }
        })
}