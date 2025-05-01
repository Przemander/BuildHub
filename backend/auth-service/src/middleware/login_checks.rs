use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper::body::{to_bytes, Bytes};
use std::sync::Arc;
use crate::app::AppState;
use crate::utils::errors::ApiError;
use redis::AsyncCommands;

/// Middleware for login lockout and rate limiting.
pub async fn login_guard_middleware(
    State(app_state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next<Body>,
) -> Response {
    // 1) Read the request body into `Bytes`
    let bytes: Bytes = match to_bytes(req.body_mut()).await {
        Ok(b) => b,
        Err(_) => {
            return ApiError::bad_request("Invalid request body")
                .into_response();
        }
    };

    // 2) Extract the "login" field from the JSON body
    let login_opt = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("login").and_then(|l| l.as_str().map(str::to_string)));

    // 3) Enforce lockout and rate-limit if we have a login and Redis
    if let (Some(login), Some(redis)) = (login_opt, &app_state.redis_client) {
        if let Err(resp) = enforce_lockout(redis, &login).await {
            return resp;
        }
        if let Err(resp) = enforce_rate_limit(redis, &login).await {
            return resp;
        }
    }

    // 4) Reattach the original body so the handler can read it
    *req.body_mut() = Body::from(bytes.clone());

    // 5) Call the next handler
    next.run(req).await
}

/// Checks if account is locked out in Redis. Fails open on Redis error.
pub async fn enforce_lockout(
    redis: &redis::Client,
    login: &str,
) -> Result<(), Response> {
    let mut conn = match redis.get_async_connection().await {
        Ok(c) => c,
        Err(_) => return Ok(()), // fail open
    };
    let key = format!("lockout:{}", login);
    let locked: bool = conn.exists(&key).await.unwrap_or(false);
    if locked {
        let err = ApiError::unauthorized(
            "Account temporarily locked due to repeated failed login attempts",
        );
        return Err(err.into_response());
    }
    Ok(())
}

/// Increments a per-login counter in Redis and blocks if limit exceeded.
/// Fails open on Redis error.
pub async fn enforce_rate_limit(
    redis: &redis::Client,
    login: &str,
) -> Result<(), Response> {
    let mut conn = match redis.get_async_connection().await {
        Ok(c) => c,
        Err(_) => return Ok(()), // fail open
    };
    let key = format!("rate:login:{}", login);
    let max_attempts = 5u32;
    let window_secs = 60usize;

    // Atomic INCR and EXPIRE
    let count: u32 = conn.incr(&key, 1).await.unwrap_or(0);
    if count == 1 {
        let _: () = conn.expire(&key, window_secs).await.unwrap_or(());
    }
    if count > max_attempts {
        // Use bad_request (429) instead of non‑existent too_many_requests
        let err = ApiError::bad_request("Too many login attempts; please try again later");
        return Err(err.into_response());
    }
    Ok(())
}