//! # Rate Limiting Middleware
//!
//! Provides a secure, configurable, and high-performance `tower` layer for
//! rate limiting requests using a fixed-window counter algorithm with Redis.
//!
//! ## Features
//! - **Fixed-Window Counter**: Simple and efficient algorithm for rate limiting.
//! - **Configurable Failure Strategy**: Supports "fail-secure" (default, blocks
//!   requests on Redis error) and "fail-open" (allows requests) modes.
//! - **Standard Headers**: Automatically adds `Retry-After`, `X-RateLimit-Limit`,
//!   and `X-RateLimit-Window` headers to rate-limited responses.
//! - **Flexible Key Generation**: Allows custom logic to define rate limiting
//!   granularity (e.g., per IP, per user, per endpoint).
//! - **Clean Builder API**: Provides a fluent interface for configuration.
//! - **Observability**: Integrates with `tracing` for structured logging and
//!   `metrics` for monitoring.

use crate::{config::redis::check_and_increment_rate_limit, utils::metrics};
use axum::{
    body::{Body, BoxBody},
    http::{Request, StatusCode},
    response::{IntoResponse, Json, Response},
};
use redis::Client;
use serde_json::json;
use std::{future::Future, pin::Pin, sync::Arc};
use tower::{Layer, Service};
use tracing::{info, warn};

/// A function type for generating a unique Redis key from a request.
/// This allows for flexible rate limiting strategies.
pub type KeyFn = dyn Fn(&Request<Body>) -> String + Send + Sync + 'static;

/// Configuration for the rate limiter with sensible defaults.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// The message returned in the body of a `429 Too Many Requests` response.
    pub message: String,
    /// The value for the `Retry-After` header, in seconds.
    pub retry_after_secs: u64,
    /// Determines behavior when Redis is unavailable.
    /// - `false` (default): Fail-secure. Blocks requests.
    /// - `true`: Fail-open. Allows requests. Use with caution.
    pub fail_open: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            message: "Too many requests. Please try again later.".to_string(),
            retry_after_secs: 60,
            fail_open: false, // Fail-secure is the safest default.
        }
    }
}

/// A `tower` layer that applies rate limiting to requests.
///
/// This struct integrates seamlessly with Axum's middleware system and can be
/// applied selectively to specific routes or globally to the entire application.
#[derive(Clone)]
pub struct RateLimiterLayer {
    redis: Arc<Client>,
    max_attempts: u32,
    window_secs: usize,
    key_fn: Arc<KeyFn>,
    config: RateLimitConfig,
}

impl<S> Layer<S> for RateLimiterLayer {
    type Service = RateLimiterMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimiterMiddleware {
            inner,
            redis: self.redis.clone(),
            max_attempts: self.max_attempts,
            window_secs: self.window_secs,
            key_fn: self.key_fn.clone(),
            config: self.config.clone(),
        }
    }
}

/// The actual middleware `Service` that processes each request.
#[derive(Clone)]
pub struct RateLimiterMiddleware<S> {
    inner: S,
    redis: Arc<Client>,
    max_attempts: u32,
    window_secs: usize,
    key_fn: Arc<KeyFn>,
    config: RateLimitConfig,
}

impl<S> Service<Request<Body>> for RateLimiterMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<BoxBody>, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let redis = self.redis.clone();
        let key = (self.key_fn)(&req);
        let max_attempts = self.max_attempts;
        let window_secs = self.window_secs;
        let mut inner = self.inner.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let allowed = match check_and_increment_rate_limit(
                &redis,
                &key,
                max_attempts,
                window_secs,
            )
            .await
            {
                Ok(allowed) => allowed,
                Err(e) => {
                    warn!(error = %e, key = %key, "Redis error during rate limit check");
                    metrics::external::redis_failure("rate_limit");

                    if config.fail_open {
                        metrics::security::rate_limit_fail_open();
                        warn!("Rate limiter failing open: allowing request despite Redis error");
                        true
                    } else {
                        warn!("Rate limiter failing secure: blocking request due to Redis error");
                        false
                    }
                }
            };

            if allowed {
                inner.call(req).await
            } else {
                info!(key = %key, max_attempts, window_secs, "Rate limit exceeded");
                metrics::security::rate_limit_blocked();

                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "status": "error",
                        "message": &config.message,
                        "code": "RATE_LIMIT_EXCEEDED"
                    })),
                )
                    .into_response();

                let headers = response.headers_mut();
                headers.insert(
                    "Retry-After",
                    config.retry_after_secs.to_string().parse().unwrap(),
                );
                headers.insert(
                    "X-RateLimit-Limit",
                    max_attempts.to_string().parse().unwrap(),
                );
                headers.insert(
                    "X-RateLimit-Window",
                    window_secs.to_string().parse().unwrap(),
                );

                Ok(response)
            }
        })
    }
}

impl RateLimiterLayer {
    /// Creates a new rate limiter layer.
    ///
    /// # Example
    /// ```ignore
    /// let layer = RateLimiterLayer::new(
    ///     redis_client,
    ///     100, // 100 requests
    ///     60,  // per 60 seconds
    ///     |req| {
    ///         // Rate limit by IP address
    ///         let ip = extract_ip_from_request(req);
    ///         format!("rate:{}:{}", req.uri().path(), ip)
    ///     }
    /// );
    /// ```
    pub fn new(
        redis: Arc<Client>,
        max_attempts: u32,
        window_secs: usize,
        key_fn: impl Fn(&Request<Body>) -> String + Send + Sync + 'static,
    ) -> Self {
        Self {
            redis,
            max_attempts,
            window_secs,
            key_fn: Arc::new(key_fn),
            config: RateLimitConfig::default(),
        }
    }

    /// Sets a custom error message for rate-limited responses.
    #[allow(dead_code)]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.config.message = message.into();
        self
    }

    /// Sets a custom `Retry-After` header value in seconds.
    #[allow(dead_code)]
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.config.retry_after_secs = seconds;
        self
    }

    /// Configures the middleware to "fail open" (allow requests) when Redis is unavailable.
    /// **Warning**: This reduces security. The default is "fail-secure" (block requests).
    #[allow(dead_code)]
    pub fn fail_open(mut self, fail_open: bool) -> Self {
        self.config.fail_open = fail_open;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_fn(_req: &Request<Body>) -> String {
        "test:rate_limiter".to_string()
    }

    #[test]
    fn test_config_builder_pattern() {
        // This test doesn't require a live Redis connection.
        let redis = Arc::new(Client::open("redis://localhost").unwrap());
        let layer = RateLimiterLayer::new(redis.clone(), 10, 60, test_key_fn)
            .with_message("Custom message")
            .with_retry_after(120)
            .fail_open(false);

        assert_eq!(layer.config.message, "Custom message");
        assert_eq!(layer.config.retry_after_secs, 120);
        assert_eq!(layer.config.fail_open, false);
    }
}
