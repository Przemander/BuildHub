//! Rate limiting middleware.
//!
//! Portfolio-ready with minimal overhead, clean design, and effective protection.

use axum::{
    body::{Body, BoxBody},
    http::{Request, StatusCode},
    response::{IntoResponse, Response, Json},
};
use redis::Client;
use serde_json::json;
use std::{future::Future, pin::Pin, sync::Arc};
use tower::{Layer, Service};
use tracing::{info, warn};

use crate::{
    config::redis::check_and_increment_rate_limit,
    utils::metrics,  // Fixed: correct import path
};

// =============================================================================
// TYPES
// =============================================================================

/// Function for generating Redis keys from requests.
pub type KeyFn = dyn Fn(&Request<Body>) -> String + Send + Sync + 'static;

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub message: Option<String>,
    pub retry_after: Option<u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            message: None,
            retry_after: Some(60),
        }
    }
}

// =============================================================================
// LAYER
// =============================================================================

/// Tower layer for rate limiting.
#[derive(Clone)]
pub struct RateLimiterLayer {
    pub redis: Arc<Client>,
    pub max_attempts: u32,
    pub window_secs: usize,
    pub key_fn: Arc<KeyFn>,
    pub config: RateLimitConfig,
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

// =============================================================================
// SERVICE
// =============================================================================

/// Rate limiting middleware service.
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
            // Check rate limit
            let allowed = match check_and_increment_rate_limit(&redis, &key, max_attempts, window_secs).await {
                Ok(allowed) => {
                    if !allowed {
                        info!(
                            key_prefix = key.split(':').next().unwrap_or("unknown"),
                            "Rate limit exceeded"
                        );
                        metrics::security::rate_limit_exceeded();
                    }
                    allowed
                }
                Err(e) => {
                    warn!(error = %e, "Redis error, failing open");
                    metrics::external::redis_failure("rate_limit");
                    metrics::security::rate_limit_fail_open();
                    
                    // Fail open - allow request when Redis is down
                    true
                }
            };

            if !allowed {
                metrics::security::rate_limit_blocked();

                let message = config.message.unwrap_or_else(|| 
                    "Too many requests. Please try again later.".to_string()
                );

                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "status": "error",
                        "message": message,
                        "code": "RATE_LIMIT_EXCEEDED"
                    }))
                ).into_response();

                // Add rate limit headers
                let headers = response.headers_mut();
                
                if let Some(retry) = config.retry_after {
                    headers.insert("Retry-After", retry.to_string().parse().unwrap());
                }
                
                headers.insert("X-RateLimit-Limit", max_attempts.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Window", window_secs.to_string().parse().unwrap());

                return Ok(response);
            }

            metrics::security::rate_limit_allowed();
            inner.call(req).await
        })
    }
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

impl RateLimiterLayer {
    /// Creates a new rate limiter with custom configuration.
    pub fn custom(
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
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode, routing::get, Router};
    use tower::ServiceExt;

    async fn handler() -> &'static str {
        "OK"
    }

    fn test_key_fn(req: &Request<Body>) -> String {
        format!("test:{}", req.uri().path())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_rate_limiting() {
        metrics::init();
        let redis = Arc::new(Client::open("redis://localhost:6379").unwrap());
        
        let layer = RateLimiterLayer::custom(redis, 2, 60, test_key_fn);

        let app = Router::new()
            .route("/test", get(handler))
            .layer(layer);

        // First two requests should succeed
        for i in 1..=2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            
            assert_eq!(response.status(), StatusCode::OK, "Request {} should succeed", i);
        }

        // Third request should be rate limited
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        
        // Check headers
        assert!(response.headers().contains_key("retry-after"));
        assert!(response.headers().contains_key("x-ratelimit-limit"));
        assert!(response.headers().contains_key("x-ratelimit-window"));
    }

    #[tokio::test]
    async fn test_fail_open_with_invalid_redis() {
        metrics::init();
        let redis = Arc::new(Client::open("redis://invalid:6379").unwrap());
        
        let layer = RateLimiterLayer::custom(redis, 1, 60, test_key_fn);

        let app = Router::new()
            .route("/test", get(handler))
            .layer(layer);

        // Should fail open and allow request
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_custom_config() {
        let config = RateLimitConfig {
            message: Some("Custom message".to_string()),
            retry_after: Some(120),
        };

        assert_eq!(config.message.as_deref(), Some("Custom message"));
        assert_eq!(config.retry_after, Some(120));
    }
}
