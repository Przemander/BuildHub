//! Rate limiting middleware for HTTP services based on Redis.
//!
//! This middleware implements configurable rate limiting with the following features:
//!
//! - Flexible key generation based on request properties (IP, path, method, etc.)
//! - Configurable time windows and request limits
//! - Redis-based distributed rate limiting with atomic operations
//! - Graceful degradation when Redis is unavailable ("fail open" policy)
//! - Comprehensive metrics and logging for operational visibility
//!
//! # Usage Example
//!
//! ```
//! use axum::Router;
//! use redis::Client;
//! use std::sync::Arc;
//!
//! // Create a rate limiter layer that limits by IP address
//! let redis_client = Arc::new(Client::open("redis://127.0.0.1/")?);
//! let rate_limiter = RateLimiterLayer {
//!     redis: redis_client,
//!     max_attempts: 100,         // 100 requests
//!     window_secs: 60,           // per 60 seconds
//!     key_fn: Arc::new(|req| {
//!         // Extract client IP from X-Forwarded-For or remote addr
//!         let ip = req.headers()
//!             .get("X-Forwarded-For")
//!             .and_then(|h| h.to_str().ok())
//!             .and_then(|s| s.split(',').next())
//!             .unwrap_or("unknown");
//!         format!("rate:ip:{}", ip)
//!     }),
//!     config: RateLimitConfig::default()
//! };
//!
//! // Apply the rate limiter to specific routes
//! let app = Router::new()
//!     .route("/login", post(login_handler))
//!     .layer(rate_limiter);
//! ```

use crate::utils::metrics::RATE_LIMIT_BLOCKS;
use crate::utils::rate_limit::check_and_increment;
use crate::{log_error, log_warn};
use axum::{
    body::{Body, BoxBody},
    http::{Request, StatusCode},
    response::Response,
};
use redis::Client;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tower::{Layer, Service};

/// Function type for generating Redis keys from requests.
pub type KeyFn = dyn Fn(&Request<Body>) -> String + Send + Sync + 'static;

/// Configuration for rate limit responses.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// HTTP status code to return when rate limited (default: 429)
    pub status_code: StatusCode,
    /// Response body to return when rate limited
    pub message: String,
    /// Value for Retry-After header in seconds (optional)
    pub retry_after: Option<u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            status_code: StatusCode::TOO_MANY_REQUESTS,
            message: "Too many requests. Please try again later.".to_string(),
            retry_after: Some(10),
        }
    }
}

/// Layer that applies rate limiting middleware to a service.
///
/// This layer creates a rate limiting middleware that:
/// 1. Generates a Redis key for each request using the provided function
/// 2. Checks and increments the counter for that key in Redis
/// 3. Blocks the request if the counter exceeds the configured limit
///
/// # Parameters
///
/// * `redis` - Redis client for distributed rate limiting
/// * `max_attempts` - Maximum number of requests allowed in window
/// * `window_secs` - Time window in seconds
/// * `key_fn` - Function to generate Redis key from request (e.g., IP-based)
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

/// The rate limiting middleware service.
///
/// This service:
/// 1. Intercepts each request
/// 2. Checks if the client has exceeded their rate limit
/// 3. Either forwards the request to the inner service or returns a rate limit error
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
        // Clone necessary values for the async block
        let redis = self.redis.clone();
        let key = (self.key_fn)(&req);
        let max_attempts = self.max_attempts;
        let window_secs = self.window_secs;
        let mut inner = self.inner.clone();
        let config = self.config.clone();

        Box::pin(async move {
            // Check if the request is allowed by the rate limiter
            let allowed = match check_and_increment(&redis, &key, max_attempts, window_secs).await {
                Ok(val) => val,
                Err(e) => {
                    // Log the error but allow the request through (fail open)
                    log_error!(
                        "RateLimiter",
                        &format!("Redis error when checking rate limit: {}", e),
                        "system_error"
                    );
                    true
                }
            };

            if !allowed {
                // Request exceeds rate limit - log and record metrics
                log_warn!(
                    "RateLimiter",
                    &format!("Rate limit exceeded for key: {}", key),
                    "rate_limit"
                );
                RATE_LIMIT_BLOCKS.with_label_values(&["rate_limit"]).inc();

                // Build response using the config values
                let mut response = Response::builder().status(config.status_code);
                
                // Add Retry-After header if configured
                if let Some(retry_secs) = config.retry_after {
                    response = response.header("Retry-After", retry_secs.to_string());
                }
                
                // Return configured response with message
                let response = response
                    .body(axum::body::boxed(Body::from(config.message)))
                    .unwrap_or_else(|_| {
                        // Fallback if builder fails
                        Response::builder()
                            .status(StatusCode::TOO_MANY_REQUESTS)
                            .body(axum::body::boxed(Body::from("Rate limit exceeded")))
                            .unwrap()
                    });
                
                return Ok(response);
            }

            // Request is allowed - forward to inner service
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, BoxBody},
        http::{Request, StatusCode},
        response::Response,
    };
    use redis::Client;
    use std::{
        convert::Infallible,
        future::ready,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::time::sleep;
    use tower::{Service, ServiceExt};
    use uuid::Uuid;

    /// Dummy inner service: always returns 200 OK.
    #[derive(Clone)]
    struct DummyService;
    impl Service<Request<Body>> for DummyService {
        type Response = Response<BoxBody>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            let resp = Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::boxed(Body::empty()))
                .unwrap();
            ready(Ok(resp))
        }
    }

    /// Test helper: new Redis client.
    async fn make_redis_client() -> Client {
        Client::open("redis://127.0.0.1/")
            .expect("Redis must be running on localhost:6379")
    }

    /// Test helper: build a rate‐limit service with random key.
    async fn setup_svc(max: u32, window: usize) -> RateLimiterMiddleware<DummyService> {
        let client = make_redis_client().await;
        let key = Uuid::new_v4().to_string();
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: max,
            window_secs: window,
            key_fn: Arc::new(move |_| key.clone()),
            config: RateLimitConfig::default(),
        };
        layer.layer(DummyService)
    }

    #[tokio::test]
    async fn allows_and_blocks_based_on_limit() {
        let svc = setup_svc(1, 60).await; // svc: RateLimiterMiddleware<DummyService>

        // First call → allowed
        let req1 = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(svc.clone().oneshot(req1).await.unwrap().status(), StatusCode::OK);

        // Second call → blocked (429)
        let req2 = Request::builder().body(Body::empty()).unwrap();
        let resp2 = svc.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn resets_after_ttl() {
        let svc = setup_svc(1, 1).await; // svc: RateLimiterMiddleware<DummyService>

        // 1) first call: allowed
        let req1 = Request::builder().body(Body::empty()).unwrap();
        let resp1 = svc.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // 2) second call: blocked (429)
        let req2 = Request::builder().body(Body::empty()).unwrap();
        let resp2 = svc.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        // wait for TTL
        sleep(Duration::from_secs(2)).await;

        // 3) after TTL: allowed again
        let req3 = Request::builder().body(Body::empty()).unwrap();
        let resp3 = svc.oneshot(req3).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn fail_open_on_redis_error() {
        // Bad port → connection error → middleware must let requests through
        let client = Client::open("redis://127.0.0.1:6380/").unwrap();
        // reuse helper: window=60, max=0
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0,
            window_secs: 60,
            key_fn: Arc::new(move |_| Uuid::new_v4().to_string()),
            config: RateLimitConfig::default(),
        };
        let svc = layer.layer(DummyService);

        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(svc.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn increments_metric_on_block() {
        let svc = setup_svc(0, 60).await;
        // Reset the counter before testing
        RATE_LIMIT_BLOCKS.reset();

        let before = RATE_LIMIT_BLOCKS.with_label_values(&["rate_limit"]).get();
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap(); // blocked
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let after = RATE_LIMIT_BLOCKS.with_label_values(&["rate_limit"]).get();
        assert!(
            after >= before + 1.0,
            "metric should increment by at least 1 (before={} after={})",
            before,
            after
        );
    }

    #[tokio::test]
    async fn uses_custom_config() {
        let client = make_redis_client().await;
        let custom_config = RateLimitConfig {
            status_code: StatusCode::SERVICE_UNAVAILABLE,
            message: "Custom rate limit message".to_string(),
            retry_after: Some(30),
        };
        
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0, // Always rate limit
            window_secs: 60,
            key_fn: Arc::new(|_| "test_key".to_string()),
            config: custom_config,
        };
        
        let svc = layer.layer(DummyService);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        
        // Check that config values were properly used
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "30"
        );
        
        // Read body to check the custom message 
        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_text, "Custom rate limit message");
    }
}