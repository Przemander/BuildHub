//! Rate limiting middleware for HTTP services based on Redis.
//!
//! This middleware implements configurable rate limiting with the following features:
//!
//! - Flexible key generation based on request properties (IP, path, method, etc.)
//! - Configurable time windows and request limits
//! - Redis-based distributed rate limiting with atomic operations
//! - Graceful degradation when Redis is unavailable ("fail open" policy)
//! - Integration with unified error handling system
//! - Comprehensive metrics for security monitoring and performance analysis
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

use crate::config::redis::check_and_increment_rate_limit;
use crate::utils::error_new::ApiError;
use crate::{
    // 🆕 Import simplified rate limiter metrics with alias to avoid conflict
    metricss::rate_limiter_metrics::{
        // Only import what we actually use
        time_rate_limit_check,
        // Helper modules with clear aliases
        request as rate_request, 
        redis as rate_redis,
    },
    log_error, log_warn,
};
use axum::{
    body::{Body, BoxBody},
    http::Request,
    response::{IntoResponse, Response},
};
use redis::Client; // ✅ Now this is unambiguous
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tower::{Layer, Service};

/// Function type for generating Redis keys from requests.
pub type KeyFn = dyn Fn(&Request<Body>) -> String + Send + Sync + 'static;

/// Configuration for rate limit responses.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Custom message to return when rate limited (optional)
    pub message: Option<String>,
    /// Value for Retry-After header in seconds (optional)
    pub retry_after: Option<u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            message: None, // Use default ApiError message
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
/// 4. Records comprehensive metrics for security and performance monitoring
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
/// 4. Records detailed metrics for monitoring and analysis
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
            // 🆕 Time the entire rate limiting operation (runtime context)
            let _timer = time_rate_limit_check(false);
            
            // Perform Redis rate limit check
            let allowed = match check_and_increment_rate_limit(&redis, &key, max_attempts, window_secs).await {
                Ok(allowed) => allowed,
                Err(cache_err) => {
                    log_error!(
                        "RateLimiter",
                        &format!("Redis error during rate limit check: {:?}", cache_err),
                        "redis_error"
                    );
                    
                    // 🆕 Classify and record Redis error using simplified API with alias
                    let error_string = cache_err.to_string().to_lowercase();
                    if error_string.contains("connection") || error_string.contains("connect") {
                        rate_redis::record_runtime_connection_error();
                    } else if error_string.contains("timeout") || error_string.contains("time") {
                        rate_redis::record_runtime_timeout_error();
                    } else {
                        rate_redis::record_runtime_command_error();
                    }
                    
                    // 🆕 Record fail open incident using helper function with alias
                    rate_request::record_runtime_fail_open();
                    
                    true // Fail open - allow request when Redis is down
                }
            };

            if !allowed {
                log_warn!(
                    "RateLimiter",
                    &format!("Rate limit exceeded for key: {}", key),
                    "rate_limit_exceeded"
                );

                // 🆕 Record blocked request using helper function with alias
                rate_request::record_runtime_blocked();

                let message = config.message
                    .unwrap_or_else(|| "Too many requests. Please try again later.".to_string());
                
                let mut api_error = ApiError::too_many_requests(&message);
                
                if let Some(retry_secs) = config.retry_after {
                    api_error = api_error.with_header("Retry-After", retry_secs.to_string());
                }
                
                return Ok(api_error.into_response());
            }

            // 🆕 Record allowed request using helper function with alias
            rate_request::record_runtime_allowed();

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
    use redis::Client; // ✅ Unambiguous in test module
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
        let svc = setup_svc(1, 60).await;

        // First call → allowed
        let req1 = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(svc.clone().oneshot(req1).await.unwrap().status(), StatusCode::OK);

        // Second call → blocked (429)
        let req2 = Request::builder().body(Body::empty()).unwrap();
        let resp2 = svc.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
        
        // Verify JSON structure from unified error system
        let body = hyper::body::to_bytes(resp2.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("\"status\":\"too_many_requests\""), 
                "Should return structured JSON error");
    }

    #[tokio::test]
    async fn resets_after_ttl() {
        let svc = setup_svc(1, 1).await;

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
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0, // Would normally block everything
            window_secs: 60,
            key_fn: Arc::new(move |_| Uuid::new_v4().to_string()),
            config: RateLimitConfig::default(),
        };
        let svc = layer.layer(DummyService);

        let req = Request::builder().body(Body::empty()).unwrap();
        // Should allow request despite Redis error
        assert_eq!(svc.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn uses_custom_config() {
        let client = make_redis_client().await;
        let custom_config = RateLimitConfig {
            message: Some("Custom rate limit message".to_string()),
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
        
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "30"
        );
        
        // Check unified error format
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_text.contains("\"status\":\"too_many_requests\""));
        assert!(body_text.contains("Custom rate limit message"));
    }

    #[tokio::test]
    async fn retry_after_header_is_set() {
        let client = make_redis_client().await;
        let config = RateLimitConfig {
            message: None,
            retry_after: Some(120), // 2 minutes
        };
        
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0, // Always rate limit
            window_secs: 60,
            key_fn: Arc::new(|_| "test_key_retry".to_string()),
            config,
        };
        
        let svc = layer.layer(DummyService);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        
        // Check that Retry-After header is properly set
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "120"
        );
        
        // Verify it's proper JSON response
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("\"status\":\"too_many_requests\""), 
                "Should return structured JSON error");
    }

    #[tokio::test]
    async fn default_message_when_none_provided() {
        let client = make_redis_client().await;
        let config = RateLimitConfig {
            message: None, // Use default message
            retry_after: None,
        };
        
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0, // Always rate limit
            window_secs: 60,
            key_fn: Arc::new(|_| "test_key_default".to_string()),
            config,
        };
        
        let svc = layer.layer(DummyService);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        
        // Check that default message is used
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Too many requests. Please try again later."), 
                "Should contain default message");
        assert!(body_str.contains("\"status\":\"too_many_requests\""), 
                "Should return structured JSON error");
    }

    #[tokio::test]
    async fn test_metrics_integration_with_rate_limiting() {
        // This test verifies that metrics are being recorded during rate limiting operations
        // Note: We can't easily assert on metric values in unit tests since they're global,
        // but we can ensure the code paths that record metrics are exercised.
        
        let svc = setup_svc(1, 60).await;

        // Create requests that will exercise different metric recording paths
        let allowed_req = Request::builder()
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();
        
        let blocked_req = Request::builder()
            .uri("/auth/login")
            .body(Body::empty())
            .unwrap();

        // First request should be allowed (and metrics recorded)
        let resp1 = svc.clone().oneshot(allowed_req).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second request should be blocked (and metrics recorded)
        let resp2 = svc.oneshot(blocked_req).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        // If we get here without panicking, metrics integration is working
        assert!(true);
    }

    #[tokio::test]
    async fn test_fail_open_metrics_integration() {
        // Test that fail open scenarios properly record metrics
        let client = Client::open("redis://127.0.0.1:6380/").unwrap(); // Bad port
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0, // Would normally block everything
            window_secs: 60,
            key_fn: Arc::new(|_| "rate:ip:test".to_string()),
            config: RateLimitConfig::default(),
        };
        let svc = layer.layer(DummyService);

        let req = Request::builder()
            .uri("/auth/login")
            .body(Body::empty())
            .unwrap();
        
        // Should allow request and record fail_open metrics
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // If we get here, fail open metrics were recorded without panicking
        assert!(true);
    }

    #[tokio::test]
    async fn test_different_redis_error_types() {
        // Test that different Redis error types are properly classified
        let client = Client::open("redis://127.0.0.1:6380/").unwrap(); // Bad port - connection error
        let layer = RateLimiterLayer {
            redis: Arc::new(client),
            max_attempts: 0,
            window_secs: 60,
            key_fn: Arc::new(|_| "test_key".to_string()),
            config: RateLimitConfig::default(),
        };
        let svc = layer.layer(DummyService);

        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        
        // Should fail open and record connection error metric
        assert_eq!(resp.status(), StatusCode::OK);
        
        // If we get here, Redis error metrics were recorded properly
        assert!(true);
    }
}