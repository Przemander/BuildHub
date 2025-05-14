//! Middleware for global and per-IP rate limiting using Redis.
//!
//! Logs all rate limit events and increments metrics for observability.

use crate::utils::rate_limit::check_and_increment;
use crate::utils::metrics::RATE_LIMIT_BLOCKS;
use crate::{log_warn, log_error};
use axum::{
    body::{Body, BoxBody},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use redis::Client;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tower::{Layer, Service};

/// RateLimiterLayer configures the rate limiting middleware.
///
/// # key_fn
///
/// The key_fn parameter is a user-supplied closure that generates a unique
/// Redis key for each request. It must implement:
///
///     Fn(&Request<Body>) -> String + Send + Sync + 'static
///
/// The closure is called with a reference to the full HTTP Request<Body>,
/// so you can inspect headers (e.g. X-Forwarded-For), the URI path,
/// method, etc., and return a String that will be used to track rate limits
/// per client or per endpoint.
#[derive(Clone)]
pub struct RateLimiterLayer {
    pub redis: Arc<Client>,
    pub max_attempts: u32,
    pub window_secs: usize,
    /// Function to generate a Redis key from the request (e.g., per-IP, per-endpoint).
    pub key_fn: Arc<dyn Fn(&Request<Body>) -> String + Send + Sync>,
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
        }
    }
}

/// The actual middleware service.
#[derive(Clone)]
pub struct RateLimiterMiddleware<S> {
    inner: S,
    redis: Arc<Client>,
    max_attempts: u32,
    window_secs: usize,
    key_fn: Arc<dyn Fn(&Request<Body>) -> String + Send + Sync>,
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

        Box::pin(async move {
            let allowed = match check_and_increment(&redis, &key, max_attempts, window_secs).await {
                Ok(val) => val,
                Err(e) => {
                    log_error!("RateLimiter", &format!("Redis error: {}", e), "system_error");
                    // Fail open on Redis error
                    true
                }
            };

            if !allowed {
                log_warn!(
                    "RateLimiter",
                    &format!("Rate limit exceeded for key: {}", key),
                    "rate_limit"
                );
                RATE_LIMIT_BLOCKS.with_label_values(&["rate_limit"]).inc();

                // return a 429 immediately
                let resp = (StatusCode::TOO_MANY_REQUESTS, "Too many requests")
                    .into_response();
                return Ok(resp.map(axum::body::boxed));
            }

            // otherwise forward to inner service
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
}