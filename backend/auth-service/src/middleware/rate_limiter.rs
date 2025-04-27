//! Middleware for global and per-IP rate limiting using Redis.

use std::sync::Arc;
use axum::{
    body::{Body, BoxBody},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use redis::Client;
use tower::{Layer, Service};
use std::future::Future;
use std::pin::Pin;
use crate::utils::rate_limit::check_and_increment;

/// RateLimiterLayer configures the rate limiting middleware.
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
            let allowed = check_and_increment(&redis, &key, max_attempts, window_secs)
                .await
                .unwrap_or(true);

            if !allowed {
                let resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many requests"
                ).into_response();
                // Convert to BoxBody for compatibility
                return Ok(resp.map(axum::body::boxed));
            }

            inner.call(req).await
        })
    }
}