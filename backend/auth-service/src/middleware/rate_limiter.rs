//! # Redis-Based Rate Limiting Middleware
//!
//! Enterprise-grade rate limiting middleware with the following production features:
//!
//! ## 🛡️ **Security & Protection**
//! - **Distributed rate limiting** via Redis for multi-instance deployments
//! - **Flexible key generation** (IP, user ID, endpoint, custom combinations)
//! - **Configurable time windows** and request limits per endpoint
//! - **Graceful degradation** with "fail-open" policy when Redis is unavailable
//!
//! ## 📊 **Observability & Monitoring**
//! - **Complete OpenTelemetry integration** with detailed span attributes
//! - **Comprehensive metrics** for security monitoring and performance analysis
//! - **Structured logging** with privacy-aware key handling
//! - **Error classification** for Redis failures (connection, timeout, command)
//!
//! ## 🔧 **Production Features**
//! - **Non-blocking Redis operations** with proper async/await patterns
//! - **Memory-efficient** with minimal allocations in hot path
//! - **Type-safe configuration** with builder pattern support
//! - **Integration with unified error system** (ApiError responses)

use crate::{
    config::redis::check_and_increment_rate_limit,
    metricss::rate_limiter_metrics::{
        time_rate_limit_check,
        request as rate_request, 
        redis as rate_redis,
    },
    utils::{
        error_new::ApiError,
        log_new::Log,
        telemetry::{business_operation_span, SpanExt},
    },
};
use axum::{
    body::{Body, BoxBody},
    http::Request,
    response::{IntoResponse, Response},
};
use redis::Client;
use std::{future::Future, pin::Pin, sync::Arc};
use tower::{Layer, Service};
use tracing::Instrument;

// =============================================================================
// TYPES AND CONFIGURATION
// =============================================================================

/// Function type for generating Redis keys from requests.
pub type KeyFn = dyn Fn(&Request<Body>) -> String + Send + Sync + 'static;

/// Configuration for rate limit responses and behavior.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Custom message to return when rate limited.
    pub message: Option<String>,
    
    /// Value for Retry-After header in seconds.
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
// TOWER LAYER IMPLEMENTATION
// =============================================================================

/// Tower layer that applies rate limiting middleware to a service.
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
// TOWER SERVICE IMPLEMENTATION
// =============================================================================

/// The rate limiting middleware service.
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

        // Create business operation span for comprehensive tracing
        let span = business_operation_span("rate_limit_check");
        
        // Record metadata for observability (privacy-safe)
        span.record("key_prefix", &key.split(':').next().unwrap_or("unknown"));
        span.record("key_length", &key.len());
        span.record("max_attempts", &max_attempts);
        span.record("window_secs", &window_secs);
        
        let span_clone = span.clone();

        Box::pin(async move {
            // Start timing the rate limit operation
            let _timer = time_rate_limit_check(false);
            
            // Perform atomic Redis rate limit check
            let rate_check_result = check_and_increment_rate_limit(
                &redis, 
                &key, 
                max_attempts, 
                window_secs
            ).await;
            
            let allowed = match rate_check_result {
                Ok(allowed) => {
                    // Successful Redis operation
                    span.record("allowed", &allowed);
                    span.record("redis.success", &true);
                    span.record("redis.operation", &"check_and_increment");
                    
                    Log::event(
                        "DEBUG",
                        "RateLimiter",
                        &format!("Rate limit check completed: allowed={}", allowed),
                        "rate_check_success",
                        "RateLimiterMiddleware::call"
                    );
                    
                    allowed
                }
                Err(cache_err) => {
                    // Redis operation failed - implement fail-open policy
                    Log::event(
                        "ERROR",
                        "RateLimiter",
                        &format!("Redis error during rate limit check: {}", cache_err),
                        "redis_error",
                        "RateLimiterMiddleware::call"
                    );
                    
                    // Record comprehensive error information in span
                    span.record("redis.success", &false);
                    span.record("redis.error_type", &cache_err.to_string());
                    span.record_error(&cache_err);
                    
                    // Classify Redis errors for better monitoring and alerting
                    let error_string = cache_err.to_string().to_lowercase();
                    let error_category = if error_string.contains("connection") || error_string.contains("connect") {
                        rate_redis::record_runtime_connection_error();
                        "connection"
                    } else if error_string.contains("timeout") || error_string.contains("time") {
                        rate_redis::record_runtime_timeout_error();
                        "timeout"
                    } else if error_string.contains("auth") || error_string.contains("noauth") {
                        rate_redis::record_runtime_command_error(); // Auth is a command issue
                        "authentication"
                    } else {
                        rate_redis::record_runtime_command_error();
                        "command"
                    };
                    
                    span.record("redis.error_category", &error_category);
                    
                    // Record fail-open incident for security monitoring
                    rate_request::record_runtime_fail_open();
                    span.record("fail_open", &true);
                    span.record("result", &"fail_open");
                    
                    // Fail open: allow request when Redis is unavailable
                    // This ensures service availability even when rate limiting is down
                    true
                }
            };

            // Handle rate limit exceeded
            if !allowed {
                Log::event(
                    "WARN",
                    "RateLimiter",
                    &format!("Rate limit exceeded for key prefix: {}", 
                             key.split(':').next().unwrap_or("unknown")),
                    "rate_limit_exceeded",
                    "RateLimiterMiddleware::call"
                );

                // Record security metrics for monitoring
                rate_request::record_runtime_blocked();
                span.record("rate_limited", &true);
                span.record("result", &"blocked");

                // Create appropriate error response
                let message = config.message.unwrap_or_else(|| {
                    "Too many requests. Please try again later.".to_string()
                });
                
                let mut api_error = ApiError::too_many_requests(&message);
                
                // Add Retry-After header if configured
                if let Some(retry_secs) = config.retry_after {
                    api_error = api_error.with_header("Retry-After", retry_secs.to_string());
                    span.record("retry_after_seconds", &retry_secs);
                }
                
                // Add rate limit information headers
                api_error = api_error
                    .with_header("X-RateLimit-Limit", max_attempts.to_string())
                    .with_header("X-RateLimit-Window", window_secs.to_string());
                
                span.record("http.status_code", &429);
                
                return Ok(api_error.into_response());
            }

            // Request is allowed - record success metrics
            rate_request::record_runtime_allowed();
            span.record("rate_limited", &false);
            span.record("result", &"allowed");

            Log::event(
                "DEBUG",
                "RateLimiter",
                "Request allowed, forwarding to inner service",
                "request_allowed",
                "RateLimiterMiddleware::call"
            );

            // Forward request to inner service
            // Note: We don't instrument this call as it will have its own spans
            inner.call(req).await
        }
        .instrument(span_clone))
    }
}