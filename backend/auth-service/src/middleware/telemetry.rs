//! HTTP telemetry middleware.
//!
//! Provides comprehensive request tracing and metrics collection.
//!
//! ## Features
//! - **Request ID**: Injects a unique `X-Request-ID` for log correlation.
//! - **Structured Logging**: Creates a `tracing` span for each request with key fields.
//! - **Metrics Integration**: Records request duration and total count for Prometheus,
//!   using parameterized route paths to avoid cardinality issues.
//! - **Noise Reduction**: Lowers log level for frequent health checks.

use axum::{
    extract::MatchedPath,
    http::{HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{field::Empty, Instrument, Level, Span};
use uuid::Uuid;

use crate::utils::metrics;

pub const HEADER_REQUEST_ID: &str = "X-Request-ID";

/// HTTP telemetry middleware for request tracing and metrics.
pub async fn telemetry_middleware<B>(req: Request<B>, next: Next<B>) -> Response {
    // 1. Prepare request context
    let request_id = extract_request_id(&req);
    let method = req.method().clone();
    // Store the original path for logging, before it's consumed by `next`.
    let original_path = req.uri().path().to_string();

    // 2. Create a tracing span with the original, concrete path.
    // This is useful for debugging individual requests.
    let span = if original_path.starts_with("/health") || original_path.starts_with("/readiness") {
        tracing::span!(
            Level::DEBUG,
            "http_request",
            request_id = %request_id,
            method = %method,
            path = %original_path,
            status = Empty,
            duration_ms = Empty,
        )
    } else {
        tracing::span!(
            Level::INFO,
            "http_request",
            request_id = %request_id,
            method = %method,
            path = %original_path,
            status = Empty,
            duration_ms = Empty,
        )
    };

    // 3. Process the request within the span's context
    let started = Instant::now();
    let mut res = next.run(req).instrument(span.clone()).await;

    // 4. Record response data and metrics
    let status = res.status();
    let duration = started.elapsed();

    // Extract the matched route path from the request extensions.
    // This is the key to solving the cardinality problem.
    let matched_path = res
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str())
        .unwrap_or(&original_path) // Fallback to original path if no match
        .to_string();

    // Start Prometheus timer using the *parameterized* path.
    let _timer = metrics::http::timer(&matched_path);

    // Update span with response details for structured logging
    Span::current().record("status", status.as_u16());
    Span::current().record("duration_ms", duration.as_millis() as u64);

    // Increment Prometheus request counter with the *parameterized* path.
    metrics::http::request(&matched_path, method.as_str(), status.as_u16());

    // 5. Add request ID to the response headers for client-side correlation
    res.headers_mut().insert(
        HEADER_REQUEST_ID,
        HeaderValue::from_str(&request_id)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid_id")),
    );

    res
}

/// Extracts a request ID from headers or generates a new one.
fn extract_request_id<B>(req: &Request<B>) -> String {
    req.headers()
        .get(HEADER_REQUEST_ID)
        .or_else(|| req.headers().get("x-request-id"))
        .or_else(|| req.headers().get("request-id"))
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_extract_request_id_logic() {
        // No headers -> generate new UUID
        let req = Request::builder().body(()).unwrap();
        let id = extract_request_id(&req);
        assert!(Uuid::parse_str(&id).is_ok());

        // With X-Request-ID
        let req = Request::builder()
            .header("X-Request-ID", "test-123")
            .body(())
            .unwrap();
        assert_eq!(extract_request_id(&req), "test-123");

        // With lowercase x-request-id
        let req = Request::builder()
            .header("x-request-id", "test-456")
            .body(())
            .unwrap();
        assert_eq!(extract_request_id(&req), "test-456");

        // With request-id
        let req = Request::builder()
            .header("request-id", "test-789")
            .body(())
            .unwrap();
        assert_eq!(extract_request_id(&req), "test-789");

        // Empty header -> generate new UUID
        let req = Request::builder()
            .header("X-Request-ID", "")
            .body(())
            .unwrap();
        let id = extract_request_id(&req);
        assert!(Uuid::parse_str(&id).is_ok());
    }
}
