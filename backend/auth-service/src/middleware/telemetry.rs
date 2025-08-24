//! HTTP telemetry middleware.
//!
//! Portfolio-ready with minimal overhead and clean tracing.

use axum::{
    extract::State,
    http::{HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::time::Instant;
use tracing::{field::Empty, Instrument, Level};
use uuid::Uuid;

use crate::app::AppState;

pub const HEADER_REQUEST_ID: &str = "X-Request-ID";

/// HTTP telemetry middleware for request tracing.
pub async fn telemetry_middleware<B>(
    State(_): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let request_id = extract_request_id(&req);
    let method = req.method().as_str();
    let path = req.uri().path();
    let started = Instant::now();
    
    // Use DEBUG for health checks, INFO for everything else
    let span = if path.starts_with("/health") {
        tracing::span!(
            Level::DEBUG,
            "http",
            request_id = %request_id,
            method = %method,
            path = %path,
            status = Empty,
            duration_ms = Empty,
        )
    } else {
        tracing::span!(
            Level::INFO,
            "http",
            request_id = %request_id,
            method = %method,
            path = %path,
            status = Empty,
            duration_ms = Empty,
        )
    };

    // Process request
    let mut res = next.run(req).instrument(span.clone()).await;
    
    // Record response data
    let status = res.status().as_u16();
    let duration = started.elapsed().as_millis() as u64;
    
    span.record("status", &status);
    span.record("duration_ms", &duration);
    
    // Add request ID to response
    res.headers_mut().insert(
        HEADER_REQUEST_ID,
        HeaderValue::from_str(&request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    res
}

/// Extracts or generates request ID.
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
    use axum::{body::Body, http::StatusCode, routing::get, Router};
    use tower::ServiceExt;

    async fn handler() -> &'static str {
        "OK"
    }

    #[tokio::test]
    async fn test_request_id_generation() {
        let state = Arc::new(AppState {
            pool: crate::config::database::init_pool(),
            redis_client: None,
            email_config: None,
        });

        let app = Router::new()
            .route("/test", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                state,
                telemetry_middleware,
            ));

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
        assert!(response.headers().contains_key(HEADER_REQUEST_ID));
    }

    #[tokio::test]
    async fn test_request_id_passthrough() {
        let state = Arc::new(AppState {
            pool: crate::config::database::init_pool(),
            redis_client: None,
            email_config: None,
        });

        let app = Router::new()
            .route("/test", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                state,
                telemetry_middleware,
            ));

        let test_id = "test-request-123";
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(HEADER_REQUEST_ID, test_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(HEADER_REQUEST_ID).unwrap(),
            test_id
        );
    }

    #[test]
    fn test_extract_request_id() {
        // No headers
        let req = Request::builder().body(()).unwrap();
        let id = extract_request_id(&req);
        assert!(!id.is_empty());
        
        // With X-Request-ID
        let req = Request::builder()
            .header("X-Request-ID", "test-123")
            .body(())
            .unwrap();
        assert_eq!(extract_request_id(&req), "test-123");
        
        // With lowercase
        let req = Request::builder()
            .header("x-request-id", "test-456")
            .body(())
            .unwrap();
        assert_eq!(extract_request_id(&req), "test-456");
        
        // Empty header (should generate new)
        let req = Request::builder()
            .header("X-Request-ID", "")
            .body(())
            .unwrap();
        let id = extract_request_id(&req);
        assert!(!id.is_empty());
        assert_ne!(id, "");
    }
}
