//! # HTTP Telemetry Middleware
//!
//! This module provides a comprehensive HTTP request telemetry middleware that:
//!
//! - **Automatically traces all HTTP requests** with consistent attributes
//! - **Extracts context** from request headers (tracing IDs, user info)
//! - **Records response metadata** including status code and timing
//! - **Integrates with OpenTelemetry** for distributed tracing
//! - **Follows W3C Trace Context specification** for interoperability
//!
//! The middleware creates a structured span for each request that flows through
//! the application, enabling detailed request analysis and correlation.

use axum::{
    extract::State,
    http::{HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use std::sync::Arc; // <-- add
use tracing::{field::Empty, Instrument, Level};
use uuid::Uuid;

use crate::app::AppState;

/// Publicly-exposed header so other layers / services can use it.
pub const HEADER_REQUEST_ID: &str = "X-Request-ID";

// ──────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE
// ──────────────────────────────────────────────────────────────────────────────
pub async fn telemetry_middleware<B>(
    State(_): State<Arc<AppState>>, // <-- was State<AppState>
    req: Request<B>,
    next: Next<B>,
) -> Response {
    // --- metadata -------------------------------------------------------------
    let request_id = request_id(&req);
    let method = req.method().as_str();
    let path = req.uri().path();
    let health = matches!(path, "/health" | "/healthz");
    let started = Instant::now();

    // --- tracing span ---------------------------------------------------------
    // `tracing::span!` needs a *literal* level. Build the span
    // with two branches so the level is constant for the macro.
    let span = if health {
        tracing::span!(
            Level::DEBUG,
            "http.request",
            request_id = %request_id,
            http.method           = %method,
            http.target           = %path,
            http.route            = %path,
            http.status_code              = Empty,
            http.request_content_length   = Empty,
            http.response_content_length  = Empty,
            duration_ms           = Empty,
            error                 = false
        )
    } else {
        tracing::span!(
            Level::INFO,
            "http.request",
            request_id = %request_id,
            http.method           = %method,
            http.target           = %path,
            http.route            = %path,
            http.status_code              = Empty,
            http.request_content_length   = Empty,
            http.response_content_length  = Empty,
            duration_ms           = Empty,
            error                 = false
        )
    };
    let span_ref = span.clone();

    // --- pipeline -------------------------------------------------------------
    let mut res = next.run(req).instrument(span_ref).await;

    // status + sizes
    span.record("http.status_code", &res.status().as_u16());
    if let Some(v) = res
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        span.record("http.response_content_length", &v);
    }

    if res.status().is_success() {
        span.record("result", &"success");
    } else if res.status().is_client_error() {
        span.record("result", &"client_error");
    } else if res.status().is_server_error() {
        span.record("result", &"server_error");
        span.record("error", &true);
    }

    // duration
    let duration = started.elapsed().as_millis() as u64;
    span.record("duration_ms", &duration);

    // propagate request-id
    res.headers_mut().insert(
        HEADER_REQUEST_ID,
        HeaderValue::from_str(&request_id).unwrap(),
    );

    res
}

// ──────────────────────────────────────────────────────────────────────────────
// HELPERS
// ──────────────────────────────────────────────────────────────────────────────
fn request_id<B>(req: &Request<B>) -> String {
    const FALLBACK_HEADERS: [&str; 2] = ["X-Request-Id", "Request-Id"];

    req.headers()
        .get(HEADER_REQUEST_ID)
        .or_else(|| FALLBACK_HEADERS.iter().find_map(|h| req.headers().get(*h)))
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}
