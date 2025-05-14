//! Application router and state configuration for BuildHub Auth Service.
//!
//! - All state is shared via `AppState` (DB pool, Redis, Email).
//! - Per-route rate limiting is enabled if Redis is available.
//! - CORS is configured for local development and production.
//! - Health and readiness endpoints are provided for orchestration.
//! - All routes are flat and explicit for clarity and maintainability.

use std::sync::Arc;
use axum::{
    http::{header::HeaderName, Method, StatusCode},
    middleware::from_fn_with_state,
    routing::{get, post},
    Json, Router, response::IntoResponse,
};
use redis::Client as RedisClient;
use serde_json::json;
use tower_http::cors::CorsLayer;

use crate::{
    config::database::DbPool,
    handlers::{
        activation::activate_account_handler,
        login::login_handler,
        logout::logout_handler,
        password_reset::{password_reset_confirm_handler, password_reset_request_handler},
        refresh::refresh_token_handler,
        register::register_handler,
    },
    middleware::{jwt_auth, rate_limiter::RateLimiterLayer},
    middleware::login_checks::login_guard_middleware,
    utils::email::EmailConfig,
    utils::metrics,
};

/// Shared application state for all handlers and middleware.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub redis_client: Option<RedisClient>,
    pub email_config: Option<EmailConfig>,
}

// Handler for metrics, using the existing gather_metrics function
async fn metrics_handler() -> impl IntoResponse {
    let metrics = metrics::gather_metrics();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics,
    )
}

/// Build the main Axum application router.
///
/// - Attaches per-route rate limiting if Redis is available.
/// - Configures CORS for local dev and production.
/// - Provides `/health` and `/ready` endpoints for orchestration.
pub async fn build_app(
    pool: DbPool,
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>,
) -> Router {
    let state = Arc::new(AppState {
        pool,
        redis_client: redis_client.clone(),
        email_config,
    });

    // Optional per-route rate limiter (uses IP address from X-Forwarded-For)
    let rate_limiter = redis_client.as_ref().map(|client| RateLimiterLayer {
        redis: Arc::new(client.clone()),
        max_attempts: 5,
        window_secs: 60,
        key_fn: Arc::new(|req: &axum::http::Request<axum::body::Body>| {
            let ip = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            format!("rate:{}:ip:{}", req.uri().path(), ip)
        }),
    });

    // Allowed CORS headers and methods
    let allowed_headers = vec![
        HeaderName::from_static("content-type"),
        HeaderName::from_static("authorization"),
        HeaderName::from_static("accept"),
        HeaderName::from_static("x-requested-with"),
    ];
    let allowed_methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ];

    // Build the router with all routes and middleware
    Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route(
            "/auth/register",
            post(register_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        .route(
            "/auth/login",
            post(login_handler)
                .layer(from_fn_with_state(state.clone(), login_guard_middleware)),
        )
        .route(
            "/auth/refresh",
            post(refresh_token_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        .route("/auth/activate", get(activate_account_handler))
        .route(
            "/auth/password-reset/request",
            post(password_reset_request_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        .route(
            "/auth/password-reset/confirm",
            post(password_reset_confirm_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        .route(
            "/auth/logout",
            post(logout_handler)
                .layer(from_fn_with_state(state.clone(), jwt_auth::jwt_auth_middleware)),
        )
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(metrics_handler))
        .route("/ready", get({
            let state = state.clone();
            move || {
                let state = state.clone();
                async move {
                    let db_ok = state.pool.get().is_ok();
                    let redis_ok = state
                        .redis_client
                        .as_ref()
                        .map_or(true, |r| r.get_connection().is_ok());
                    let email_ok = state.email_config.is_some();
                    let ready = db_ok && redis_ok && email_ok;
                    let code = if ready { 200 } else { 503 };
                    (
                        StatusCode::from_u16(code).unwrap(),
                        Json(json!({
                            "status": if ready { "ok" } else { "not ready" },
                            "db": db_ok,
                            "redis": redis_ok,
                            "email": email_ok
                        })),
                    )
                }
            }
        }))
        .with_state(state.clone())
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:3000".parse().unwrap(),
                    "http://127.0.0.1:3000".parse().unwrap(),
                ])
                .allow_methods(allowed_methods)
                .allow_headers(allowed_headers)
                .allow_credentials(true),
        )
}

// Provide a default RateLimiterLayer when Redis is missing (no-op)
impl Default for RateLimiterLayer {
    fn default() -> Self {
        RateLimiterLayer {
            redis: Arc::new(RedisClient::open("redis://127.0.0.1/").expect("placeholder Redis")),
            max_attempts: 0,
            window_secs: 0,
            key_fn: Arc::new(|_| String::new()),
        }
    }
}