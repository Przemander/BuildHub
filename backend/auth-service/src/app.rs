//! Application router and state configuration.
//!
//! This module defines the application structure, routes, and middleware setup
//! for the auth service. It sets up public routes (e.g., for registration, login,
//! token refresh, and account activation), protected routes (e.g., for logout),
//! and a metrics endpoint for Prometheus monitoring.
//!
//! Best practices applied:
//! - Clear module and function documentation.
//! - Structured logging using log_debug and log_info at key stages.
//! - Metrics exposure via a dedicated /metrics endpoint.
//! - Centralized configuration of CORS settings for controlled cross-origin requests.

use axum::{
    http::{header::HeaderName, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::CorsLayer;
use redis::Client as RedisClient;
use std::sync::Arc;
use crate::{log_info, log_debug};
use crate::{
    config::database::DbPool,
    handlers::{
        activation::activate_account_handler,
        login::login_handler,
        logout::logout_handler,
        refresh::refresh_token_handler,
        register::register_handler,
        password_reset::{
            password_reset_request_handler,
            password_reset_confirm_handler,
        },
    },
    utils::email::EmailConfig,
    middleware::jwt_auth, // Import the module, not a non-existent function
    middleware::rate_limiter::RateLimiterLayer,
};

/// Application state shared across handlers.
///
/// Contains the database connection pool, an optional Redis client for token management,
/// and an optional email configuration for account activation.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub redis_client: Option<RedisClient>,
    pub email_config: Option<EmailConfig>,
}

/// Builds the application router with all routes and middleware configured.
///
/// # Arguments
/// * `pool` - Database connection pool.
/// * `redis_client` - Optional Redis client (required for token management and activation codes).
/// * `email_config` - Optional email configuration (required for account activation).
///
/// # Returns
/// A fully configured Router ready to be served.
pub async fn build_app(
    pool: DbPool,
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>,
) -> Router {
    log_debug!("App initialization", "Creating application state", "success");
    
    // Construct shared state for all handlers.
    let state = Arc::new(AppState {
        pool,
        redis_client,
        email_config,
    });

    // --- Rate Limiter Middleware Setup ---
    let rate_limiter = if let Some(redis_client) = &state.redis_client {
        // Example: 5 requests per minute per IP per endpoint
        Some(RateLimiterLayer {
            redis: Arc::new(redis_client.clone()),
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
        })
    } else {
        None
    };

    log_debug!("App initialization", "Configuring public routes", "success");
    // Define public endpoints for registration, login, refresh, account activation, and password reset.
    let mut public_routes = Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/refresh", post(refresh_token_handler))
        .route("/auth/activate", get(activate_account_handler))
        .route("/auth/password-reset/request", post(password_reset_request_handler))
        .route("/auth/password-reset/confirm", post(password_reset_confirm_handler));

    // Apply rate limiter to all public routes if Redis is configured
    if let Some(rate_limiter) = rate_limiter {
        public_routes = public_routes.layer(rate_limiter);
    }

    // Metrics route: exposes Prometheus metrics.
    let metrics_route = Router::new().route("/metrics", get(metrics_handler));

    log_debug!("App initialization", "Configuring protected routes", "success");
    // Protected routes (e.g., logout) that may require authentication middleware.
    let protected_routes = Router::new()
        .route("/auth/logout", post(logout_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), jwt_auth::jwt_auth_middleware)); // Use the function from the module

    log_debug!("App initialization", "Configuring health check routes", "success");
    // Health check routes for liveness and readiness probes.
    let health_routes = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ready", get({
            let state = state.clone();
            move || {
                let state = state.clone();
                async move {
                    // Check DB
                    let db_ok = state.pool.get().is_ok();
                    // Check Redis (if configured)
                    let redis_ok = state.redis_client.as_ref().map_or(true, |r| r.get_connection().is_ok());
                    // Check Email config (if required)
                    let email_ok = state.email_config.is_some();

                    let ready = db_ok && redis_ok && email_ok;
                    let status = if ready { "ok" } else { "not ready" };
                    let code = if ready { 200 } else { 503 };
                    (StatusCode::from_u16(code).unwrap(), Json(json!({ "status": status, "db": db_ok, "redis": redis_ok, "email": email_ok })))
                }
            }
        }));

    log_debug!("App initialization", "Configuring CORS settings", "success");
    // Setup CORS layer: specify allowed origins, methods, headers, and credential sharing.
    let allowed_headers = vec![
        axum::http::header::CONTENT_TYPE,
        axum::http::header::AUTHORIZATION,
        axum::http::header::ACCEPT,
        HeaderName::from_static("x-requested-with"),
    ];

    let allowed_methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ];

    log_info!("App initialization", "Building application router", "success");
    // Merge all routes (public, protected, metrics, health) with shared state and CORS settings.
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(metrics_route)
        .merge(health_routes)
        .with_state(state.clone()) // FIX: pass Arc<AppState> by clone
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

/// Handler for exposing Prometheus metrics.
///
/// Metrics are gathered using the `gather_metrics()` function from the metrics module.
/// This endpoint is intended to be scraped by Prometheus.
async fn metrics_handler() -> impl IntoResponse {
    use axum::http::{StatusCode, header};
    let metrics = crate::utils::metrics::gather_metrics();
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; version=0.0.4")], metrics)
}