//! Application router and state configuration for BuildHub Auth Service.
//!
//! This module provides the core application structure and routing configuration:
//!
//! - **Centralized State Management**: All application state is shared via `AppState`
//! - **Enhanced Security**: Route-specific rate limiting with Redis backend
//! - **Cross-Origin Support**: Configurable CORS for both development and production
//! - **Service Health**: Comprehensive health and readiness endpoints for orchestration
//! - **Monitoring**: Prometheus metrics endpoint for observability
//! - **Maintainability**: Explicit routes with clear structure for easy maintenance
//!
//! # Architecture
//!
//! The application follows a layered architecture with:
//!
//! 1. Router-level concerns (CORS, shared state, etc.)
//! 2. Route-specific middleware (auth, rate limiting)
//! 3. Handler functions for business logic
//! 4. Shared application state for services
//!
//! # Key Components
//!
//! - **`AppState`**: Shared state container for databases and services
//! - **`build_app`**: Main function to construct the application with all routes
//! - **Rate Limiting**: Per-route protection based on client IP
//! - **CORS Configuration**: Safe defaults with explicit allowed origins

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
        debug::debug_routes, // Add this line to import debug routes
    },
    middleware::{jwt_auth, rate_limiter::{RateLimiterLayer, RateLimitConfig}},
    middleware::login_checks::login_guard_middleware,
    utils::email::EmailConfig,
    utils::metrics,
};

/// Default rate limit window in seconds
const DEFAULT_RATE_LIMIT_WINDOW_SECS: usize = 60;

/// Default maximum attempts per window
const DEFAULT_RATE_LIMIT_MAX_ATTEMPTS: u32 = 5;

/// Shared application state for all handlers and middleware.
///
/// This structure centralizes access to all external dependencies:
/// - Database connection pool
/// - Redis client for caching and rate limiting
/// - Email configuration for notifications
///
/// Using a shared state pattern allows for:
/// - Simplified dependency injection
/// - Consistent access patterns across handlers
/// - Easier testing with mock implementations
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub pool: DbPool,
    
    /// Redis client for caching and rate limiting (optional)
    pub redis_client: Option<RedisClient>,
    
    /// Email service configuration (optional)
    pub email_config: Option<EmailConfig>,
}

/// Prometheus metrics endpoint handler.
///
/// This handler returns all application metrics in Prometheus text format,
/// suitable for scraping by Prometheus or compatible monitoring systems.
///
/// # Returns
///
/// - Status 200 OK
/// - Content-Type header for Prometheus text format
/// - Metrics data as plain text
async fn metrics_handler() -> impl IntoResponse {
    let metrics = metrics::gather_metrics();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics,
    )
}

/// Build the main Axum application router with all routes and middleware.
///
/// This function constructs the complete application with:
/// - Route-specific rate limiting (when Redis is available)
/// - JWT authentication for protected routes
/// - CORS configuration for web clients
/// - Health and readiness endpoints for orchestration
/// - Metrics endpoint for monitoring
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `redis_client` - Optional Redis client for caching and rate limiting
/// * `email_config` - Optional email service configuration
///
/// # Returns
///
/// Configured Axum Router with all routes and middleware
pub async fn build_app(
    pool: DbPool,
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>,
) -> Router {
    // Create shared application state
    let state = Arc::new(AppState {
        pool,
        redis_client: redis_client.clone(),
        email_config,
    });

    // Configure per-route rate limiter if Redis is available
    let rate_limiter = redis_client.as_ref().map(|client| RateLimiterLayer {
        redis: Arc::new(client.clone()),
        max_attempts: DEFAULT_RATE_LIMIT_MAX_ATTEMPTS,
        window_secs: DEFAULT_RATE_LIMIT_WINDOW_SECS,
        key_fn: Arc::new(|req: &axum::http::Request<axum::body::Body>| {
            // Extract client IP from forwarded header or use "unknown"
            let ip = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            
            // Create route+IP specific rate limit key
            format!("rate:{}:ip:{}", req.uri().path(), ip)
        }),
        config: RateLimitConfig::default(),
    });

    // Define allowed CORS headers
    let allowed_headers = vec![
        HeaderName::from_static("content-type"),
        HeaderName::from_static("authorization"),
        HeaderName::from_static("accept"),
        HeaderName::from_static("x-requested-with"),
    ];
    
    // Define allowed CORS methods
    let allowed_methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ];

    // Create the base router with all standard routes
    let mut app = Router::new()
        // Root route - service information
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        
        // Registration endpoint with rate limiting
        .route(
            "/auth/register",
            post(register_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        
        // Login endpoint with login check middleware
        .route(
            "/auth/login",
            post(login_handler)
                .layer(from_fn_with_state(state.clone(), login_guard_middleware)),
        )
        
        // Token refresh endpoint with rate limiting
        .route(
            "/auth/refresh",
            post(refresh_token_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        
        // Account activation endpoint
        .route("/auth/activate", get(activate_account_handler))
        
        // Password reset request with rate limiting
        .route(
            "/auth/password-reset/request",
            post(password_reset_request_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        
        // Password reset confirmation with rate limiting
        .route(
            "/auth/password-reset/confirm",
            post(password_reset_confirm_handler)
                .layer(rate_limiter.clone().unwrap_or_default()),
        )
        
        // Logout endpoint with JWT authentication required
        .route(
            "/auth/logout",
            post(logout_handler)
                .layer(from_fn_with_state(state.clone(), jwt_auth::jwt_auth_middleware)),
        )
        
        // Health check endpoint - simple alive check
        .route("/health", get(|| async { "ok" }))
        
        // Prometheus metrics endpoint
        .route("/metrics", get(metrics_handler))
        
        // Readiness check with detailed component status
        .route("/ready", get({
            let state = state.clone();
            move || {
                let state = state.clone();
                async move {
                    // Check all dependencies
                    let db_ok = state.pool.get().is_ok();
                    let redis_ok = state
                        .redis_client
                        .as_ref()
                        .map_or(true, |r| r.get_connection().is_ok());
                    let email_ok = state.email_config.is_some();
                    
                    // Overall readiness requires all components
                    let ready = db_ok && redis_ok && email_ok;
                    let code = if ready { 200 } else { 503 };
                    
                    // Return detailed status
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
        }));
        
    // Add debug routes in non-production environments
    if std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
        app = app.nest("/", debug_routes());
    }
        
    // Add shared state and CORS layer to the final router
    app.with_state(state.clone())
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:3000".parse().unwrap(),
                    "http://127.0.0.1:3000".parse().unwrap(),
                    "http://localhost:8080".parse().unwrap(), // Add Vue.js frontend URL
                    "http://127.0.0.1:8080".parse().unwrap(), // Add alternative localhost notation
                ])
                .allow_methods(allowed_methods)
                .allow_headers(allowed_headers)
                .allow_credentials(true),
        )
}

/// Default implementation for RateLimiterLayer when Redis is unavailable.
///
/// This creates a no-op rate limiter that allows all requests through,
/// effectively disabling rate limiting when Redis is not available.
impl Default for RateLimiterLayer {
    fn default() -> Self {
        RateLimiterLayer {
            // Placeholder Redis client that won't actually be used
            redis: Arc::new(RedisClient::open("redis://127.0.0.1/").expect("placeholder Redis")),
            // Set maximum attempts to u32::MAX to effectively disable limiting
            max_attempts: u32::MAX,
            // Minimal window size since it won't be used
            window_secs: 1,
            // Return same key for all requests to ensure no limiting
            key_fn: Arc::new(|_| "noop".to_string()),
            // Default configuration
            config: RateLimitConfig::default(),
        }
    }
}