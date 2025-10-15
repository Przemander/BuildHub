//! Application router and state configuration.
//!
//! This module constructs the main Axum application, configuring state,
//! routing, and middleware for a production-ready service.

use axum::{
    extract::State,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use redis::Client as RedisClient;
use serde_json::json;
use std::{env, sync::Arc, time::Duration};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::{
    config::database::DbPool,
    handlers::{
        activation::activation_handler,
        debug::debug_routes,
        login::login_handler,
        logout::logout_handler,
        password_reset::{password_reset_confirm_handler, password_reset_request_handler},
        refresh::refresh_token_handler,
        register::register_handler,
    },
    middleware::{
        jwt_auth::jwt_auth_middleware,
        rate_limiter::RateLimiterLayer,
        telemetry::telemetry_middleware,
    },
    utils::{email::EmailConfig, metrics},
};

// =============================================================================
// CONSTANTS
// =============================================================================

const DEFAULT_RATE_LIMIT_WINDOW_SECS: usize = 60;
const DEFAULT_RATE_LIMIT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_DEV_ORIGINS: &[&str] = &[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
];

// =============================================================================
// APPLICATION STATE
// =============================================================================

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub redis_client: Option<RedisClient>,
    pub email_config: Option<EmailConfig>,
}

// =============================================================================
// HEALTH ENDPOINTS
// =============================================================================

/// Prometheus metrics endpoint.
async fn metrics_handler() -> impl IntoResponse {
    let metrics = metrics::gather();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        metrics,
    )
}

/// Health check endpoint.
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness check endpoint.
async fn readiness_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_healthy = crate::config::database::check_database_health(&state.pool)
        .await
        .is_ok();

    let redis_healthy = match &state.redis_client {
        Some(client) => crate::config::redis::check_redis_connection(client).await,
        None => false,
    };

    let email_configured = state.email_config.is_some();
    let ready = db_healthy && (redis_healthy || state.redis_client.is_none());

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let status = json!({
        "status": if ready { "ready" } else { "not_ready" },
        "components": {
            "database": if db_healthy { "healthy" } else { "unhealthy" },
            "redis": if redis_healthy { "healthy" } else if state.redis_client.is_none() { "not_configured" } else { "unhealthy" },
            "email": if email_configured { "configured" } else { "not_configured" }
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    (status_code, Json(status))
}

/// Service info endpoint.
async fn service_info_handler() -> impl IntoResponse {
    let info = json!({
        "service": "auth-service",
        "version": env!("CARGO_PKG_VERSION"),
        "features": {
            "jwt_auth": true,
            "email_activation": true,
            "password_reset": true,
            "rate_limiting": true
        },
        "documentation": "/docs"
    });

    (StatusCode::OK, Json(info))
}

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Configure rate limiter.
fn configure_rate_limiter(redis_client: Option<&RedisClient>) -> Option<RateLimiterLayer> {
    let redis_client = match redis_client {
        Some(client) => client,
        None => {
            warn!("Rate limiting disabled - Redis not configured");
            return None;
        }
    };

    let window_secs = env::var("RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RATE_LIMIT_WINDOW_SECS);

    let max_attempts = env::var("RATE_LIMIT_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RATE_LIMIT_MAX_ATTEMPTS);

    info!(
        "Rate limiter configured: {} attempts per {}s",
        max_attempts, window_secs
    );

    Some(RateLimiterLayer::new(
        Arc::new(redis_client.clone()),
        max_attempts,
        window_secs,
        |req| {
            let ip = req
                .headers()
                .get("x-forwarded-for")
                .or_else(|| req.headers().get("x-real-ip"))
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim())
                .unwrap_or("unknown");

            format!("rate:{}:{}", req.uri().path(), ip)
        },
    ))
}

/// Configure CORS.
fn configure_cors() -> CorsLayer {
    let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
    let is_production = app_env == "production";

    if is_production {
        let allowed_origins = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "https://buildhub.example.com".to_string())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect::<Vec<_>>();

        CorsLayer::new()
            .allow_origin(allowed_origins)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .max_age(Duration::from_secs(3600))
    } else {
        CorsLayer::new()
            .allow_origin(
                DEFAULT_DEV_ORIGINS
                    .iter()
                    .map(|s| s.parse().unwrap())
                    .collect::<Vec<_>>(),
            )
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .allow_credentials(true)
            .max_age(Duration::from_secs(3600))
    }
}

// =============================================================================
// APPLICATION BUILDER
// =============================================================================

/// Build the main application router.
pub async fn build_app(
    pool: DbPool,
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>,
) -> Router {
    let start_time = std::time::Instant::now();

    let state = Arc::new(AppState {
        pool,
        redis_client,
        email_config,
    });

    let rate_limiter = configure_rate_limiter(state.redis_client.as_ref());
    let cors_layer = configure_cors();

    let base_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/readiness", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        .route("/info", get(service_info_handler));

    let public_auth_routes = Router::new()
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/activate", get(activation_handler))
        .route(
            "/auth/password-reset/request",
            post(password_reset_request_handler),
        )
        .route(
            "/auth/password-reset/confirm",
            post(password_reset_confirm_handler),
        );

    let public_auth_routes = if let Some(limiter) = rate_limiter {
        public_auth_routes.layer(limiter)
    } else {
        public_auth_routes
    };

    let protected_auth_routes = Router::new()
        .route("/auth/logout", post(logout_handler))
        .route("/auth/refresh", post(refresh_token_handler))
        .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

    let mut app = base_routes
        .merge(public_auth_routes)
        .merge(protected_auth_routes);

    let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
    if app_env != "production" {
        info!("Debug routes enabled (non-production environment)");
        app = app.nest("/debug", debug_routes());
    }

    let final_app = app
        .layer(from_fn_with_state(state.clone(), telemetry_middleware))
        .layer(cors_layer)
        .with_state(state);

    let duration = start_time.elapsed();
    info!(
        "Application router built in {:.2}ms",
        duration.as_millis()
    );

    final_app
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to prevent race conditions when setting environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_configure_cors_development() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("APP_ENV", "development");
        let _cors = configure_cors();
        // Test passes if it doesn't panic
        env::remove_var("APP_ENV");
    }

    #[test]
    fn test_configure_cors_production() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("APP_ENV", "production");
        env::set_var("ALLOWED_ORIGINS", "https://example.com,https://app.example.com");
        let _cors = configure_cors();
        // Test passes if it doesn't panic
        env::remove_var("APP_ENV");
        env::remove_var("ALLOWED_ORIGINS");
    }
}