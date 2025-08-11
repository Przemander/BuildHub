//! # Application Router and State Configuration
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
//! The module follows a layered architecture with:
//! - Router-level concerns (CORS, shared state)
//! - Route-specific middleware (auth, rate limiting)
//! - Handler functions for business logic
//! - Shared application state for service dependencies

use axum::{
    extract::State,
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use redis::Client as RedisClient;
use serde_json::json;
use std::{env, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::Instrument;

use crate::{
    config::database::DbPool,
    handlers::{
        activation::activate_account_handler,
        debug::debug_routes,
        login::login_handler,
        logout::logout_handler,
        password_reset::{password_reset_confirm_handler, password_reset_request_handler},
        refresh::refresh_token_handler,
        register::register_handler,
    },
    metricss::app_metrics::{
        record_app_build_attempt, record_app_build_success, record_app_build_duration,
    },
    middleware::{
        jwt_auth::jwt_auth_middleware,
        login_checks::login_guard_middleware,
        rate_limiter::{RateLimitConfig, RateLimiterLayer},
        telemetry::telemetry_middleware,
    },
    utils::email::EmailConfig,
    utils::log_new::Log,
    utils::telemetry::business_operation_span,
};

/// Default rate limit window in seconds
const DEFAULT_RATE_LIMIT_WINDOW_SECS: usize = 60;

/// Default maximum attempts per window
const DEFAULT_RATE_LIMIT_MAX_ATTEMPTS: u32 = 5;

/// Default CORS origins for development
const DEFAULT_DEV_ORIGINS: &[&str] = &[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
];

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

/// Prometheus metrics endpoint handler with instrumentation.
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
    // Create span for metrics gathering
    let span = business_operation_span("gather_prometheus_metrics");

    // Clone span for async instrumentation
    let span_clone = span.clone();

    async move {
        Log::event(
            "DEBUG",
            "Metrics",
            "Gathering Prometheus metrics",
            "metrics_request",
            "metrics_handler",
        );

        let metrics = prometheus::TextEncoder::new()
            .encode_to_string(&prometheus::default_registry().gather())
            .unwrap_or_else(|e| {
                Log::event(
                    "ERROR",
                    "Metrics",
                    &format!("Failed to encode metrics: {}", e),
                    "metrics_encoding_error",
                    "metrics_handler",
                );
                "# Error collecting metrics".to_string()
            });

        span.record("metrics_size", &metrics.len());
        span.record("result", &"success");

        // Return metrics with proper content type
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4"),
            )],
            metrics,
        )
    }
    .instrument(span_clone)
    .await
}

/// Health check endpoint handler with instrumentation.
///
/// Simple alive check that returns "ok" if the service is running.
/// This is used by load balancers and orchestrators for basic health checks.
async fn health_handler() -> impl IntoResponse {
    // Create span for health check
    let span = business_operation_span("health_check");

    // Clone span for async instrumentation
    let span_clone = span.clone();

    async move {
        Log::event(
            "DEBUG",
            "Health",
            "Processing health check request",
            "health_check",
            "health_handler",
        );

        span.record("result", &"healthy");

        (StatusCode::OK, "ok")
    }
    .instrument(span_clone)
    .await
}

/// Readiness check endpoint handler with comprehensive dependency verification.
///
/// This handler checks all service dependencies and returns detailed status
/// information suitable for Kubernetes readiness probes.
async fn readiness_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Create span for readiness check
    let span = business_operation_span("readiness_check");
    let span_clone = span.clone();

    async move {
        Log::event(
            "DEBUG",
            "Readiness",
            "Processing readiness check request",
            "readiness_check",
            "readiness_handler",
        );

        // Check database connection
        let db_status = crate::config::database::check_database_health(&state.pool).await;
        let db_healthy = db_status.unwrap_or(false);

        // Check Redis if available
        let redis_healthy = match &state.redis_client {
            Some(client) => crate::config::redis::check_redis_connection(client).await,
            None => false,
        };

        // Check email configuration
        let email_configured = state.email_config.is_some();

        // Calculate overall readiness
        let ready = db_healthy && (redis_healthy || state.redis_client.is_none()) && email_configured;
        let status_code = if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };

        span.record("database_healthy", &db_healthy);
        span.record("redis_healthy", &redis_healthy);
        span.record("email_configured", &email_configured);
        span.record("overall_ready", &ready);
        span.record("status_code", &status_code.as_u16());

        if ready {
            span.record("result", &"ready");
        } else {
            span.record("result", &"not_ready");
        }

        // Build status response
        let status = json!({
            "status": if ready { "ready" } else { "not_ready" },
            "components": {
                "database": {
                    "status": if db_healthy { "ready" } else { "not_ready" },
                    "required": true
                },
                "redis": {
                    "status": if redis_healthy { "ready" } else { "not_ready" },
                    "required": false
                },
                "email": {
                    "status": if email_configured { "ready" } else { "not_ready" },
                    "required": true
                }
            },
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        (status_code, Json(status))
    }
    .instrument(span_clone)
    .await
}

/// Service information endpoint handler.
///
/// Returns basic information about the running service including version,
/// build information, and capabilities.
async fn service_info_handler() -> impl IntoResponse {
    // Create span for service info
    let span = business_operation_span("service_info");

    // Clone span for async instrumentation
    let span_clone = span.clone();

    async move {
        Log::event(
            "DEBUG",
            "Service Info",
            "Providing service information",
            "service_info_request",
            "service_info_handler",
        );

        let info = json!({
            "service": "auth-service",
            "version": env!("CARGO_PKG_VERSION"),
            "features": {
                "jwt": true,
                "redis": true,
                "email": true,
                "metrics": true,
                "rate_limiting": true
            },
            "documentation": "/docs",
            "git_commit": option_env!("GIT_COMMIT_HASH").unwrap_or("unknown"),
            "build_time": option_env!("BUILD_TIME").unwrap_or("unknown")
        });

        span.record("service_version", &env!("CARGO_PKG_VERSION"));
        span.record("result", &"success");

        (StatusCode::OK, Json(info))
    }
    .instrument(span_clone)
    .await
}

/// Configure rate limiter with Redis client and instrumentation.
///
/// Creates a rate limiter layer that uses Redis for distributed rate limiting
/// across multiple service instances.
///
/// # Arguments
///
/// * `redis_client` - Optional Redis client for rate limiting storage
///
/// # Returns
///
/// * `Some(RateLimiterLayer)` - If Redis is available
/// * `None` - If Redis is unavailable (disabling rate limiting)
fn configure_rate_limiter(redis_client: Option<&RedisClient>) -> Option<RateLimiterLayer> {
    // Create span for rate limiter configuration
    let span = business_operation_span("configure_rate_limiter");

    span.in_scope(|| {
        let redis_client = match redis_client {
            Some(client) => client,
            None => {
                Log::event(
                    "WARN",
                    "Rate Limiter",
                    "Redis unavailable; rate limiting disabled",
                    "redis_unavailable",
                    "configure_rate_limiter",
                );
                span.record("rate_limiter_enabled", &false);
                return None;
            }
        };

        // Read rate limit settings from environment or use defaults
        let window_secs = env::var("RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_WINDOW_SECS);

        let max_attempts = env::var("RATE_LIMIT_MAX_ATTEMPTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_MAX_ATTEMPTS);

        span.record("rate_limiter_enabled", &true);
        span.record("window_secs", &window_secs);
        span.record("max_attempts", &max_attempts);

        Log::event(
            "INFO",
            "Rate Limiter",
            &format!("Configuring rate limiter: {} attempts per {}s", max_attempts, window_secs),
            "rate_limiter_configured",
            "configure_rate_limiter",
        );

        // Configure rate limiter with Redis backend
        Some(RateLimiterLayer {
            redis: Arc::new(redis_client.clone()),
            max_attempts,
            window_secs,
            key_fn: Arc::new(move |req| {
                // Create key from IP address and path
                let ip = req
                    .headers()
                    .get("X-Forwarded-For")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("unknown")
                    .split(',')
                    .next()
                    .unwrap_or("unknown");

                let path = req.uri().path();
                format!("ratelimit:{}:{}", ip, path)
            }),
            config: RateLimitConfig {
                message: Some("Rate limit exceeded. Please try again later.".to_string()),
                retry_after: Some(window_secs as u64),
            },
        })
    })
}

/// Configure CORS layer with development and production-safe defaults.
///
/// Sets up Cross-Origin Resource Sharing with appropriate headers and origins
/// based on the deployment environment.
///
/// # Returns
///
/// A configured CorsLayer ready to be applied to the router
fn configure_cors() -> CorsLayer {
    // Create span for CORS configuration
    let span = business_operation_span("configure_cors");

    span.in_scope(|| {
        // Determine if we're in production or development
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        let is_production = app_env == "production";

        let cors_layer = if is_production {
            // Production: Use explicit origins from environment
            let allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
                .map(|origins| origins.split(',').map(String::from).collect::<Vec<_>>())
                .unwrap_or_else(|_| vec!["https://buildhub.example.com".to_string()]);

            span.record("environment", &"production");
            span.record("origins_count", &allowed_origins.len());

            Log::event(
                "INFO",
                "CORS",
                &format!("Configuring CORS for production with {} origins", allowed_origins.len()),
                "cors_production",
                "configure_cors",
            );

            // Create production CORS with explicit origins and restricted methods
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .allow_credentials(true)
                .expose_headers([
                    HeaderName::from_static("x-rate-limit-remaining"),
                    HeaderName::from_static("x-rate-limit-reset"),
                ])
                .max_age(Duration::from_secs(3600))
                .allow_origin(
                    allowed_origins
                        .into_iter()
                        .filter_map(|origin| {
                            origin.parse::<HeaderValue>().ok().or_else(|| {
                                Log::event(
                                    "WARN",
                                    "CORS",
                                    &format!("Invalid origin: {}", origin),
                                    "invalid_origin",
                                    "configure_cors",
                                );
                                None
                            })
                        })
                        .collect::<Vec<_>>(),
                )
        } else {
            // Development: Allow default development origins
            span.record("environment", &"development");
            span.record("origins_count", &DEFAULT_DEV_ORIGINS.len());

            Log::event(
                "INFO",
                "CORS",
                "Configuring CORS for development (permissive)",
                "cors_development",
                "configure_cors",
            );

            // Create development CORS with permissive settings, but enumerate headers when using credentials
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    HeaderName::from_static("x-requested-with"),
                    HeaderName::from_static("x-csrf-token"),
                ])
                .allow_credentials(true)
                .expose_headers([
                    HeaderName::from_static("x-rate-limit-remaining"),
                    HeaderName::from_static("x-rate-limit-reset"),
                ])
                .max_age(Duration::from_secs(3600))
                .allow_origin(
                    DEFAULT_DEV_ORIGINS
                        .iter()
                        .filter_map(|&origin| origin.parse::<HeaderValue>().ok())
                        .collect::<Vec<_>>(),
                )
        };

        cors_layer
    })
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
    // Create main build span
    let span = business_operation_span("build_axum_application");

    // Clone span for async instrumentation
    let span_clone = span.clone();

    // Record build attempt
    record_app_build_attempt();
    let start_time = std::time::Instant::now();

    async move {
        // Create shared application state
        let state = Arc::new(AppState {
            pool,
            redis_client: redis_client.clone(),
            email_config,
        });

        // Configure rate limiter if Redis is available
        let rate_limiter = configure_rate_limiter(redis_client.as_ref());

        // Configure CORS
        let cors_layer = configure_cors();

        // Configure telemetry middleware
        let telemetry_layer = from_fn_with_state(state.clone(), telemetry_middleware);

        // Build routes
        let mut app = Router::new()
            // Public health routes (no authentication or rate limiting)
            .route("/health", get(health_handler))
            .route("/readiness", get(readiness_handler))
            .route("/metrics", get(metrics_handler))
            .route("/info", get(service_info_handler));
            
        // Authentication routes with appropriate middleware
        if let Some(limiter) = rate_limiter.clone() {
            app = app
                .route(
                    "/auth/login",
                    post(login_handler)
                        .layer(ServiceBuilder::new().layer(limiter.clone()).into_inner())
                        .layer(from_fn_with_state(state.clone(), login_guard_middleware)),
                )
                .route(
                    "/auth/register",
                    post(register_handler)
                        .layer(ServiceBuilder::new().layer(limiter.clone()).into_inner()),
                )
                .route(
                    "/auth/password-reset/request",
                    post(password_reset_request_handler)
                        .layer(ServiceBuilder::new().layer(limiter.clone()).into_inner()),
                )
                .route(
                    "/auth/password-reset/confirm",
                    post(password_reset_confirm_handler)
                        .layer(ServiceBuilder::new().layer(limiter.clone()).into_inner()),
                )
                .route(
                    "/auth/refresh",
                    post(refresh_token_handler)
                        .layer(ServiceBuilder::new().layer(limiter.clone()).into_inner()),
                )
                .route(
                    "/auth/logout",
                    post(logout_handler)
                        .layer(ServiceBuilder::new().layer(limiter).into_inner()),
                );
        } else {
            // Routes without rate limiting when Redis is unavailable
            app = app
                .route(
                    "/auth/login",
                    post(login_handler)
                        .layer(from_fn_with_state(state.clone(), login_guard_middleware)),
                )
                .route("/auth/register", post(register_handler))
                .route("/auth/password-reset/request", post(password_reset_request_handler))
                .route("/auth/password-reset/confirm", post(password_reset_confirm_handler))
                .route("/auth/refresh", post(refresh_token_handler))
                .route("/auth/logout", post(logout_handler));
        }
        
        // Add remaining routes
        app = app
            .route("/auth/activate", get(activate_account_handler))
            .route(
                "/auth/protected",
                get(|| async { "Protected resource" })
                    .layer(from_fn_with_state(state.clone(), jwt_auth_middleware)),
            );

        // Add debug routes in non-production environments
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        if app_env != "production" {
            span.record("debug_routes_enabled", &true);
            app = app.nest("/debug", debug_routes());

            Log::event(
                "INFO",
                "Application Builder",
                "Debug routes enabled in non-production environment",
                "debug_routes_enabled",
                "build_app",
            );
        } else {
            span.record("debug_routes_enabled", &false);

            Log::event(
                "INFO",
                "Application Builder",
                "Debug routes disabled in production environment",
                "debug_routes_disabled",
                "build_app",
            );
        }

        // Add global middleware and state
        let final_app = app
            .with_state(state)
            .layer(telemetry_layer)       // apply telemetry before CORS to keep Body=axum::body::Body
            .layer(cors_layer);            // keep CORS

        // Record successful build and metrics
        let duration = start_time.elapsed().as_secs_f64();
        record_app_build_success();
        record_app_build_duration(duration);

        span.record("result", &"success");
        span.record("duration_seconds", &duration);
        span.record("total_routes", &11); // Update if routes change

        Log::event(
            "INFO",
            "Application Builder",
            "Axum application construction completed successfully",
            "app_build_success",
            "build_app",
        );

        final_app
    }
    .instrument(span_clone)
    .await
}

/// Default implementation for RateLimiterLayer when Redis is unavailable.
///
/// This creates a no-op rate limiter that allows all requests through,
/// effectively disabling rate limiting when Redis is not available.
impl Default for RateLimiterLayer {
    fn default() -> Self {
        // Create span for default rate limiter
        let span = business_operation_span("create_default_rate_limiter");

        span.in_scope(|| {
            Log::event(
                "WARN",
                "Rate Limiter",
                "Creating default (no-op) rate limiter due to missing Redis",
                "default_rate_limiter",
                "RateLimiterLayer::default",
            );

            span.record("rate_limiter_type", &"noop");
            span.record("max_attempts", &u32::MAX);

            RateLimiterLayer {
                redis: Arc::new(
                    RedisClient::open("redis://localhost/").unwrap_or_else(|_| {
                        // This is a dummy client that will never be used
                        RedisClient::open("redis://localhost/")
                            .expect("Failed to create dummy Redis client")
                    }),
                ),
                max_attempts: u32::MAX, // Allow unlimited attempts
                window_secs: 1,
                key_fn: Arc::new(|_| "dummy".to_string()), // Dummy key function
                config: RateLimitConfig::default(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::database::init_pool;
    use axum::http::StatusCode;
    use std::env;

    #[tokio::test]
    async fn test_build_app_without_redis() {
        // Set up test environment
        env::set_var("DATABASE_URL", "sqlite::memory:");

        let pool = init_pool();
        let app = build_app(pool, None, None).await;

        // Verify the app is created successfully
        let _service = app.into_make_service();
        // If we get here without panic, the test passes
    }

    #[tokio::test]
    async fn test_service_info_handler() {
        let response = service_info_handler().await;
        let json_response = response.into_response();
        assert_eq!(json_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_handler() {
        let response = health_handler().await;
        let text_response = response.into_response();
        assert_eq!(text_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let response = metrics_handler().await;
        let metrics_response = response.into_response();
        assert_eq!(metrics_response.status(), StatusCode::OK);
    }

    #[test]
    fn test_configure_cors_development() {
        env::set_var("APP_ENV", "development");
        let _cors_layer = configure_cors();
        // CORS layer is configured, but we can't easily test its internals
        // This test mainly ensures no panics occur during configuration
    }

    #[test]
    fn test_configure_cors_production() {
        env::set_var("APP_ENV", "production");
        env::set_var(
            "CORS_ALLOWED_ORIGINS",
            "https://example.com,https://api.example.com",
        );
        let _cors_layer = configure_cors();
        // CORS layer is configured, but we can't easily test its internals
        // This test mainly ensures no panics occur during configuration

        // Clean up
        env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    fn test_rate_limiter_default() {
        let default_limiter = RateLimiterLayer::default();
        assert_eq!(default_limiter.max_attempts, u32::MAX);
        assert_eq!(default_limiter.window_secs, 1);
    }
}
