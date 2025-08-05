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
use tracing::Instrument; // ✅ ASYNC INSTRUMENTATION

use crate::{
    config::database::DbPool,
    handlers::{
        activation::activate_account_handler,
        login::login_handler,
        logout::logout_handler,
        password_reset::{password_reset_confirm_handler, password_reset_request_handler},
        refresh::refresh_token_handler,
        register::register_handler,
        debug::debug_routes,
    },
    middleware::{jwt_auth, rate_limiter::{RateLimiterLayer, RateLimitConfig}},
    middleware::login_checks::login_guard_middleware,
    utils::email::EmailConfig,
    utils::log_new::Log, // ✅ NOWY SYSTEM LOGOWANIA
    utils::telemetry::business_operation_span, // ✅ OPENTELEMETRY SPANS
    metricss::app_metrics::{record_app_build_attempt, record_app_build_success}, // ✅ METRICS
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
            "Metrics Handler",
            "Gathering Prometheus metrics for export",
            "metrics_gather_start",
            "metrics_handler"
        );
        
        // Gather metrics with proper error handling
        let metrics_result = std::panic::catch_unwind(|| {
            crate::metricss::init_all_metrics();
            // Return the actual metrics as a string
            prometheus::TextEncoder::new()
                .encode_to_string(&prometheus::gather())
                .unwrap_or_else(|_| "# Metrics encoding failed\n".to_string())
        });
        
        match metrics_result {
            Ok(metrics) => {
                span.record("metrics_size_bytes", &metrics.len());
                span.record("result", &"success");
                
                Log::event(
                    "DEBUG",
                    "Metrics Handler",
                    &format!("Successfully gathered {} bytes of metrics data", metrics.len()),
                    "metrics_gather_success",
                    "metrics_handler"
                );
                
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
                    metrics,
                )
            }
            Err(e) => {
                span.record("result", &"failure");
                span.record("failure_reason", &"metrics_gather_panic");
                
                Log::event(
                    "ERROR",
                    "Metrics Handler",
                    &format!("Failed to gather metrics due to panic: {:?}", e),
                    "metrics_gather_error",
                    "metrics_handler"
                );
                
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "text/plain")],
                    "# Metrics temporarily unavailable\n".to_string(),
                )
            }
        }
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
            "Health Handler",
            "Processing health check request",
            "health_check_request",
            "health_handler"
        );
        
        span.record("result", &"healthy");
        
        Log::event(
            "DEBUG",
            "Health Handler",
            "Health check completed successfully",
            "health_check_success",
            "health_handler"
        );
        
        "ok"
    }
    .instrument(span_clone)
    .await
}

/// Readiness check endpoint handler with comprehensive dependency verification.
///
/// This handler checks all service dependencies and returns detailed status
/// information suitable for Kubernetes readiness probes.
async fn readiness_handler(state: Arc<AppState>) -> impl IntoResponse {
    // Create span for readiness check
    let span = business_operation_span("readiness_check");
    
    // Clone span for async instrumentation
    let span_clone = span.clone();
    
    async move {
        Log::event(
            "DEBUG",
            "Readiness Handler",
            "Starting comprehensive readiness check",
            "readiness_check_start",
            "readiness_handler"
        );
        
        // Check database connectivity
        let db_span = business_operation_span("check_database_readiness");
        let db_ok = db_span.in_scope(|| {
            match state.pool.get() {
                Ok(_) => {
                    Log::event(
                        "DEBUG",
                        "Readiness Handler",
                        "Database connection check passed",
                        "db_check_success",
                        "readiness_handler"
                    );
                    true
                }
                Err(e) => {
                    Log::event(
                        "WARN",
                        "Readiness Handler",
                        &format!("Database connection check failed: {}", e),
                        "db_check_failure",
                        "readiness_handler"
                    );
                    false
                }
            }
        });
        
        // Check Redis connectivity if configured
        let redis_span = business_operation_span("check_redis_readiness");
        let redis_ok = redis_span.in_scope(|| {
            match state.redis_client.as_ref() {
                Some(client) => {
                    match client.get_connection() {
                        Ok(_) => {
                            Log::event(
                                "DEBUG",
                                "Readiness Handler",
                                "Redis connection check passed",
                                "redis_check_success",
                                "readiness_handler"
                            );
                            true
                        }
                        Err(e) => {
                            Log::event(
                                "WARN",
                                "Readiness Handler",
                                &format!("Redis connection check failed: {}", e),
                                "redis_check_failure",
                                "readiness_handler"
                            );
                            false
                        }
                    }
                }
                None => {
                    Log::event(
                        "DEBUG",
                        "Readiness Handler",
                        "Redis not configured, skipping check",
                        "redis_check_skipped",
                        "readiness_handler"
                    );
                    true // Redis is optional
                }
            }
        });
        
        // Check email configuration
        let email_span = business_operation_span("check_email_readiness");
        let email_ok = email_span.in_scope(|| {
            let configured = state.email_config.is_some();
            
            if configured {
                Log::event(
                    "DEBUG",
                    "Readiness Handler",
                    "Email configuration check passed",
                    "email_check_success",
                    "readiness_handler"
                );
            } else {
                Log::event(
                    "WARN",
                    "Readiness Handler",
                    "Email service not configured",
                    "email_check_not_configured",
                    "readiness_handler"
                );
            }
            
            configured
        });
        
        // Calculate overall readiness
        let ready = db_ok && redis_ok && email_ok;
        let status_code = if ready { 200 } else { 503 };
        
        // Record span data
        span.record("database_ready", &db_ok);
        span.record("redis_ready", &redis_ok);
        span.record("email_ready", &email_ok);
        span.record("overall_ready", &ready);
        span.record("status_code", &status_code);
        
        if ready {
            Log::event(
                "INFO",
                "Readiness Handler",
                "All service dependencies are ready",
                "readiness_check_success",
                "readiness_handler"
            );
            span.record("result", &"ready");
        } else {
            Log::event(
                "WARN",
                "Readiness Handler",
                "One or more service dependencies are not ready",
                "readiness_check_failure",
                "readiness_handler"
            );
            span.record("result", &"not_ready");
        }
        
        // Return detailed status
        (
            StatusCode::from_u16(status_code).unwrap(),
            Json(json!({
                "status": if ready { "ready" } else { "not ready" },
                "components": {
                    "database": {
                        "status": if db_ok { "ready" } else { "not ready" },
                        "required": true
                    },
                    "redis": {
                        "status": if redis_ok { "ready" } else { "not ready" },
                        "required": false
                    },
                    "email": {
                        "status": if email_ok { "ready" } else { "not ready" },
                        "required": true
                    }
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        )
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
            "Service Info Handler",
            "Providing service information",
            "service_info_request",
            "service_info_handler"
        );
        
        let info = json!({
            "service": "BuildHub Authentication Service",
            "version": env!("CARGO_PKG_VERSION"),
            "status": "running",
            "features": {
                "authentication": true,
                "rate_limiting": true,
                "email_notifications": true,
                "metrics": true,
                "health_checks": true
            },
            "endpoints": {
                "health": "/health",
                "readiness": "/ready", 
                "metrics": "/metrics",
                "auth": "/auth/*"
            }
        });
        
        span.record("service_version", &env!("CARGO_PKG_VERSION"));
        span.record("result", &"success");
        
        Log::event(
            "DEBUG",
            "Service Info Handler",
            &format!("Served service info for version {}", env!("CARGO_PKG_VERSION")),
            "service_info_success",
            "service_info_handler"
        );
        
        Json(info)
    }
    .instrument(span_clone)
    .await
}

/// Configure rate limiter with Redis client and instrumentation.
///
/// Creates a rate limiter layer that uses Redis for distributed rate limiting
/// across multiple service instances.
fn configure_rate_limiter(redis_client: Option<&RedisClient>) -> Option<RateLimiterLayer> {
    // Create span for rate limiter configuration
    let span = business_operation_span("configure_rate_limiter");
    
    span.in_scope(|| {
        match redis_client {
            Some(client) => {
                Log::event(
                    "INFO",
                    "Rate Limiter",
                    &format!("Configuring Redis-backed rate limiter (max: {}, window: {}s)", 
                        DEFAULT_RATE_LIMIT_MAX_ATTEMPTS, DEFAULT_RATE_LIMIT_WINDOW_SECS),
                    "rate_limiter_redis_config",
                    "configure_rate_limiter"
                );
                
                span.record("rate_limiter_type", &"redis");
                span.record("max_attempts", &DEFAULT_RATE_LIMIT_MAX_ATTEMPTS);
                span.record("window_seconds", &DEFAULT_RATE_LIMIT_WINDOW_SECS);
                
                Some(RateLimiterLayer {
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
                })
            }
            None => {
                Log::event(
                    "WARN",
                    "Rate Limiter",
                    "Redis not available, rate limiting will be disabled",
                    "rate_limiter_disabled",
                    "configure_rate_limiter"
                );
                
                span.record("rate_limiter_type", &"disabled");
                None
            }
        }
    })
}

/// Configure CORS layer with development and production-safe defaults.
///
/// Sets up Cross-Origin Resource Sharing with appropriate headers and origins
/// based on the deployment environment.
fn configure_cors() -> CorsLayer {
    // Create span for CORS configuration
    let span = business_operation_span("configure_cors");
    
    span.in_scope(|| {
        let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        
        Log::event(
            "INFO",
            "CORS Configuration",
            &format!("Configuring CORS for environment: {}", app_env),
            "cors_config_start",
            "configure_cors"
        );
        
        // Define allowed CORS headers
        let allowed_headers = vec![
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("x-requested-with"),
            HeaderName::from_static("x-forwarded-for"),
        ];
        
        // Define allowed CORS methods
        let allowed_methods = vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ];
        
        // Configure origins based on environment
        let cors_layer = if app_env == "production" {
            // In production, use environment variable for allowed origins
            let origins_env = std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "https://app.buildhub.com".to_string());
            
            let origins: Vec<_> = origins_env
                .split(',')
                .filter_map(|origin| origin.trim().parse().ok())
                .collect();
            
            span.record("cors_mode", &"production");
            span.record("origins_count", &origins.len());
            
            Log::event(
                "INFO",
                "CORS Configuration",
                &format!("Production CORS configured with {} origins", origins.len()),
                "cors_production_config",
                "configure_cors"
            );
            
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(allowed_methods)
                .allow_headers(allowed_headers)
                .allow_credentials(true)
        } else {
            // Development mode with permissive defaults
            let origins: Vec<_> = DEFAULT_DEV_ORIGINS
                .iter()
                .filter_map(|&origin| origin.parse().ok())
                .collect();
            
            span.record("cors_mode", &"development");
            span.record("origins_count", &origins.len());
            
            Log::event(
                "INFO",
                "CORS Configuration",
                &format!("Development CORS configured with {} default origins", origins.len()),
                "cors_development_config",
                "configure_cors"
            );
            
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(allowed_methods)
                .allow_headers(allowed_headers)
                .allow_credentials(true)
        };
        
        span.record("result", &"success");
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
    
    async move {
        Log::event(
            "INFO",
            "Application Builder",
            "Starting Axum application construction",
            "app_build_start",
            "build_app"
        );
        
        // Create shared application state
        let state_span = business_operation_span("create_app_state");
        let state = state_span.in_scope(|| {
            Log::event(
                "DEBUG",
                "Application Builder",
                "Creating shared application state",
                "app_state_create",
                "build_app"
            );
            
            Arc::new(AppState {
                pool,
                redis_client: redis_client.clone(),
                email_config,
            })
        });
        
        span.record("redis_enabled", &redis_client.is_some());
        span.record("email_enabled", &state.email_config.is_some());
        
        // Configure rate limiter
        let rate_limiter_span = business_operation_span("configure_rate_limiter");
        let rate_limiter = rate_limiter_span.in_scope(|| {
            configure_rate_limiter(redis_client.as_ref())
        });
        
        // Configure CORS
        let cors_span = business_operation_span("configure_cors");
        let cors_layer = cors_span.in_scope(|| {
            configure_cors()
        });
        
        // Build routes with instrumentation
        let routes_span = business_operation_span("build_routes");
        let app = routes_span.in_scope(|| {
            Log::event(
                "DEBUG",
                "Application Builder",
                "Building route definitions",
                "routes_build_start",
                "build_app"
            );
            
            let mut router = Router::new()
                // Root route - service information
                .route("/", get(service_info_handler))
                
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
                .route("/health", get(health_handler))
                
                // Prometheus metrics endpoint
                .route("/metrics", get(metrics_handler))
                
                // Readiness check with detailed component status
                .route("/ready", get({
                    let state = state.clone();
                    move || readiness_handler(state)
                }));
            
            // Add debug routes in non-production environments
            let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
            if app_env != "production" {
                Log::event(
                    "INFO",
                    "Application Builder",
                    "Adding debug routes (non-production environment)",
                    "debug_routes_added",
                    "build_app"
                );
                
                router = router.nest("/debug", debug_routes());
                span.record("debug_routes_enabled", &true);
            } else {
                span.record("debug_routes_enabled", &false);
            }
            
            router
        });
        
        // Add shared state and CORS layer
        let final_app_span = business_operation_span("finalize_app");
        let final_app = final_app_span.in_scope(|| {
            Log::event(
                "DEBUG",
                "Application Builder",
                "Applying state and CORS middleware",
                "app_finalize",
                "build_app"
            );
            
            app.with_state(state.clone()).layer(cors_layer)
        });
        
        // Record successful build
        record_app_build_success();
        span.record("result", &"success");
        span.record("total_routes", &8); // Update if routes change
        
        Log::event(
            "INFO",
            "Application Builder",
            "Axum application construction completed successfully",
            "app_build_success",
            "build_app"
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
                "Creating no-op rate limiter (Redis unavailable)",
                "rate_limiter_noop_created",
                "RateLimiterLayer::default"
            );
            
            span.record("rate_limiter_type", &"noop");
            span.record("max_attempts", &u32::MAX);
            
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::database::init_pool;
    use std::env;
    
    #[tokio::test]
    async fn test_build_app_without_redis() {
        // Set up test environment
        env::set_var("DATABASE_URL", "sqlite::memory:");
        
        let pool = init_pool();
        let app = build_app(pool, None, None).await;
        
        // Verify the app is created successfully - fix the test
        // The Router doesn't have an is_empty method, we just check it builds
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
        let cors_layer = configure_cors();
        // CORS layer is configured, but we can't easily test its internals
        // This test mainly ensures no panics occur during configuration
    }
    
    #[test]
    fn test_configure_cors_production() {
        env::set_var("APP_ENV", "production");
        env::set_var("CORS_ALLOWED_ORIGINS", "https://example.com,https://api.example.com");
        let cors_layer = configure_cors();
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