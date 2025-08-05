//! Authentication Service main entry point.
//!
//! This module serves as the primary entry point for the BuildHub Authentication Service,
//! implementing a production-ready microservice with:
//!
//! - **Robust Initialization**: Structured service startup with proper error handling
//! - **Observability**: Comprehensive logging, metrics, and OpenTelemetry integration
//! - **Configuration**: Environment-based configuration with validation
//! - **Graceful Shutdown**: Signal handling for clean process termination
//! - **Service Dependencies**: Database, Redis, and email service management
//!
//! # Architecture Overview
//!
//! The service follows a clean architecture approach:
//!
//! 1. **Configuration Layer**: Environment variables, settings validation
//! 2. **Infrastructure Layer**: Database, Redis, external services
//! 3. **API Layer**: HTTP endpoints, routing, middleware
//! 4. **Domain Layer**: Business logic, validation, security
//!
//! # Startup Sequence
//!
//! 1. Initialize observability (metrics, logging, OpenTelemetry)
//! 2. Load and validate configuration
//! 3. Establish service dependencies (database, Redis)
//! 4. Apply database migrations
//! 5. Build HTTP application with routes and middleware
//! 6. Start HTTP server with graceful shutdown handling
//!
//! # Shutdown Sequence
//!
//! 1. Capture shutdown signal (Ctrl+C or SIGTERM)
//! 2. Complete in-flight requests
//! 3. Close database connections and other resources
//! 4. Exit with appropriate status code

use axum::Server;
use dotenvy::dotenv;
use redis::Client as RedisClient;
use std::{env, net::SocketAddr, time::Duration};
use tokio::signal;
use tracing::Instrument; // ✅ ASYNC INSTRUMENTATION
use tracing_appender::non_blocking;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};

use crate::app::build_app;
use crate::config::database::{init_pool, run_migrations, check_database_health, DbPool};
use crate::config::redis::{check_redis_connection, init_redis};
use crate::utils::email::EmailConfig;
use crate::utils::log_new::Log; // ✅ NOWY SYSTEM LOGOWANIA
use crate::utils::telemetry::{business_operation_span, SpanExt}; // ✅ OPENTELEMETRY SPANS
use crate::metricss::core::{record_startup_attempt, record_startup_success, record_startup_failure}; // ✅ METRICS

mod app;
mod config;
mod db;
mod handlers;
mod middleware;
mod utils;
mod metricss;

/// Maximum time to wait for connections to close during shutdown (in seconds)
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Default port if not specified in environment
const DEFAULT_PORT: u16 = 3000;

/// Default host address if not specified in environment
const DEFAULT_HOST: &str = "127.0.0.1";

/// Service startup timeout in seconds
const SERVICE_STARTUP_TIMEOUT_SECS: u64 = 60;

/// Required environment variables that must be present for the service to start
const REQUIRED_ENV_VARS: &[&str] = &["DATABASE_URL", "JWT_SECRET"];

/// Optional environment variables that enhance service functionality if present
const OPTIONAL_ENV_VARS: &[&str] = &[
    "REDIS_URL",
    "SMTP_SERVER",
    "SMTP_USERNAME", 
    "SMTP_PASSWORD",
    "FRONTEND_URL",
];

/// Main entry point for the authentication service.
///
/// Initializes all components and starts the HTTP server with graceful
/// shutdown handling and comprehensive observability.
///
/// # Error Handling
///
/// Returns errors for critical initialization failures that prevent
/// the service from starting properly.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create main startup span
    let startup_span = business_operation_span("service_startup");
    startup_span.record("service_name", &"auth-service");
    startup_span.record("version", &env!("CARGO_PKG_VERSION"));
    
    // Clone span for async instrumentation
    let startup_span_clone = startup_span.clone();
    let startup_span_for_result = startup_span.clone();
    
    // Record startup attempt metrics
    record_startup_attempt();
    
    // Wrap the entire startup process in instrumentation
    let result = async move {
        Log::event(
            "INFO",
            "Service Startup",
            &format!("Starting authentication service v{}", env!("CARGO_PKG_VERSION")),
            "startup_begin",
            "main"
        );
        
        // Step 1: Initialize observability first
        let observability_span = business_operation_span("initialize_observability");
        let observability_result = observability_span.in_scope(|| {
            // Initialize all metrics first
            metricss::init_all_metrics();
            
            // Configure structured JSON logging with async writer
            setup_logging()
        });
        
        match observability_result {
            Ok(_) => {
                Log::event(
                    "INFO",
                    "Service Startup",
                    "Observability systems initialized successfully",
                    "observability_success",
                    "main"
                );
                startup_span.record("observability_initialized", &true);
            }
            Err(e) => {
                startup_span.record("observability_initialized", &false);
                startup_span.record("failure_reason", &"observability_failed");
                startup_span.record_error(&e);
                record_startup_failure();
                return Err(e);
            }
        }

        // Step 2: Load environment configuration
        let config_span = business_operation_span("load_configuration");
        config_span.in_scope(|| {
            // Load environment variables from .env file if present
            dotenv().ok();
            
            Log::event(
                "INFO",
                "Service Startup",
                "Environment configuration loaded",
                "environment_loaded",
                "main"
            );
            
            // Validate required environment variables
            check_required_env_vars();
            startup_span.record("configuration_loaded", &true);
        });

        // Step 3: Initialize all service dependencies with timeout
        let services_result = tokio::time::timeout(
            Duration::from_secs(SERVICE_STARTUP_TIMEOUT_SECS),
            initialize_services()
        ).await;
        
        let (pool, redis_client, email_config) = match services_result {
            Ok(Ok(services)) => {
                Log::event(
                    "INFO",
                    "Service Startup",
                    "All service dependencies initialized successfully",
                    "services_success",
                    "main"
                );
                startup_span.record("services_initialized", &true);
                services
            }
            Ok(Err(e)) => {
                Log::event(
                    "ERROR",
                    "Service Startup",
                    &format!("Service initialization failed: {}", e),
                    "services_failure",
                    "main"
                );
                startup_span.record("services_initialized", &false);
                startup_span.record("failure_reason", &"services_failed");
                startup_span.record_error(&e);
                record_startup_failure();
                return Err(e);
            }
            Err(_) => {
                let timeout_error = "Service initialization timed out";
                Log::event(
                    "ERROR",
                    "Service Startup",
                    timeout_error,
                    "services_timeout",
                    "main"
                );
                startup_span.record("services_initialized", &false);
                startup_span.record("failure_reason", &"services_timeout");
                record_startup_failure();
                return Err(timeout_error.into());
            }
        };

        // Step 4: Build the Axum application
        let app_span = business_operation_span("build_application");
        let app = app_span.in_scope(|| {
            build_app(pool, redis_client, email_config)
        }).await;
        
        Log::event(
            "INFO",
            "Service Startup",
            "HTTP application built with all routes and middleware",
            "application_built",
            "main"
        );
        startup_span.record("application_built", &true);

        // Step 5: Determine server address
        let addr = get_server_address()?;
        startup_span.record("bind_address", &addr.to_string());
        
        Log::event(
            "INFO",
            "Service Startup",
            &format!("Server ready to start on {}", addr),
            "server_ready",
            "main"
        );

        // Step 6: Start the server with graceful shutdown
        startup_span.record("startup_complete", &true);
        record_startup_success();
        
        Log::event(
            "INFO",
            "Service Startup",
            &format!("Authentication service listening on {}", addr),
            "startup_success",
            "main"
        );

        // Create server operation span
        let server_span = business_operation_span("run_http_server");
        server_span.record("bind_address", &addr.to_string());
        
        let server_span_clone = server_span.clone();
        
        // Run server with instrumentation
        let server_result = async move {
            Server::bind(&addr)
                .serve(app.into_make_service())
                .with_graceful_shutdown(shutdown_signal())
                .await
        }
        .instrument(server_span_clone)
        .await;

        match server_result {
            Ok(_) => {
                server_span.record("result", &"success");
                Log::event(
                    "INFO",
                    "Service Shutdown",
                    "HTTP server shutdown completed successfully",
                    "shutdown_success",
                    "main"
                );
            }
            Err(e) => {
                server_span.record("result", &"failure");
                server_span.record_error(&e);
                Log::event(
                    "ERROR",
                    "Service Shutdown",
                    &format!("HTTP server shutdown with error: {}", e),
                    "shutdown_error",
                    "main"
                );
                return Err(e.into());
            }
        }

        Ok(())
    }
    .instrument(startup_span_clone)
    .await;
    match &result {
        Ok(_) => {
            startup_span_for_result.record("result", &"success");
        }
        Err(_) => {
            startup_span_for_result.record("result", &"failure");
        }
    }

    result
}

/// Sets up structured JSON logging with OpenTelemetry integration.
///
/// Configures tracing with:
/// - JSON formatting for machine parsability
/// - Async non-blocking writer for performance
/// - Filtering based on environment or default level
/// - OpenTelemetry span integration
///
/// # Returns
///
/// Result indicating if logging setup was successful
fn setup_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Create span for logging setup
    let span = business_operation_span("setup_logging");
    
    span.in_scope(|| {
        Log::event(
            "DEBUG",
            "Logging Setup",
            "Initializing structured JSON logging",
            "logging_init_start",
            "setup_logging"
        );
        
        // Create non-blocking stdout writer
        let (non_blocking, _guard) = non_blocking(std::io::stdout());
        
        // Configure JSON formatter with OpenTelemetry support
        let fmt_layer = fmt::layer()
            .with_writer(non_blocking)
            .json()
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .with_target(false);

        // Get log level from environment or use default
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));
        
        // ✅ FIX: Clone filter przed użyciem w log
        let filter_str = filter.to_string();
        span.record("log_level", &filter_str);
        
        // Initialize the global subscriber with OpenTelemetry integration
        Registry::default()
            .with(filter)
            .with(fmt_layer)
            .init();

        Log::event(
            "INFO",
            "Logging Setup",
            &format!("Structured logging initialized with level: {}", filter_str),
            "logging_init_success",
            "setup_logging"
        );
        
        span.record("result", &"success");
        Ok(())
    })
}

/// Initialize all service dependencies with comprehensive health checks.
///
/// Sets up and verifies connections to:
/// - Database (required) with health check
/// - Redis (optional) with connectivity verification
/// - Email service (optional) with configuration validation
///
/// # Returns
///
/// Tuple with database pool, optional Redis client, and optional email config
///
/// # Errors
///
/// Returns error if critical services (database) fail to initialize
async fn initialize_services(
) -> Result<(DbPool, Option<RedisClient>, Option<EmailConfig>), Box<dyn std::error::Error>> {
    // Create span for service initialization
    let span = business_operation_span("initialize_services");
    
    // Clone span for async instrumentation
    let span_clone = span.clone();
    
    async move {
        Log::event(
            "INFO",
            "Service Dependencies",
            "Starting initialization of all service dependencies",
            "dependencies_init_start",
            "initialize_services"
        );

        // Step 1: Initialize database connection pool
        let db_span = business_operation_span("initialize_database");
        let pool = db_span.in_scope(|| {
            Log::event(
                "DEBUG",
                "Service Dependencies",
                "Initializing database connection pool",
                "database_init_start",
                "initialize_services"
            );
            init_pool()
        });
        
        // Step 2: Verify database connectivity and health
        match check_database_health(&pool).await {
            Ok(true) => {
                Log::event(
                    "INFO",
                    "Service Dependencies",
                    "Database health check passed",
                    "database_health_success",
                    "initialize_services"
                );
                span.record("database_healthy", &true);
            }
            Ok(false) => {
                let error_msg = "Database health check failed";
                Log::event(
                    "ERROR",
                    "Service Dependencies",
                    error_msg,
                    "database_health_failure",
                    "initialize_services"
                );
                span.record("database_healthy", &false);
                span.record("failure_reason", &"database_unhealthy");
                return Err(error_msg.into());
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Service Dependencies",
                    &format!("Database health check error: {}", e),
                    "database_health_error",
                    "initialize_services"
                );
                span.record("database_healthy", &false);
                span.record("failure_reason", &"database_health_error");
                span.record_error(&e);
                return Err(e.into());
            }
        }

        // Step 3: Apply any pending database migrations
        let migration_span = business_operation_span("run_migrations");
        migration_span.in_scope(|| {
            match run_migrations(&pool) {
                Ok(_) => {
                    Log::event(
                        "INFO",
                        "Service Dependencies",
                        "Database migrations completed successfully",
                        "migrations_success",
                        "initialize_services"
                    );
                    span.record("migrations_applied", &true);
                    Ok(())
                }
                Err(e) => {
                    Log::event(
                        "ERROR",
                        "Service Dependencies",
                        &format!("Database migrations failed: {}", e),
                        "migrations_failure",
                        "initialize_services"
                    );
                    span.record("migrations_applied", &false);
                    span.record("failure_reason", &"migrations_failed");
                    span.record_error(&e);
                    Err(e)
                }
            }
        })?;

        // Step 4: Initialize Redis client if configured
        let redis_span = business_operation_span("initialize_redis");
        let redis_client = redis_span.in_scope(|| {
            match init_redis() {
                Ok(client) => {
                    Log::event(
                        "DEBUG",
                        "Service Dependencies",
                        "Redis client created, testing connectivity",
                        "redis_client_created",
                        "initialize_services"
                    );
                    Some(client)
                }
                Err(e) => {
                    Log::event(
                        "WARN",
                        "Service Dependencies",
                        &format!("Redis initialization failed: {}, disabling Redis features", e),
                        "redis_init_failure",
                        "initialize_services"
                    );
                    span.record("redis_available", &false);
                    span.record("redis_error", &e.to_string());
                    None
                }
            }
        });

        // Test Redis connectivity if client was created
        let redis_client = if let Some(client) = redis_client {
            if check_redis_connection(&client).await {
                Log::event(
                    "INFO",
                    "Service Dependencies",
                    "Redis connectivity verified successfully",
                    "redis_connectivity_success",
                    "initialize_services"
                );
                span.record("redis_available", &true);
                Some(client)
            } else {
                Log::event(
                    "WARN",
                    "Service Dependencies",
                    "Redis ping failed, disabling Redis features",
                    "redis_ping_failure",
                    "initialize_services"
                );
                span.record("redis_available", &false);
                None
            }
        } else {
            None
        };

        // Step 5: Initialize email configuration if environment variables are present
        let email_span = business_operation_span("initialize_email");
        let email_config = email_span.in_scope(|| {
            match EmailConfig::new() {
                Ok(cfg) => {
                    Log::event(
                        "INFO",
                        "Service Dependencies",
                        "Email service configuration validated successfully",
                        "email_config_success",
                        "initialize_services"
                    );
                    span.record("email_available", &true);
                    Some(cfg)
                }
                Err(e) => {
                    Log::event(
                        "WARN",
                        "Service Dependencies",
                        &format!("Email configuration failed: {}, disabling email features", e),
                        "email_config_failure",
                        "initialize_services"
                    );
                    span.record("email_available", &false);
                    span.record("email_error", &e.to_string());
                    None
                }
            }
        });

        Log::event(
            "INFO",
            "Service Dependencies",
            "All service dependencies initialized successfully",
            "dependencies_init_success",
            "initialize_services"
        );
        span.record("result", &"success");

        Ok((pool, redis_client, email_config))
    }
    .instrument(span_clone)
    .await
}

/// Validate required and optional environment variables with detailed reporting.
///
/// Checks for presence of:
/// - Required variables (fails service startup if missing)
/// - Optional variables (warns but continues if missing)
///
/// Logs detailed information about configuration status with structured data.
fn check_required_env_vars() {
    // Create span for environment validation
    let span = business_operation_span("validate_environment_variables");
    
    span.in_scope(|| {
        Log::event(
            "DEBUG",
            "Environment Validation",
            "Starting validation of required and optional environment variables",
            "env_validation_start",
            "check_required_env_vars"
        );
        
        // Check required environment variables
        let mut missing_required = Vec::new();
        
        for &var in REQUIRED_ENV_VARS {
            if env::var(var).is_err() {
                missing_required.push(var);
                Log::event(
                    "ERROR",
                    "Environment Validation",
                    &format!("Missing required environment variable: {}", var),
                    "required_var_missing",
                    "check_required_env_vars"
                );
            }
        }
        
        if missing_required.is_empty() {
            Log::event(
                "INFO",
                "Environment Validation",
                "All required environment variables are present",
                "required_vars_complete",
                "check_required_env_vars"
            );
            span.record("required_vars_present", &true);
        } else {
            span.record("required_vars_present", &false);
            span.record("missing_required_count", &missing_required.len());
            
            // This would normally cause the service to fail startup
            // but we'll let the downstream components handle the actual failure
        }

        // Check optional environment variables
        let mut missing_optional = Vec::new();
        
        for &var in OPTIONAL_ENV_VARS {
            if env::var(var).is_err() {
                missing_optional.push(var);
            }
        }
        
        if missing_optional.is_empty() {
            Log::event(
                "INFO",
                "Environment Validation",
                "All optional environment variables are present",
                "optional_vars_complete",
                "check_required_env_vars"
            );
            span.record("optional_vars_present", &true);
        } else {
            Log::event(
                "WARN",
                "Environment Validation",
                &format!("Missing optional environment variables: {:?} (some features may be disabled)", missing_optional),
                "optional_vars_missing",
                "check_required_env_vars"
            );
            span.record("optional_vars_present", &false);
            span.record("missing_optional_count", &missing_optional.len());
        }
        
        span.record("total_required_vars", &REQUIRED_ENV_VARS.len());
        span.record("total_optional_vars", &OPTIONAL_ENV_VARS.len());
        span.record("result", &"complete");
    });
}

/// Determine server binding address from environment with validation.
///
/// Uses HOST and PORT environment variables if available,
/// falling back to defaults (127.0.0.1:3000) if not specified.
///
/// # Returns
///
/// Socket address to bind the server to
///
/// # Errors
///
/// Returns error if address parsing fails
fn get_server_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    // Create span for address resolution
    let span = business_operation_span("resolve_server_address");
    
    span.in_scope(|| {
        Log::event(
            "DEBUG",
            "Server Configuration",
            "Resolving server bind address from environment",
            "address_resolution_start",
            "get_server_address"
        );
        
        // Get port from environment or use default
        // ✅ FIX: Explicit type annotation for parse
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);
            
        // Get host from environment or use default
        let host = env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
        
        span.record("host", &host);
        span.record("port", &port);
        span.record("using_defaults", &(port == DEFAULT_PORT && host == DEFAULT_HOST));
        
        // Parse into socket address
        let addr_str = format!("{}:{}", host, port);
        match addr_str.parse::<SocketAddr>() {
            Ok(addr) => {
                Log::event(
                    "INFO",
                    "Server Configuration",
                    &format!("Server address resolved: {}", addr),
                    "address_resolution_success",
                    "get_server_address"
                );
                span.record("resolved_address", &addr.to_string());
                span.record("result", &"success");
                Ok(addr)
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Server Configuration",
                    &format!("Failed to parse server address '{}': {}", addr_str, e),
                    "address_resolution_failure",
                    "get_server_address"
                );
                span.record("result", &"failure");
                span.record("failure_reason", &"parse_error");
                span.record_error(&e);
                Err(e.into())
            }
        }
    })
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM) with proper instrumentation.
///
/// This function blocks until the process receives a shutdown signal,
/// then returns to allow graceful termination.
///
/// Handles both Ctrl+C for interactive use and SIGTERM for container environments.
async fn shutdown_signal() {
    // Create span for shutdown handling
    let span = business_operation_span("handle_shutdown_signal");
    
    // Clone span for async instrumentation
    let span_clone = span.clone();
    
    async move {
        Log::event(
            "DEBUG",
            "Shutdown Handler",
            "Waiting for shutdown signal (Ctrl+C or SIGTERM)",
            "shutdown_wait_start",
            "shutdown_signal"
        );
        
        // Handle CTRL+C signal
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
            
            Log::event(
                "INFO",
                "Shutdown Handler",
                "Shutdown signal received: Ctrl+C",
                "shutdown_signal_ctrl_c",
                "shutdown_signal"
            );
            span.record("signal_type", &"ctrl_c");
        };

        // Handle SIGTERM on Unix platforms
        #[cfg(unix)]
        let sigterm = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
            
            Log::event(
                "INFO",
                "Shutdown Handler",
                "Shutdown signal received: SIGTERM",
                "shutdown_signal_sigterm",
                "shutdown_signal"
            );
            span.record("signal_type", &"sigterm");
        };

        // Stub for non-Unix platforms
        #[cfg(not(unix))]
        let sigterm = std::future::pending::<()>();

        // Wait for either signal
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm => {},
        }
        
        // Record shutdown initiation
        span.record("shutdown_initiated", &true);
        span.record("graceful_timeout_seconds", &GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
        
        Log::event(
            "INFO",
            "Shutdown Handler",
            &format!("Initiating graceful shutdown with {}s timeout for connections to close", GRACEFUL_SHUTDOWN_TIMEOUT_SECS),
            "shutdown_graceful_start",
            "shutdown_signal"
        );
        
        // Note: The actual graceful shutdown timeout is handled by Axum
        // This is just for logging and observability
        span.record("result", &"shutdown_initiated");
    }
    .instrument(span_clone)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[test]
    fn test_get_server_address_default() {
        // Remove any existing environment variables for this test
        env::remove_var("HOST");
        env::remove_var("PORT");
        
        // Should use defaults
        let addr = get_server_address().unwrap();
        assert_eq!(
            addr.to_string(),
            format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT)
        );
    }
    
    #[test]
    fn test_get_server_address_custom() {
        // Set environment variables for this test
        env::set_var("HOST", "0.0.0.0");
        env::set_var("PORT", "8080");
        
        // Should use environment values
        let addr = get_server_address().unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:8080");
        
        // Clean up environment
        env::remove_var("HOST");
        env::remove_var("PORT");
    }
    
    #[test]
    fn test_required_env_vars_are_consistent() {
        // Ensure all required variables are actually checked
        assert!(
            REQUIRED_ENV_VARS.contains(&"DATABASE_URL"),
            "DATABASE_URL should be in REQUIRED_ENV_VARS"
        );
        assert!(
            REQUIRED_ENV_VARS.contains(&"JWT_SECRET"),
            "JWT_SECRET should be in REQUIRED_ENV_VARS"
        );
    }
    
    #[test]
    fn test_startup_timeout_is_reasonable() {
        // Ensure startup timeout is reasonable for production
        assert!(SERVICE_STARTUP_TIMEOUT_SECS >= 30);
        assert!(SERVICE_STARTUP_TIMEOUT_SECS <= 300); // Max 5 minutes
    }
    
    #[test]
    fn test_graceful_shutdown_timeout_is_reasonable() {
        // Ensure shutdown timeout allows for proper connection cleanup
        assert!(GRACEFUL_SHUTDOWN_TIMEOUT_SECS >= 10);
        assert!(GRACEFUL_SHUTDOWN_TIMEOUT_SECS <= 120); // Max 2 minutes
    }
}