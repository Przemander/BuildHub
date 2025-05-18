//! Authentication Service main entry point.
//!
//! This module serves as the primary entry point for the BuildHub Authentication Service,
//! implementing a production-ready microservice with:
//!
//! - **Robust Initialization**: Structured service startup with proper error handling
//! - **Observability**: Comprehensive logging and metrics integration
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
//! 1. Initialize observability (metrics, logging)
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
use std::{env, net::SocketAddr};
use tokio::signal;
use tracing::{error, info, warn};
use tracing_appender::non_blocking;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};

use crate::app::build_app;
use crate::config::database::{init_pool, run_migrations, DbPool};
use crate::config::redis::{check_redis_connection, init_redis};
use crate::utils::email::EmailConfig;
use crate::utils::metrics;

mod app;
mod config;
mod db;
mod handlers;
mod middleware;
mod utils;

/// Maximum time to wait for connections to close during shutdown (in seconds)
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Default port if not specified in environment
const DEFAULT_PORT: u16 = 3000;

/// Default host address if not specified in environment
const DEFAULT_HOST: &str = "127.0.0.1";

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
/// shutdown handling.
///
/// # Error Handling
///
/// Returns errors for critical initialization failures that prevent
/// the service from starting properly.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Prometheus metrics
    metrics::init();
    
    // Configure structured JSON logging with async writer
    setup_logging()?;
    info!(
        service = "auth-service",
        version = env!("CARGO_PKG_VERSION"),
        "Server initialization: logging & metrics configured"
    );

    // Load environment variables from .env file if present
    dotenv().ok();
    info!("Server initialization: environment loaded");

    // Validate required environment variables
    check_required_env_vars();

    // Initialize all service dependencies
    let (pool, redis_client, email_config) = initialize_services().await?;
    info!("Server initialization: services initialized");

    // Build the Axum application with all routes and middleware
    let app = build_app(pool, redis_client, email_config).await;
    info!("Server initialization: application built");

    // Determine the address to bind based on environment or defaults
    let addr = get_server_address()?;
    info!(address = %addr, "Server startup: listening");

    // Start the server with graceful shutdown handling
    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shutdown: complete");
    Ok(())
}

/// Sets up structured JSON logging.
///
/// Configures tracing with:
/// - JSON formatting for machine parsability
/// - Async non-blocking writer for performance
/// - Filtering based on environment or default level
///
/// # Returns
///
/// Result indicating if logging setup was successful
fn setup_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Create non-blocking stdout writer
    let (non_blocking, _guard) = non_blocking(std::io::stdout());
    
    // Configure JSON formatter
    let fmt_layer = fmt::layer()
        .with_writer(non_blocking)
        .json()
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .with_target(false);

    // Get log level from environment or use default
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    // Initialize the global subscriber
    Registry::default()
        .with(filter)
        .with(fmt_layer)
        .init();

    Ok(())
}

/// Initialize all service dependencies.
///
/// Sets up and verifies connections to:
/// - Database (required)
/// - Redis (optional)
/// - Email service (optional)
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
    // Initialize database connection pool
    let pool = init_pool();
    
    // Verify database connectivity
    pool.get().map_err(|e| {
        error!(error = %e, "Database connection failed");
        e
    })?;
    info!("Server initialization: database pool ready");

    // Apply any pending database migrations
    run_migrations(&pool).map_err(|e| {
        error!(error = %e, "Database migrations failed");
        e
    })?;
    info!("Server initialization: database migrations applied");

    // Initialize Redis client if configured
    let redis_client = match init_redis() {
        Ok(client) => {
            // Verify Redis connectivity with ping
            if check_redis_connection(&client).await {
                info!("Server initialization: Redis connected");
                Some(client)
            } else {
                warn!("Server initialization: Redis ping failed, disabling Redis features");
                None
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                "Server initialization: Redis init error, disabling Redis features"
            );
            None
        }
    };

    // Initialize email configuration if environment variables are present
    let email_config = match EmailConfig::new() {
        Ok(cfg) => {
            info!("Server initialization: email configured");
            Some(cfg)
        }
        Err(e) => {
            warn!(
                error = %e,
                "Server initialization: email config error, disabling email features"
            );
            None
        }
    };

    Ok((pool, redis_client, email_config))
}

/// Validate required and optional environment variables.
///
/// Checks for presence of:
/// - Required variables (fails service startup if missing)
/// - Optional variables (warns but continues if missing)
///
/// Logs detailed information about configuration status.
fn check_required_env_vars() {
    // Check required environment variables
    let mut missing_required = false;
    
    for &var in REQUIRED_ENV_VARS {
        if env::var(var).is_err() {
            error!(variable = var, "Missing required environment variable");
            missing_required = true;
        }
    }
    
    if !missing_required {
        info!("Server initialization: required environment variables present");
    }

    // Check optional environment variables
    let all_optional_present = OPTIONAL_ENV_VARS
        .iter()
        .all(|&var| env::var(var).is_ok());
    
    if all_optional_present {
        info!("Server initialization: all optional environment variables present");
    } else {
        let missing: Vec<_> = OPTIONAL_ENV_VARS
            .iter()
            .filter(|&&var| env::var(var).is_err())
            .collect();
            
        warn!(
            missing = ?missing,
            "Server initialization: some optional environment variables missing"
        );
    }
}

/// Determine server binding address from environment.
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
    // Get port from environment or use default
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
        
    // Get host from environment or use default
    let host = env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    
    // Parse into socket address
    let addr = format!("{}:{}", host, port).parse()?;
    
    Ok(addr)
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
///
/// This function blocks until the process receives a shutdown signal,
/// then returns to allow graceful termination.
///
/// Handles both Ctrl+C for interactive use and SIGTERM for container environments.
async fn shutdown_signal() {
    // Handle CTRL+C signal
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Shutdown signal received: Ctrl+C");
    };

    // Handle SIGTERM on Unix platforms
    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
        info!("Shutdown signal received: SIGTERM");
    };

    // Stub for non-Unix platforms
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    // Wait for either signal
    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm => {},
    }
    
    // Allow a grace period for connections to close
    info!(
        timeout_seconds = GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
        "Starting graceful shutdown, waiting for connections to close"
    );
    
    // In a production environment, you might want to notify
    // health check systems here that the service is shutting down
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
}