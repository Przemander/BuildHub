//! Authentication Service main entry point.
//!
//! This module initializes logging, loads environment variables, checks configuration,
//! initializes required services (database connection pool, Redis client, email configuration),
//! initializes Prometheus metrics and builds the application's router with all middleware,
//! routes, and CORS configuration. Finally, it starts the HTTP server with graceful shutdown support.
//!
//! Best practices applied:
//! - Clear and consistent module-level and inline documentation.
//! - Structured logging at key stages, e.g., service initialization and shutdown.
//! - Metrics initialization and integration for observability via a dedicated /metrics endpoint.
//! - Dependency initialization using asynchronous functions and early error handling.

use axum::Server;
use dotenvy::dotenv;
use std::{env, net::SocketAddr};
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use redis::Client as RedisClient;
use crate::app::build_app;
// Import run_migrations along with init_pool
use crate::config::database::{init_pool, DbPool, run_migrations};
use crate::config::redis::{init_redis, check_redis_connection};
use crate::utils::email::EmailConfig;
use log::{error, warn};

mod app;
mod config;
mod db;
mod handlers;
mod middleware;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Log system configuration startup success.
    log_info!("Server initialization", "Configure logging system", "success");

    // Load environment variables from .env file.
    dotenv().ok();
    log_info!("Server initialization", "Load environment variables", "success");

    // Check for required and optional environment variables.
    check_required_env_vars();

    // Initialize required services: database pool, Redis client (optional), and email configuration (optional).
    let (pool, redis_client, email_config) = initialize_services().await?;
    log_info!("Server initialization", "Services initialization complete", "success");

    // Initialize Prometheus metrics.
    crate::utils::metrics::init();

    // Build the application with all routes, middleware and shared state.
    let app = build_app(pool, redis_client, email_config).await;
    log_info!("Server initialization", "Build application", "success");

    // Determine the server address from environment variables or use defaults.
    let addr = get_server_address()?;
    log_info!("Server startup", "Configure server address", "success");
    log_info!("Server startup", "Auth service listening", "success");

    // Bind and serve the application using graceful shutdown.
    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    log_info!("Server shutdown", "Complete shutdown sequence", "success");

    Ok(())
}

/// Initializes all required services and returns their instances.
/// 
/// This function initializes the database connection pool, runs migrations,
/// attempts to initialize the Redis client (logging warnings if unavailable),
/// and creates an email configuration.
/// 
/// # Returns
/// *(DbPool, Option<RedisClient>, Option<EmailConfig>)* on success.
/// Otherwise, it returns an error.
async fn initialize_services() -> Result<(DbPool, Option<RedisClient>, Option<EmailConfig>), Box<dyn std::error::Error>> {
    // Initialize the database connection pool.
    let pool = init_pool();
    {
        // Test that a connection can be acquired.
        let conn_result = pool.get();
        if conn_result.is_err() {
            let e = conn_result.err().unwrap();
            log_error!("Server initialization", "Test database connection", "failure");
            error!("Failed to connect to database: {}", e);
            // Return the error to stop initialization
            return Err(Box::new(e));
        }
        log_info!("Server initialization", "Database connection pool", "success");
        // Connection acquired successfully, drop it as it's no longer needed here.
        drop(conn_result.unwrap());
    }

    // Run database migrations after confirming pool is working.
    if !run_migrations(&pool) {
        log_error!("Server initialization", "Database migrations failed", "critical");
        // Exit the application if migrations fail, as it's a critical step.
        // Using std::process::exit might be abrupt in async context, returning error is better.
        return Err("Database migrations failed".into());
    } else {
        log_info!("Server initialization", "Database migrations checked/run", "success");
    }


    // Attempt to initialize Redis client.
    let redis_client = match init_redis() {
        Ok(client) => {
            log_info!("Server initialization", "Redis client created", "success");
            if check_redis_connection(&client).await {
                log_info!("Server initialization", "Test Redis connection", "success");
                Some(client)
            } else {
                log_warn!("Server initialization", "Test Redis connection", "failure");
                None
            }
        }
        Err(e) => {
            log_warn!("Server initialization", "Initialize Redis client", "failure");
            warn!("Failed to initialize Redis client: {}, continuing without Redis", e);
            None
        }
    };

    // Attempt to create email configuration.
    let email_config = match EmailConfig::new() {
        Ok(config) => {
            log_info!("Server initialization", "Initialize email configuration", "success");
            Some(config)
        }
        Err(e) => {
            log_warn!("Server initialization", "Initialize email configuration", "failure");
            warn!("Failed to initialize email configuration: {}. Email features will be disabled.", e);
            None
        }
    };

    Ok((pool, redis_client, email_config))
}

/// Parses the server address from environment variables or returns defaults.
/// 
/// Default port is 3000 and default host is "127.0.0.1".
/// 
/// # Returns
/// *SocketAddr* representing the address to bind the server.
fn get_server_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    log_info!("Server initialization", "Server port", "success");

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    log_info!("Server initialization", "Server host", "success");

    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse()?;
    log_info!("Server initialization", "Parse server address", "success");
    
    Ok(addr)
}

/// Checks required and optional environment variables and logs their status.
fn check_required_env_vars() {
    let required_vars = ["DATABASE_URL", "JWT_SECRET"];
    let mut missing_required = false;

    for var in required_vars.iter() {
        if env::var(var).is_err() {
            error!("Required environment variable '{}' is not set", var);
            missing_required = true;
        }
    }
    log_info!("Server initialization", "Check environment variables", "success");

    if missing_required {
        log_warn!("Server initialization", "Verify all required variables", "failure");
    }

    let optional_vars = ["REDIS_URL", "PORT", "HOST", "SMTP_SERVER", "SMTP_USERNAME", "SMTP_PASSWORD", "FRONTEND_URL"];
    let mut all_optional_present = true;

    for var in optional_vars.iter() {
        if env::var(var).is_err() {
            all_optional_present = false;
        }
    }

    if all_optional_present {
        log_info!("Server initialization", "Check optional environment variables", "success");
    } else {
        log_warn!("Server initialization", "Check optional environment variables", "failure");
    }
}

/// Handles OS shutdown signals to gracefully shut down the server.
/// 
/// This function listens for Ctrl+C and Unix terminate signals,
/// logging the shutdown event.
async fn shutdown_signal() {
    log_info!("Server lifecycle", "Shutdown signal handler", "success");

    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            log_info!("Server shutdown", "Received shutdown signal via Ctrl+C", "success");
        },
        _ = terminate => {
            log_info!("Server shutdown", "Received shutdown signal", "success");
        },
    };
}