//! # BuildHub Authentication Service
//!
//! A production-ready, secure, and observable authentication microservice.
//!
//! ## Features
//! - JWT-based authentication (access & refresh tokens).
//! - Secure user registration with email activation.
//! - Two-step password reset flow.
//! - Redis-backed rate limiting and token revocation.
//! - Comprehensive observability with `tracing` and `Prometheus`.
//! - Graceful shutdown and robust error handling.

use axum::Server;
use std::{env, net::SocketAddr, time::Duration};
use tokio::signal;
use tracing::{error, info, warn};

use crate::{
    app::build_app,
    config::{
        database::{check_database_health, init_pool, run_migrations},
        redis::init_redis,
    },
    utils::{email::EmailConfig, metrics, validators},
};

// Module declarations
mod app;
mod config;
mod db;
mod handlers;
mod middleware;
mod utils;

// Service constants
const SERVICE_NAME: &str = "auth-service";
const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PORT: u16 = 3000;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file if present
    dotenvy::dotenv().ok();

    // Initialize tracing for structured logging
    init_tracing();

    // Initialize metrics and validators eagerly
    metrics::init();
    validators::init();

    info!(
        service = SERVICE_NAME,
        version = SERVICE_VERSION,
        "Starting authentication service"
    );

    // Validate required configuration
    validate_config()?;

    // Initialize database connection pool and run migrations
    let pool = init_pool();
    run_migrations(&pool)?;
    if let Err(e) = check_database_health(&pool).await {
        error!("Database health check failed: {}", e);
        return Err("Database is unhealthy, shutting down.".into());
    }

    // Initialize Redis client (optional)
    let redis_client = match init_redis() {
        Ok(client) => {
            info!("Redis connected successfully");
            Some(client)
        }
        Err(e) => {
            warn!("Redis is unavailable: {}. Some features may be disabled.", e);
            None
        }
    };

    // Initialize email client (optional)
    let email_config = match EmailConfig::new() {
        Ok(config) => {
            info!("Email service configured successfully");
            Some(config)
        }
        Err(e) => {
            warn!("Email service is unavailable: {}. Some features may be disabled.", e);
            None
        }
    };

    // Build the main Axum application
    let app = build_app(pool, redis_client, email_config).await;

    // Determine server bind address
    let addr = get_bind_address()?;

    // Start the server
    info!("Server listening on {}", addr);
    print_banner(&addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Service shut down gracefully");
    Ok(())
}

// =============================================================================
// INITIALIZATION & SHUTDOWN
// =============================================================================

/// Initializes the `tracing` subscriber for structured, JSON-formatted logs.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false) // Disable module path logging for cleaner output
        .json()
        .init();
}

/// Validates that all required environment variables are set.
fn validate_config() -> Result<(), Box<dyn std::error::Error>> {
    let required = ["DATABASE_URL", "JWT_SECRET"];
    for var in &required {
        if env::var(var).is_err() {
            let err_msg = format!("Missing required environment variable: {}", var);
            error!("{}", err_msg);
            return Err(err_msg.into());
        }
    }
    Ok(())
}

/// Determines the server's bind address from environment variables or defaults.
fn get_bind_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    Ok(format!("{}:{}", host, port).parse()?)
}

/// Listens for termination signals (Ctrl+C, SIGTERM) to trigger a graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, initiating shutdown..."),
        _ = terminate => info!("Received SIGTERM, initiating shutdown..."),
    }

    info!(
        "Graceful shutdown initiated (timeout: {}s)",
        GRACEFUL_SHUTDOWN_TIMEOUT.as_secs()
    );
}

/// Prints a startup banner with key service information.
fn print_banner(addr: &SocketAddr) {
    let version_str = format!("{:<38}", SERVICE_VERSION);
    let addr_str = format!("{:<38}", addr);
    let health_str = format!("http://{}/health", addr);
    let metrics_str = format!("http://{}/metrics", addr);
    let ready_str = format!("http://{}/readiness", addr);

    println!(
        r#"
╔═══════════════════════════════════════════════════╗
║          BuildHub Authentication Service          ║
╠═══════════════════════════════════════════════════╣
║ Version:  {}║
║ Address:  {}║
║                                                   ║
║ Health:   {:<38}║
║ Metrics:  {:<38}║
║ Ready:    {:<38}║
╚═══════════════════════════════════════════════════╝
"#,
        version_str, addr_str, health_str, metrics_str, ready_str
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_constants() {
        assert_eq!(SERVICE_NAME, "auth-service");
        assert_eq!(DEFAULT_PORT, 3000);
    }

    #[test]
    fn test_get_bind_address_default() {
        env::remove_var("HOST");
        env::remove_var("PORT");
        let addr = get_bind_address().unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:3000");
    }

    #[test]
    fn test_get_bind_address_custom() {
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", "8080");
        let addr = get_bind_address().unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:8080");
        env::remove_var("HOST");
        env::remove_var("PORT");
    }
}
