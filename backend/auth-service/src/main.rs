//! BuildHub Authentication Service
//!
//! Production-ready authentication microservice with JWT tokens, rate limiting,
//! and comprehensive observability.

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
    utils::metrics,  // Fixed: metrics is in utils module
    utils::email::EmailConfig,
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

    // Initialize tracing
    init_tracing();

    // Initialize metrics
    metrics::init();

    info!(
        service = SERVICE_NAME,
        version = SERVICE_VERSION,
        "Starting authentication service"
    );

    // Validate configuration
    validate_config()?;

    // Initialize components
    let pool = init_pool();
    run_migrations(&pool)?;
    
    // Fixed: check_database_health returns Result<(), Error>, not Result<bool, Error>
    if let Err(e) = check_database_health(&pool).await {
        error!("Database health check failed: {}", e);
        return Err("Database unhealthy".into());
    }

    let redis_client = match init_redis() {
        Ok(client) => {
            info!("Redis connected");
            Some(client)
        }
        Err(e) => {
            warn!("Redis unavailable: {}", e);
            None
        }
    };

    let email_config = match EmailConfig::new() {
        Ok(config) => {
            info!("Email configured");
            Some(config)
        }
        Err(e) => {
            warn!("Email unavailable: {}", e);
            None
        }
    };

    // Build application
    let app = build_app(pool, redis_client, email_config).await;

    // Bind address
    let addr = get_bind_address()?;

    // Start server
    info!("Listening on {}", addr);
    print_banner(&addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Service shut down gracefully");
    Ok(())
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/// Initialize tracing subscriber.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .json()
        .init();
}

/// Validate required environment variables.
fn validate_config() -> Result<(), Box<dyn std::error::Error>> {
    let required = ["DATABASE_URL", "JWT_SECRET"];
    
    for var in &required {
        if env::var(var).is_err() {
            return Err(format!("Missing required env var: {}", var).into());
        }
    }
    
    Ok(())
}

/// Get server bind address.
fn get_bind_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    
    Ok(format!("{}:{}", host, port).parse()?)
}

/// Wait for shutdown signal.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
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
        _ = ctrl_c => info!("Received Ctrl+C"),
        _ = terminate => info!("Received SIGTERM"),
    }

    info!("Starting graceful shutdown ({}s timeout)", GRACEFUL_SHUTDOWN_TIMEOUT.as_secs());
}

/// Print startup banner.
fn print_banner(addr: &SocketAddr) {
    println!(
        r#"
╔═══════════════════════════════════════════════════╗
║          BuildHub Authentication Service          ║
╠═══════════════════════════════════════════════════╣
║  Version:  {}                              ║
║  Address:  {}                    ║
║                                                   ║
║  Health:   http://{}/health            ║
║  Metrics:  http://{}/metrics           ║
║  Ready:    http://{}/readiness         ║
╚═══════════════════════════════════════════════════╝
"#,
        format!("{:<8}", SERVICE_VERSION),
        format!("{:<21}", addr),
        addr,
        addr,
        addr
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
}
