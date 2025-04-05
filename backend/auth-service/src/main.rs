//! Authentication Service main entry point.
//!
//! This module initializes the server, sets up middleware,
//! and starts the HTTP server to handle API requests.

use axum::Server;
use std::{net::SocketAddr, env};
use dotenvy::dotenv;
use tokio::signal;
use crate::app::build_app;
use crate::config::database::{init_pool, DbPool};
use crate::config::redis::{init_redis, check_redis_connection};
use redis::Client as RedisClient;
use crate::utils::email::EmailConfig;
use log::{info, error, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod app;
mod config;
mod db;
mod utils;
mod handlers;
mod middleware;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "auth_service=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenv().ok();
    info!("Environment variables loaded");
    
    // Check for required environment variables
    check_required_env_vars();

    // Initialize services
    let (pool, redis_client, email_config) = initialize_services().await?;

    // Build application with database pool, Redis client, and email config
    let app = build_app(pool, redis_client, email_config).await;
    info!("Application built successfully");

    // Determine address to listen on
    let addr = get_server_address()?;
    info!("🚀 Server starting on {}", addr);

    // Start the server with graceful shutdown signal handling
    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
        
    info!("Server shutdown complete");
    Ok(())
}

/// Initialize all required services and return their instances.
/// 
/// This function handles initialization of:
/// - Database connection pool
/// - Redis client (optional)
/// - Email configuration (optional)
///
/// # Returns
/// A tuple containing the initialized services or None if they failed to initialize
async fn initialize_services() -> Result<(DbPool, Option<RedisClient>, Option<EmailConfig>), Box<dyn std::error::Error>> {
    
    // Initialize database connection pool
    info!("Initializing database connection pool");
    let pool = init_pool();
    
    // Test database connection
    {
        let conn = pool.get().map_err(|e| {
            error!("Failed to connect to database: {}", e);
            e
        })?;
        
        info!("Database connection successful");
        drop(conn);
    }
    
    // Initialize Redis client
    info!("Initializing Redis client");
    let redis_client = match init_redis() {
        Ok(client) => {
            if check_redis_connection(&client).await {
                info!("Redis connection successful");
                Some(client)
            } else {
                warn!("Redis connection test failed, continuing without Redis");
                None
            }
        }
        Err(e) => {
            warn!("Failed to initialize Redis client: {}, continuing without Redis", e);
            None
        }
    };
    
    // Initialize email configuration
    info!("Initializing email configuration");
    let email_config = match EmailConfig::new() {
        Ok(config) => {
            info!("Email configuration initialized successfully");
            Some(config)
        }
        Err(e) => {
            warn!("Failed to initialize email configuration: {}. Email features will be disabled.", e);
            None
        }
    };

    Ok((pool, redis_client, email_config))
}

/// Parse the server address from environment variables or use defaults.
///
/// # Returns
/// A properly formatted SocketAddr to bind the server to
fn get_server_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    // Determine address to listen on
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
        
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    
    // Parse the host string into a SocketAddr
    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse()?;
    
    Ok(addr)
}

/// Check required and optional environment variables and log their status.
fn check_required_env_vars() {
    let required_vars = ["DATABASE_URL", "JWT_SECRET"];
    let mut missing_required = false;
    
    for var in required_vars.iter() {
        if env::var(var).is_err() {
            error!("Required environment variable '{}' is not set", var);
            missing_required = true;
        } else {
            info!("Required environment variable '{}' is set", var);
        }
    }

    if missing_required {
        warn!("Some required environment variables are missing. The application may not function correctly.");
    }

    let optional_vars = ["REDIS_URL", "PORT", "HOST", "SMTP_SERVER", "SMTP_USERNAME", "SMTP_PASSWORD", "FRONTEND_URL"];
    
    for var in optional_vars.iter() {
        if env::var(var).is_err() {
            warn!("Optional environment variable '{}' is not set, using default", var);
        } else {
            info!("Optional environment variable '{}' is set", var);
        }
    }
}

/// Handles OS shutdown signals to gracefully shut down the server.
///
/// This function waits for SIGINT (Ctrl+C) or SIGTERM signals
/// and returns when one is received, allowing the server to
/// gracefully complete in-flight requests before shutting down.
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
        _ = ctrl_c => {
            info!("SIGINT received, starting graceful shutdown");
        },
        _ = terminate => {
            info!("SIGTERM received, starting graceful shutdown");
        },
    }
}