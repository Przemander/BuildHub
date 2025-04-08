//! Authentication Service main entry point.
//!
//! This module initializes the server, sets up middleware,
//! and starts the HTTP server to handle API requests.

use axum::Server;
use utils::log::Log;
use std::{net::SocketAddr, env};
use dotenvy::dotenv;
use tokio::signal;
use crate::app::build_app;
use crate::config::database::{init_pool, DbPool};
use crate::config::redis::{init_redis, check_redis_connection};
use redis::Client as RedisClient;
use crate::utils::email::EmailConfig;
use log::{error, warn};
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
    
    Log::debug(
        "Server initialization", 
        "Configure logging system", 
        "success"
    );

    // Load environment variables
    dotenv().ok();
    
    Log::debug(
        "Server initialization",
        "Load environment variables", 
        "success"
    );
    
    // Check for required environment variables
    check_required_env_vars();
    
    let (pool, redis_client, email_config) = initialize_services().await?;

    Log::debug(
        "Server initialization",
        "Services initialization complete",
        "success"
    );

    
    let app = build_app(pool, redis_client, email_config).await;
    
    Log::debug(
        "Server initialization",
        "Build application",
        "success"
    );

    // Determine address to listen on
    let addr = get_server_address()?;
    
    Log::debug(
        "Server startup",
        "Configure server address",
        "success"
    );
    
    // Log startup message
    Log::info(
        "Server startup",
        "Auth service listening",
        "success"
    );
    
    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
        
    Log::info(
        "Server shutdown",
        "Complete shutdown sequence",
        "success"
    );
    
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
    

    let pool = init_pool();
    
    {
        let conn = pool.get().map_err(|e| {
            Log::error(
                "Server initialization",
                "Test database connection",
                "failure"
            );
            error!("Failed to connect to database: {}", e);
            e
        })?;
        
        Log::info(
            "Server initialization",
            "Database connection pool",
            "success"
        );
        
        drop(conn);
    }
    
    
    let redis_client = match init_redis() {
        Ok(client) => {
            Log::info(
                "Server initialization",
                "Redis client created",
                "success"
            );
            
            if check_redis_connection(&client).await {
                Log::debug(
                    "Server initialization",
                    "Test Redis connection",
                    "success"
                );
                Some(client)
            } else {
                Log::warn(
                    "Server initialization",
                    "Test Redis connection",
                    "failure"
                );
                
                Log::debug(
                    "Server initialization",
                    "Redis connection test",
                    "failure"
                );
                
                None
            }
        }
        Err(e) => {
            Log::warn(
                "Server initialization",
                "Initialize Redis client",
                "failure"
            );
        
            warn!("Failed to initialize Redis client: {}, continuing without Redis", e);
            None
        }
    };
    

    let email_config = match EmailConfig::new() {
        Ok(config) => {
            Log::info(
                "Server initialization",
                "Initialize email configuration",
                "success");
            
            Some(config)
        }
        Err(e) => {
            Log::warn(
                "Server initialization",
                "Initialize email configuration",
                "failure"
            );
            
            Log::debug(
                "Server initialization",
                "Email configuration error",
                "failure"
            );
            
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
        
    Log::debug(
        "Server initialization",
        "Server port",
        "success"
    );
    
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    
    Log::debug(
        "Server initialization",
        "Server host",
        "success"
    );
    
    // Parse the host string into a SocketAddr
    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse()?;
    
    Log::info(
        "Server initialization",
        "Parse server address",
        "success"
    );
    
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
    }};

    Log::debug(
        "Server initialization",
        "Check environment variable",
        "success"
    );
    
    if missing_required {
        Log::warn(
            "Server initialization",
            "Verify all required variables",
            "failure"
        )
    };
    

    let optional_vars = ["REDIS_URL", "PORT", "HOST", "SMTP_SERVER", "SMTP_USERNAME", "SMTP_PASSWORD", "FRONTEND_URL"];
    let mut all_optional_present = true;
    let mut missing_count = 0;
    
    for var in optional_vars.iter() {
        if env::var(var).is_err() {
            Log::debug(
                "Server initialization",
                "Check environment variable",
                "failure"
            );
            
            all_optional_present = false;
            missing_count += 1;
        } else {
            Log::debug(
                "Server initialization",
                "Check environment variable",
                "success"
            );
        }
    }
    
    if all_optional_present {
        Log::info(
            "Server initialization",
            "Check optional environment variables",
            "success"
        );
    } else {
        Log::info(
            "Server initialization",
            "Check optional environment variables",
            "partial"
        );
    }
}

/// Handles OS shutdown signals to gracefully shut down the server.
///
/// This function waits for SIGINT (Ctrl+C) or SIGTERM signals
/// and returns when one is received, allowing the server to
/// gracefully complete in-flight requests before shutting down.
async fn shutdown_signal() {
    Log::debug(
        "Server lifecycle",
        "Shutdown signal handler",
        "success"
    );

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
            Log::info(
                "Server shutdown",
                "Receive shutdown signal",
                "success"
            );
        },
        _ = terminate => {
            Log::info(
                "Server shutdown",
                "Receive shutdown signal",
                "success"
            );
        },
    };
}