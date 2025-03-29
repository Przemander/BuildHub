use axum::Server;
use std::{net::SocketAddr, env};
use dotenvy::dotenv;
use crate::app::build_app;
use crate::config::database::init_pool;
use crate::config::redis::{init_redis, check_redis_connection};
use crate::utils::email::EmailConfig;
use log::{info, error, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod app;
mod config;
mod db;
mod utils;
mod handlers;

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
    
    // Check for required environment variables
    check_required_env_vars();

    // Initialize database connection pool
    info!("Initializing database connection pool");
    let pool = init_pool();
    
    // Initialize Redis client
    info!("Initializing Redis client");
    let redis_client = match init_redis() {
        Ok(client) => {
            if check_redis_connection(&client).await {
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

    // Build application with database pool, Redis client, and email config
    let app = build_app(pool, redis_client, email_config).await;

    // Determine address to listen on
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
        
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    
    // Parse the host string into a SocketAddr
    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse()?;
    
    info!("🚀 Server starting on {}", addr);

    // Start the server
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
        
    Ok(())
}

fn check_required_env_vars() {
    let required_vars = ["DATABASE_URL", "JWT_SECRET"];
    
    for var in required_vars.iter() {
        if env::var(var).is_err() {
            error!("Required environment variable '{}' is not set", var);
        }
    }

    let optional_vars = ["REDIS_URL", "PORT", "HOST", "SMTP_SERVER", "SMTP_USERNAME", "SMTP_PASSWORD", "FRONTEND_URL"];
    
    for var in optional_vars.iter() {
        if env::var(var).is_err() {
            warn!("Optional environment variable '{}' is not set, using default", var);
        }
    }
}