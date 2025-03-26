use axum::Server;
use config::redis::check_redis_connection;
use std::net::SocketAddr;
use dotenvy::dotenv;
use crate::app::build_app;
use crate::config::database::init_pool;
use crate::config::redis::init_redis;
use log::{info, error};
use tracing_subscriber::fmt::init as init_tracing;

mod app;
mod config;
mod db;
mod utils;
mod handlers;

#[tokio::main]
async fn main() {
    // Initialize tracing for better logging
    init_tracing();

    // Load environment variables
    dotenv().ok();
    
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
                error!("Failed to connect to Redis");
                None
            }
        }
        Err(e) => {
            error!("Failed to initialize Redis client: {}", e);
            None
        }
    };

    // Build application with database pool and Redis client
    let app = build_app(pool, redis_client).await;

    // Start the server
    let addr =  SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on {}", addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

// Helper function to chceck 