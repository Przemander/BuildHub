//! Authentication Service main entry point.
//!
//! - Initializes logging, metrics, config, services, builds the app and starts the HTTP server.
//! - Production-ready: robust error handling, graceful shutdown, and clear startup sequence.

use axum::Server;
use dotenvy::dotenv;
use metrics_exporter_prometheus::PrometheusBuilder;
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

mod app;
mod config;
mod db;
mod handlers;
mod middleware;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Install Prometheus metrics exporter on :9000 (/metrics)
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], 9000))
        .install()?;

    // 2) Initialize tracing_subscriber to write JSON logs to stdout
    let (non_blocking, _guard) = non_blocking(std::io::stdout());
    let fmt_layer = fmt::layer()
        .with_writer(non_blocking)
        .json()                       // ⇠ use JSON for events & span‐fields
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .with_target(false);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    Registry::default().with(filter).with(fmt_layer).init();

    info!("Server initialization: logging & metrics configured");

    // 3) Load environment variables
    dotenv().ok();
    info!("Server initialization: environment loaded");

    // 4) Validate required env vars
    check_required_env_vars();

    // 5) Initialize services (DB pool, Redis, email)
    let (pool, redis_client, email_config) = initialize_services().await?;
    info!("Server initialization: services initialized");

    // 6) Build the Axum application
    let app = build_app(pool, redis_client, email_config).await;
    info!("Server initialization: application built");

    // 7) Determine bind address
    let addr = get_server_address()?;
    info!(%addr, "Server startup: listening");

    // 8) Serve with graceful shutdown
    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shutdown: complete");
    Ok(())
}

/// Initialize database pool, run migrations, Redis client and email config.
async fn initialize_services(
) -> Result<(DbPool, Option<RedisClient>, Option<EmailConfig>), Box<dyn std::error::Error>> {
    // Database pool
    let pool = init_pool();
    pool.get().map_err(|e| {
        error!("Database connection failed: {}", e);
        e
    })?;
    info!("Server initialization: database pool ready");

    run_migrations(&pool).map_err(|e| {
        error!("Database migrations failed: {}", e);
        e
    })?;
    info!("Server initialization: database migrations applied");

    // Redis client (optional)
    let redis_client = match init_redis() {
        Ok(client) => {
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
                "Server initialization: Redis init error: {}, disabling Redis",
                e
            );
            None
        }
    };

    // Email config (optional)
    let email_config = match EmailConfig::new() {
        Ok(cfg) => {
            info!("Server initialization: email configured");
            Some(cfg)
        }
        Err(e) => {
            warn!(
                "Server initialization: email config error: {}, disabling email",
                e
            );
            None
        }
    };

    Ok((pool, redis_client, email_config))
}

/// Check required and optional environment variables.
fn check_required_env_vars() {
    let required = ["DATABASE_URL", "JWT_SECRET"];
    let mut missing = false;
    for &var in &required {
        if env::var(var).is_err() {
            error!("Missing required env var: {}", var);
            missing = true;
        }
    }
    if !missing {
        info!("Server initialization: required env vars present");
    }

    let optional = [
        "REDIS_URL",
        "SMTP_SERVER",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "FRONTEND_URL",
    ];
    let all_opt = optional.iter().all(|&v| env::var(v).is_ok());
    if all_opt {
        info!("Server initialization: optional env vars present");
    } else {
        warn!("Server initialization: some optional env vars missing");
    }
}

/// Parse HOST and PORT, defaulting to 127.0.0.1:3000.
fn get_server_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = format!("{}:{}", host, port).parse()?;
    Ok(addr)
}

/// Wait for Ctrl+C or terminate signal.
async fn shutdown_signal() {
    let ctrl = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let term = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl => info!("Shutdown signal received: Ctrl+C"),
        _ = term => info!("Shutdown signal received: SIGTERM"),
    }
}