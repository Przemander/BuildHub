//! # BuildHub Authentication Service
//!
//! A production-ready authentication microservice built with Rust, featuring:
//!
//! - **Enterprise Security**: JWT-based authentication with refresh tokens
//! - **High Performance**: Async Rust with Tokio runtime
//! - **Observability**: OpenTelemetry tracing, Prometheus metrics, structured logging
//! - **Resilience**: Circuit breakers, rate limiting, graceful degradation
//! - **Cloud Native**: Docker ready, Kubernetes compatible health probes
//!
//! ## Architecture
//!
//! The service follows Domain-Driven Design with clean architecture:
//! - Presentation Layer: HTTP handlers and middleware
//! - Application Layer: Business logic and workflows
//! - Domain Layer: Core entities and rules
//! - Infrastructure Layer: Database, cache, external services
//!
//! ## Features
//!
//! - User registration with email activation
//! - Secure login with account lockout protection
//! - Token refresh with rotation
//! - Password reset flow
//! - Rate limiting per endpoint
//! - Comprehensive audit logging

use axum::Server;
use std::{env, net::SocketAddr, time::Duration, sync::OnceLock};
use tokio::{signal, time::timeout};
use tracing::{error, info, warn};

// Internal imports organized by layer
use crate::{
    app::build_app,
    config::{
        database::{check_database_health, init_pool, run_migrations, DbPool},
        redis::{check_redis_connection, init_redis},
    },
    metricss::{
        core::{record_startup_attempt, record_startup_failure, record_startup_success},
        init_all_metrics,
    },
    utils::{
        email::EmailConfig,
        log_new::Log,
        otel::init_telemetry,
    },
};

// Module declarations
mod app;
mod config;
mod db;
mod handlers;
mod metricss;
mod middleware;
mod utils;

// Configuration constants
const SERVICE_NAME: &str = "auth-service";
const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PORT: u16 = 3000;
const DEFAULT_HOST: &str = "0.0.0.0";
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

// Required environment variables
const REQUIRED_ENV_VARS: &[&str] = &[
    "DATABASE_URL",
    "JWT_SECRET",
];

// Optional environment variables with defaults
const OPTIONAL_ENV_VARS: &[(&str, &str)] = &[
    ("REDIS_URL", "redis://localhost:6379"),
    ("SMTP_SERVER", "smtp://localhost:25"),
    ("FRONTEND_URL", "http://localhost:3000"),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
    ("APP_ENV", "development"),
    ("LOG_LEVEL", "info"),
    ("RUST_LOG", "info"),
];

/// Application entry point with comprehensive initialization and error handling.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Record startup attempt for metrics
    record_startup_attempt();
    let start_time = std::time::Instant::now();

    // Load environment variables from .env file if present (development)
    if let Err(e) = dotenvy::dotenv() {
        if !matches!(e, dotenvy::Error::Io(_)) {
            eprintln!("Warning: Error loading .env file: {}", e);
        }
    }

    // Initialize observability stack first (logging, tracing, metrics)
    initialize_observability()?;

    // Log service startup
    info!(
        service = SERVICE_NAME,
        version = SERVICE_VERSION,
        "Starting authentication service"
    );

    // Validate environment configuration
    validate_configuration()?;

    // Initialize all components with timeout
    let components = timeout(STARTUP_TIMEOUT, initialize_components()).await??;

    // Build the application
    let app = build_app(
        components.db_pool.clone(),
        components.redis_client.clone(),
        components.email_config.clone(),
    )
    .await;

    // Determine bind address
    let addr = get_bind_address()?;

    // Create server with graceful shutdown
    let server = Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal());

    // Record successful startup
    let startup_duration = start_time.elapsed();
    record_startup_success();
    
    info!(
        addr = %addr,
        duration_ms = startup_duration.as_millis(),
        "Service started successfully"
    );

    // Print startup banner
    print_startup_banner(&addr);

    // Run the server
    match server.await {
        Ok(_) => {
            info!("Service shut down gracefully");
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "Server error during runtime");
            Err(e.into())
        }
    }
}

/// Service components initialized during startup
struct ServiceComponents {
    db_pool: DbPool,
    redis_client: Option<redis::Client>,
    email_config: Option<EmailConfig>,
}

/// Initialize logging, tracing, and metrics
fn initialize_observability() -> Result<(), Box<dyn std::error::Error>> {
    static OBS_ONCE: OnceLock<()> = OnceLock::new();

    OBS_ONCE.get_or_init(|| {
        let otel_enabled = env::var("OTEL_ENABLED").unwrap_or_else(|_| "true".into()) == "true";

        if otel_enabled {
            // Try OTEL; on failure, fall back to basic fmt subscriber
            if let Err(e) = init_telemetry() {
                eprintln!("OpenTelemetry init failed: {e}. Falling back to basic tracing.");
                let _ = tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .with_target(false)
                    .json()
                    .try_init(); // never panic if already set
            } else {
                eprintln!("OpenTelemetry initialized");
            }
        } else {
            // Basic tracing; never panic if already set elsewhere
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_target(false)
                .json()
                .try_init();
            eprintln!("Basic tracing initialized");
        }
    });

    // Now tracing is safe to use
    info!("Tracing system initialized");

    // Initialize Prometheus metrics
    init_all_metrics();
    info!("Metrics system initialized");

    // Optional structured log event
    Log::event(
        "INFO",
        "Service",
        "Observability stack initialized",
        "observability_init_success",
        "initialize_observability",
    );

    Ok(())
}

/// Validate required and optional environment variables
fn validate_configuration() -> Result<(), Box<dyn std::error::Error>> {
    info!("Validating service configuration");

    // Check required variables
    let mut missing_required = Vec::new();
    for var in REQUIRED_ENV_VARS {
        if env::var(var).is_err() {
            missing_required.push(*var);
        }
    }

    if !missing_required.is_empty() {
        let error_msg = format!(
            "Missing required environment variables: {}",
            missing_required.join(", ")
        );
        error!("{}", error_msg);
        record_startup_failure();
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, error_msg)));
    }

    // Check optional variables and set defaults
    for (var, default) in OPTIONAL_ENV_VARS {
        if env::var(var).is_err() {
            warn!(
                variable = var,
                default = default,
                "Optional environment variable not set, using default"
            );
            env::set_var(var, default);
        }
    }

    // Log configuration summary
    let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
    info!(
        environment = app_env,
        "Configuration validated successfully"
    );

    Ok(())
}

/// Initialize all service components with health checks
async fn initialize_components() -> Result<ServiceComponents, Box<dyn std::error::Error>> {
    info!("Initializing service components");

    // Initialize database
    info!("Connecting to database");
    let db_pool = init_pool();
    
    // Run migrations
    info!("Running database migrations");
    run_migrations(&db_pool).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    
    // Verify database health
    if !check_database_health(&db_pool).await? {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Database health check failed"
        )));
    }
    info!("Database initialized successfully");

    // Initialize Redis (optional)
    let redis_client = match init_redis() {
        Ok(client) => {
            if check_redis_connection(&client).await {
                info!("Redis initialized successfully");
                Some(client)
            } else {
                warn!("Redis connection check failed, continuing without Redis");
                None
            }
        }
        Err(e) => {
            warn!(error = %e, "Redis initialization failed, continuing without Redis");
            None
        }
    };

    // Initialize email configuration (optional)
    let email_config = match EmailConfig::new() {
        Ok(config) => {
            info!("Email service configured successfully");
            Some(config)
        }
        Err(e) => {
            warn!(error = %e, "Email configuration failed, continuing without email");
            None
        }
    };

    // Log component summary
    Log::event(
        "INFO",
        "Service",
        &format!(
            "Components initialized - Database: ✓, Redis: {}, Email: {}",
            if redis_client.is_some() { "✓" } else { "✗" },
            if email_config.is_some() { "✓" } else { "✗" }
        ),
        "components_initialized",
        "initialize_components",
    );

    Ok(ServiceComponents {
        db_pool,
        redis_client,
        email_config,
    })
}

/// Determine the socket address to bind the server
fn get_bind_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let host = env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("{}:{}", host, port).parse()?;
    Ok(addr)
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
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
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        }
        _ = terminate => {
            info!("Received SIGTERM signal");
        }
    }

    info!(
        timeout_secs = GRACEFUL_SHUTDOWN_TIMEOUT.as_secs(),
        "Starting graceful shutdown"
    );

    // Give connections time to close gracefully
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Print startup banner with service information
fn print_startup_banner(addr: &SocketAddr) {
    let banner = format!(
        r#"
╔═══════════════════════════════════════════════════════════════╗
║                   BuildHub Authentication Service              ║
╠═══════════════════════════════════════════════════════════════╣
║  Version:     {}                                        ║
║  Environment: {}                                   ║
║  Address:     {}                           ║
║                                                               ║
║  Health:      http://{}/health                     ║
║  Metrics:     http://{}/metrics                    ║
║  Ready:       http://{}/readiness                  ║
╚═══════════════════════════════════════════════════════════════╝
"#,
        format!("{:<8}", SERVICE_VERSION),
        format!("{:<12}", env::var("APP_ENV").unwrap_or_else(|_| "development".to_string())),
        format!("{:<21}", addr),
        addr,
        addr,
        addr
    );

    println!("{}", banner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_env_vars_constant() {
        assert!(!REQUIRED_ENV_VARS.is_empty());
        assert!(REQUIRED_ENV_VARS.contains(&"DATABASE_URL"));
        assert!(REQUIRED_ENV_VARS.contains(&"JWT_SECRET"));
    }

    #[test]
    fn test_service_constants() {
        assert_eq!(SERVICE_NAME, "auth-service");
        assert_eq!(DEFAULT_PORT, 3000);
        assert_eq!(DEFAULT_HOST, "0.0.0.0");
    }

    #[test]
    fn test_optional_env_vars_have_defaults() {
        for (var, default) in OPTIONAL_ENV_VARS {
            assert!(!var.is_empty());
            assert!(!default.is_empty());
        }
    }
}
