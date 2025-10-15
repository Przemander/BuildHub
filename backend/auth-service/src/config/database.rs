//! Database configuration and connection pool management.
//!
//! Provides reliable PostgreSQL connectivity with connection pooling
//! and automatic migrations.

use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use std::env;
use std::str::FromStr;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::{utils::errors::AuthServiceError, utils::metrics};

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

/// Database connection pool type.
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Pooled database connection type.
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

// =============================================================================
// CONFIGURATION CONSTANTS & HELPERS
// =============================================================================

const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Helper to parse an environment variable with a default value.
fn get_env_var<T: FromStr>(name: &str, default: T) -> T {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or(default)
}

// =============================================================================
// POOL INITIALIZATION
// =============================================================================

/// Initializes the database connection pool with production-ready, configurable settings.
///
/// # Configuration (from environment variables with defaults)
/// - `DATABASE_URL`: The connection string (required).
/// - `DB_MAX_POOL_SIZE`: Max connections (default: 25).
/// - `DB_MIN_IDLE`: Min idle connections (default: 2).
/// - `DB_CONNECTION_TIMEOUT_SECS`: Connection timeout (default: 10).
/// - `DB_IDLE_TIMEOUT_SECS`: Idle connection timeout (default: 600).
/// - `DB_MAX_LIFETIME_SECS`: Max connection lifetime (default: 1800).
///
/// # Panics
/// Panics if `DATABASE_URL` is not set or pool creation fails (fail-fast for startup).
pub fn init_pool() -> DbPool {
    let database_url = env::var(DATABASE_URL_ENV).unwrap_or_else(|_| {
        error!("Missing {} environment variable", DATABASE_URL_ENV);
        panic!("DATABASE_URL must be set in .env or environment variables");
    });

    let max_size = get_env_var("DB_MAX_POOL_SIZE", 25u32);
    let min_idle = get_env_var("DB_MIN_IDLE", 2u32);
    let connection_timeout = get_env_var("DB_CONNECTION_TIMEOUT_SECS", 10u64);
    let idle_timeout = get_env_var("DB_IDLE_TIMEOUT_SECS", 600u64);
    let max_lifetime = get_env_var("DB_MAX_LIFETIME_SECS", 1800u64);

    info!("Initializing PostgreSQL connection pool");

    let manager = ConnectionManager::<PgConnection>::new(database_url);

    let pool = Pool::builder()
        .max_size(max_size)
        .min_idle(Some(min_idle))
        .connection_timeout(Duration::from_secs(connection_timeout))
        .idle_timeout(Some(Duration::from_secs(idle_timeout)))
        .max_lifetime(Some(Duration::from_secs(max_lifetime)))
        .test_on_check_out(true)
        .build(manager)
        .unwrap_or_else(|e| {
            error!("Failed to create PostgreSQL connection pool: {}", e);
            panic!("Failed to create database connection pool: {}", e);
        });

    info!(
        "PostgreSQL pool initialized (max={}, min_idle={}, timeout={}s)",
        max_size, min_idle, connection_timeout
    );

    metrics::db::pool_configured(max_size as i64);

    pool
}

// =============================================================================
// CONNECTION MANAGEMENT
// =============================================================================

/// Acquires a database connection from the pool.
///
/// Records metrics for connection acquisition attempts.
pub fn get_connection(pool: &DbPool) -> Result<DbConnection, AuthServiceError> {
    match pool.get() {
        Ok(conn) => {
            metrics::db::connection_acquired();
            Ok(conn)
        }
        Err(e) => {
            error!("Failed to acquire database connection: {}", e);
            metrics::db::connection_failed();
            Err(AuthServiceError::database(
                "Failed to acquire database connection",
            ))
        }
    }
}

// =============================================================================
// DATABASE MIGRATIONS
// =============================================================================

/// Runs pending database migrations.
///
/// Migrations are embedded in the binary and run automatically on startup.
/// This ensures the database schema is always up-to-date.
pub fn run_migrations(pool: &DbPool) -> Result<(), AuthServiceError> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

    info!("Checking for pending database migrations");
    let mut conn = get_connection(pool)?;

    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(applied) => {
            if !applied.is_empty() {
                info!("Successfully applied {} migration(s)", applied.len());
                for migration in &applied {
                    info!("  - Applied migration: {}", migration);
                }
            } else {
                info!("Database schema is up to date");
            }
            Ok(())
        }
        Err(e) => {
            error!("Failed to run database migrations: {}", e);
            Err(AuthServiceError::database("Failed to run database migrations"))
        }
    }
}

// =============================================================================
// HEALTH CHECKS
// =============================================================================

/// Performs a database health check.
///
/// Executes a simple query to verify database connectivity and responsiveness.
pub async fn check_database_health(pool: &DbPool) -> Result<(), AuthServiceError> {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        let mut conn = get_connection(&pool)?;
        diesel::sql_query("SELECT 1").execute(&mut conn).map_err(|e| {
            warn!("Database health check failed: {}", e);
            AuthServiceError::database("Database health check failed")
        })?;
        Ok(())
    })
    .await
    .map_err(|e| {
        error!("Failed to spawn health check task: {}", e);
        AuthServiceError::database("Failed to perform health check")
    })?
}