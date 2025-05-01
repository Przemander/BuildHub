//! Database configuration and connection pool management.
//!
//! This module sets up and manages the SQLite database connection pool using Diesel and r2d2.
//! It also runs pending migrations. Logging is focused on critical
//! events and errors, while metrics track essential operations.
//!
//! Best practices applied:
//! - Clear documentation with Rust doc comments.
//! - Logging critical events with log_info, log_debug, and log_error.
//! - Metrics integration to observe important database operations.
//! - Graceful error handling with meaningful return values.

use crate::utils::errors::DatabaseError;
use crate::utils::metrics::DB_OPERATIONS;
use crate::{log_debug, log_error, log_info};
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::SqliteConnection;
use std::env;
use tracing_error::SpanTrace;

/// Type alias for the database connection pool.
pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Initializes the database connection pool using the DATABASE_URL environment variable.
///
/// # Panics
/// Panics if DATABASE_URL is not set or if pool creation fails.
pub fn init_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env or environment variables");

    log_info!("Database", "Initializing connection pool", "success");
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);

    // Configure the pool with reasonable defaults for SQLite.
    let pool = Pool::builder()
        .max_size(15) // SQLite limits concurrent writers.
        .min_idle(Some(1)) // Ensure at least one idle connection.
        .connection_timeout(std::time::Duration::from_secs(10))
        .build(manager)
        .unwrap_or_else(|e| {
            log_error!(
                "Database",
                &format!("Failed to create connection pool: {}", e),
                "failure"
            );
            DB_OPERATIONS
                .with_label_values(&["pool", "failure"])
                .inc();
            panic!("Failed to create database connection pool: {}", e);
        });

    log_debug!(
        "Database",
        "Connection pool parameters configured",
        "success"
    );
    DB_OPERATIONS.with_label_values(&["pool", "init"]).inc();
    pool
}

/// Retrieves a connection from the database pool.
///
/// Increments metrics for both success and failure.
pub fn get_connection(
    pool: &DbPool,
) -> Result<PooledConnection<ConnectionManager<SqliteConnection>>, DatabaseError> {
    match pool.get() {
        Ok(conn) => {
            DB_OPERATIONS
                .with_label_values(&["connection", "success"])
                .inc();
            Ok(conn)
        }
        Err(e) => {
            log_error!(
                "Database",
                &format!("Failed to acquire connection: {}", e),
                "failure"
            );
            DB_OPERATIONS
                .with_label_values(&["connection", "failure"])
                .inc();
            Err(DatabaseError::Connection {
                source: Box::new(e),
                span: SpanTrace::capture(),
            })
        }
    }
}

/// Runs pending database migrations to update the schema.
///
/// Returns Ok(()) if migrations run successfully, or DatabaseError otherwise.
pub fn run_migrations(pool: &DbPool) -> Result<(), DatabaseError> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

    let mut conn = get_connection(pool)?;

    DB_OPERATIONS
        .with_label_values(&["migration", "attempt"])
        .inc();
    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(_) => {
            log_info!("Database", "Migrations executed successfully", "success");
            DB_OPERATIONS
                .with_label_values(&["migration", "success"])
                .inc();
            Ok(())
        }
        Err(e) => {
            log_error!(
                "Database",
                &format!("Migrations execution failed: {}", e),
                "failure"
            );
            DB_OPERATIONS
                .with_label_values(&["migration", "failure"])
                .inc();
            Err(DatabaseError::Migration {
                source: e,
                span: SpanTrace::capture(),
            })
        }
    }
}