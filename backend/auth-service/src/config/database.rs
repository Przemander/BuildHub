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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, time::{SystemTime, UNIX_EPOCH}};
    

    /// Generate a unique file path in the temp directory.
    fn make_db_url() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = env::temp_dir();
        path.push(format!("test_db_{}.sqlite", nanos));
        path.to_str().unwrap().to_string()
    }

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn init_pool_no_env_panics() {
        env::remove_var("DATABASE_URL");
        // should panic because DATABASE_URL is missing
        init_pool();
    }

    #[test]
    fn init_pool_and_get_connection_success() {
        let url = make_db_url();
        env::set_var("DATABASE_URL", &url);
        let pool = init_pool();
        // Pool must yield a connection
        assert!(pool.get().is_ok());
    }

    #[test]
    #[should_panic(expected = "Failed to create database connection pool")]
    fn get_connection_failure_returns_error() {
        // point at a non‐existent directory so init_pool() panics
        let mut bad = env::temp_dir();
        bad.push("no_such_dir");
        bad.push("db.sqlite");
        env::set_var("DATABASE_URL", bad.to_str().unwrap());
        // pool creation will attempt to open and then panic
        let _ = init_pool();
    }

    #[test]
    fn run_migrations_is_idempotent() {
        let url = make_db_url();
        env::set_var("DATABASE_URL", &url);
        let pool = init_pool();
        // first run
        assert!(run_migrations(&pool).is_ok());
        // second run (no new migrations) should still succeed
        assert!(run_migrations(&pool).is_ok());
    }
}