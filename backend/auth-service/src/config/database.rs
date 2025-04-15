//! Database configuration and connection pool management.
//!
//! This module sets up and manages the SQLite database connection pool using Diesel and r2d2.
//! It also runs pending migrations and performs health checks. Logging is focused on critical
//! events and errors, while metrics track essential operations.
//!
//! Best practices applied:
//! - Clear documentation with Rust doc comments.
//! - Logging critical events with log_info, log_warn, and log_error.
//! - Metrics integration to observe important database operations.
//! - Graceful error handling with meaningful return values.

use diesel::r2d2::{ConnectionManager, Pool};
use diesel::SqliteConnection;
use std::env;
use crate::{log_debug, log_error, log_info, log_warn};

// Metrics (adjust these metric names according to your metrics definitions).
use crate::utils::metrics::{DB_OPERATIONS, DB_HEALTH};

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
        .max_size(15)      // SQLite limits concurrent writers.
        .min_idle(Some(1)) // Ensure at least one idle connection.
        .build(manager)
        .expect("Failed to create database connection pool.");
    
    // Log pool configuration at the debug level.
    log_debug!("Database", "Connection pool parameters configured", "success");
    DB_OPERATIONS.with_label_values(&["pool", "init"]).inc();
    pool
}

/// Runs pending database migrations to update the schema.
///
/// Returns true if migrations run successfully, or false if an error occurred.
pub fn run_migrations(pool: &DbPool) -> bool {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    
    match pool.get() {
        Ok(mut conn) => {
            DB_OPERATIONS.with_label_values(&["migration", "attempt"]).inc();
            match conn.run_pending_migrations(MIGRATIONS) {
                Ok(_) => {
                    log_info!("Database", "Migrations executed successfully", "success");
                    DB_OPERATIONS.with_label_values(&["migration", "success"]).inc();
                    true
                },
                Err(e) => {
                    log_error!("Database", "Migrations execution failed", "failure");
                    DB_OPERATIONS.with_label_values(&["migration", "failure"]).inc();
                    eprintln!("Migration error: {}", e);
                    false
                }
            }
        },
        Err(e) => {
            log_error!("Database", "Failed to acquire connection for migrations", "failure");
            DB_OPERATIONS.with_label_values(&["migration", "conn_failure"]).inc();
            eprintln!("Connection error: {}", e);
            false
        }
    }
}

/// Checks the health of the database by executing a simple query.
///
/// Updates a gauge metric to indicate healthy status.
/// Returns true if the query succeeds, or false otherwise.
pub fn check_database_health(pool: &DbPool) -> bool {
    use diesel::sql_query;
    use diesel::RunQueryDsl;

    match pool.get() {
        Ok(mut conn) => {
            match sql_query("SELECT 1").execute(&mut conn) {
                Ok(_) => {
                    log_info!("Database", "Health check succeeded", "success");
                    DB_HEALTH.set(1.0);
                    true
                },
                Err(_) => {
                    log_warn!("Database", "Health check query failed", "failure");
                    DB_HEALTH.set(0.0);
                    false
                }
            }
        },
        Err(_) => {
            log_error!("Database", "Failed to acquire connection for health check", "failure");
            DB_HEALTH.set(0.0);
            false
        }
    }
}