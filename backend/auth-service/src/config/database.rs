//! Database configuration and connection pool management.
//!
//! This module sets up and manages the SQLite database connection pool using Diesel and r2d2.
//! It handles initialization, connection acquisition, and schema migrations while providing
//! comprehensive observability through metrics and structured logging.
//!
//! # Features
//!
//! - Thread-safe connection pooling with configurable parameters
//! - Automatic schema migrations with embedded migrations
//! - Comprehensive metrics tracking for all database operations
//! - Structured logging with contextual error information
//! - Error handling with detailed context preservation
//! - Graceful connection handling under high load
//!
//! # Configuration
//!
//! The module requires a `DATABASE_URL` environment variable pointing to a valid SQLite
//! database file. For development, this is typically a file path like:
//! `sqlite:///path/to/database.db`.

use crate::utils::errors::DatabaseError;
use crate::utils::metrics::{DB_CONNECTION_OPERATIONS, DB_MIGRATION_OPERATIONS, DB_POOL_OPERATIONS};
use crate::{log_error, log_info};
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::SqliteConnection;
use std::env;
use std::time::Duration;
use tracing_error::SpanTrace;

/// Type alias for the database connection pool.
pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Type alias for a pooled database connection.
pub type DbConnection = PooledConnection<ConnectionManager<SqliteConnection>>;

/// Environment variable name for database URL.
const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Default connection timeout in seconds.
const DEFAULT_CONNECTION_TIMEOUT_SECONDS: u64 = 10;

/// Default maximum pool size.
const DEFAULT_MAX_POOL_SIZE: u32 = 15;

/// Default minimum idle connections.
const DEFAULT_MIN_IDLE: u32 = 1;

/// Initializes the database connection pool using the DATABASE_URL environment variable.
///
/// This function creates a connection pool with optimized settings for SQLite:
/// - Connection timeout of 10 seconds
/// - Maximum 15 connections (SQLite has limitations on concurrent writers)
/// - At least 1 idle connection for faster response times
///
/// # Panics
///
/// - If `DATABASE_URL` environment variable is not set
/// - If the pool creation fails for any reason (invalid URL, filesystem issues, etc.)
///
/// # Example
///
/// ```
/// use crate::config::database;
///
/// std::env::set_var("DATABASE_URL", "sqlite::memory:");
/// let pool = database::init_pool();
/// // Now use the pool for database operations
/// ```
pub fn init_pool() -> DbPool {
    let database_url = env::var(DATABASE_URL_ENV)
        .expect("DATABASE_URL must be set in .env or environment variables");

    log_info!(
        "Database", 
        &format!("Initializing connection pool with URL: {}", mask_db_url(&database_url)), 
        "initialization"
    );
    
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);

    // Configure the pool with optimized settings for SQLite
    let pool = Pool::builder()
        .max_size(DEFAULT_MAX_POOL_SIZE) // SQLite limits concurrent writers
        .min_idle(Some(DEFAULT_MIN_IDLE)) // Ensure at least one idle connection
        .connection_timeout(Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECONDS))
        .build(manager)
        .unwrap_or_else(|e| {
            log_error!("Database", &format!("Failed to create connection pool: {}", e), "initialization_error");
            DB_POOL_OPERATIONS.with_label_values(&["failure"]).inc();
            panic!("Failed to create database connection pool: {}", e);
        });

    log_info!("Database", &format!("Connection pool initialized (max_size={}, min_idle={})", 
        DEFAULT_MAX_POOL_SIZE, DEFAULT_MIN_IDLE), "initialization_success");
    
    DB_POOL_OPERATIONS.with_label_values(&["success"]).inc();
    
    pool
}

/// Retrieves a connection from the database pool with proper error handling.
///
/// This function attempts to get a connection from the pool and wraps any errors
/// in a strongly-typed `DatabaseError`. It also increments metrics for both
/// success and failure scenarios.
///
/// # Arguments
///
/// * `pool` - Database connection pool to get connection from
///
/// # Returns
///
/// * `Ok(DbConnection)` - A pooled database connection ready for use
/// * `Err(DatabaseError)` - Error with context if connection acquisition fails
///
/// # Example
///
/// ```
/// use crate::config::database;
///
/// fn example_function(pool: &database::DbPool) -> Result<(), database::DatabaseError> {
///     let conn = database::get_connection(pool)?;
///     // Use conn for database operations
///     Ok(())
/// }
/// ```
pub fn get_connection(pool: &DbPool) -> Result<DbConnection, DatabaseError> {
    match pool.get() {
        Ok(conn) => {
            DB_CONNECTION_OPERATIONS.with_label_values(&["success"]).inc();
            Ok(conn)
        }
        Err(e) => {
            log_error!("Database", &format!("Failed to acquire connection: {}", e), "connection_error");
            DB_CONNECTION_OPERATIONS.with_label_values(&["failure"]).inc();
            Err(DatabaseError::Connection {
                source: Box::new(e),
                span: SpanTrace::capture(),
            })
        }
    }
}

/// Runs pending database migrations to update the schema.
///
/// This function applies any pending migrations from the embedded migrations directory.
/// It is safe to call this function multiple times; it will only apply migrations
/// that haven't been run yet.
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Returns
///
/// * `Ok(())` - If migrations run successfully or there were no pending migrations
/// * `Err(DatabaseError)` - If migrations failed to run
///
/// # Example
///
/// ```
/// use crate::config::database;
///
/// fn initialize_database() -> Result<(), database::DatabaseError> {
///     let pool = database::init_pool();
///     database::run_migrations(&pool)?;
///     Ok(())
/// }
/// ```
pub fn run_migrations(pool: &DbPool) -> Result<(), DatabaseError> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    // Define embedded migrations
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

    // Get a database connection
    let mut conn = get_connection(pool)?;

    log_info!("Database", "Running pending migrations...", "migration_attempt");
    DB_MIGRATION_OPERATIONS.with_label_values(&["attempt"]).inc();
    
    // Run migrations and handle the result
    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(applied) => {
            let count = applied.len();
            if count > 0 {
                log_info!(
                    "Database", 
                    &format!("Applied {} migrations successfully", count), 
                    "migration_success"
                );
            } else {
                log_info!(
                    "Database", 
                    "No pending migrations to apply", 
                    "migration_success"
                );
            }
            
            DB_MIGRATION_OPERATIONS.with_label_values(&["success"]).inc();
            
            Ok(())
        }
        Err(e) => {
            log_error!(
                "Database",
                &format!("Migration execution failed: {}", e),
                "migration_failure"
            );
            
            DB_MIGRATION_OPERATIONS.with_label_values(&["failure"]).inc();
            
            Err(DatabaseError::Migration {
                source: e,
                span: SpanTrace::capture(),
            })
        }
    }
}

/// Masks sensitive information in database URLs for safe logging.
///
/// This function hides passwords and other sensitive information in database URLs,
/// making them safe to include in logs.
///
/// # Arguments
///
/// * `url` - Database URL that may contain sensitive information
///
/// # Returns
///
/// A String with sensitive information replaced with asterisks
fn mask_db_url(url: &str) -> String {
    // For SQLite URLs (file paths), simply return them as they have no credentials
    if url.starts_with("sqlite:") {
        return url.to_string();
    }
    
    // For other DB types that might contain credentials, mask them
    // Example: postgres://user:password@localhost:5432/dbname -> postgres://user:****@localhost:5432/dbname
    if let Some(at_pos) = url.find('@') {
        if let Some(proto_end) = url.find("://") {
            let proto_end = proto_end + 3;
            if at_pos > proto_end {
                if let Some(pwd_start) = url[proto_end..at_pos].find(':') {
                    let pwd_start = proto_end + pwd_start + 1;
                    return format!(
                        "{}{}{}",
                        &url[0..pwd_start],
                        "****",
                        &url[at_pos..]
                    );
                }
            }
        }
    }
    
    // If format not recognized or no credentials to mask, return a generic indication
    "database-url-with-masked-credentials".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, time::{SystemTime, UNIX_EPOCH}};
    
    /// Set up test environment with default parameters
    fn setup_test() {
        // Ensure previous tests don't affect current test
        env::remove_var(DATABASE_URL_ENV);
    }
    
    /// Generate a unique file path in the temp directory for database testing.
    ///
    /// This ensures tests don't interfere with each other by using fresh database files.
    fn make_db_url() -> String {
        // Use nanosecond precision to ensure uniqueness
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        let mut path = env::temp_dir();
        path.push(format!("test_db_{}.sqlite", nanos));
        
        // Convert path to string format that SQLite can use
        format!("sqlite://{}", path.to_str().unwrap())
    }

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn init_pool_no_env_panics() {
        // Start with a clean environment
        setup_test();
        
        // Explicitly remove the DATABASE_URL environment variable
        env::remove_var(DATABASE_URL_ENV);
        
        // Assert variable is truly unset
        assert!(env::var(DATABASE_URL_ENV).is_err(), "DATABASE_URL must be set in .env or environment variables");
        
        // Now call init_pool which should panic with the expected message
        let _pool = init_pool();
    }

    #[test]
    fn init_pool_and_get_connection_success() {
        // Arrange
        setup_test();
        let url = make_db_url();
        env::set_var(DATABASE_URL_ENV, &url);
        
        // Act
        let pool = init_pool();
        
        // Assert
        let conn_result = pool.get();
        assert!(conn_result.is_ok(), "Pool should yield a valid connection");
    }

    #[test]
    #[should_panic(expected = "Failed to create database connection pool")]
    fn invalid_db_url_causes_init_pool_to_panic() {
        // Arrange
        setup_test();
        let mut bad = env::temp_dir();
        bad.push("no_such_dir");
        bad.push("db.sqlite");
        
        // Use a path that doesn't exist and can't be created
        env::set_var(DATABASE_URL_ENV, format!("sqlite://{}", bad.to_str().unwrap()));
        
        // Act - pool creation will attempt to open and then panic
        let _ = init_pool();
        
        // Assert - handled by should_panic attribute
    }

    #[test]
    fn run_migrations_is_idempotent() {
        // Arrange
        setup_test();
        let url = make_db_url();
        env::set_var(DATABASE_URL_ENV, &url);
        let pool = init_pool();
        
        // Act & Assert
        
        // First run
        let result1 = run_migrations(&pool);
        assert!(result1.is_ok(), "First migration should succeed");
        
        // Second run (no new migrations) should still succeed
        let result2 = run_migrations(&pool);
        assert!(result2.is_ok(), "Repeated migration should succeed (idempotent)");
    }
    
    #[test]
    fn get_connection_maps_pool_errors() {
        // Arrange
        setup_test();
        
        // Create a pool with a timeout of 1ms to force timeout errors
        let url = make_db_url();
        env::set_var(DATABASE_URL_ENV, &url);
        let manager = ConnectionManager::<SqliteConnection>::new(url);
        
        // Create a pool with very short timeout to guarantee connection timeouts
        // Increase from 1ms to 10ms to allow initial connection to succeed
        let pool = Pool::builder()
            .connection_timeout(Duration::from_millis(10))
            .max_size(1)
            .build(manager)
            .expect("Should build a pool with short timeout");
        
        // Make the pool busy by holding its only connection
        let _conn = pool.get().expect("Should get first connection");
        
        // Act - The next get() should timeout because max_size is 1 and we're holding it
        let result = get_connection(&pool);
        
        // Assert
        assert!(result.is_err(), "Should return an error on timeout");
        
        // Check the error type without unwrapping
        match result {
            Err(DatabaseError::Connection { source: _, span: _ }) => {
                // Expected error type, test passes
            },
            _ => {
                panic!("Wrong error type returned: expected DatabaseError::Connection");
            }
        }
    }
    
    #[test]
    fn mask_db_url_hides_sensitive_info() {
        // Arrange & Act & Assert
        
        // Test with SQLite URL
        assert_eq!(
            mask_db_url("sqlite:///tmp/test.db"),
            "sqlite:///tmp/test.db",
            "SQLite URLs should not be masked"
        );
        
        // Test with Postgres URL containing credentials
        assert_eq!(
            mask_db_url("postgres://user:secret@localhost:5432/mydb"),
            "postgres://user:****@localhost:5432/mydb",
            "Postgres password should be masked"
        );
        
        // Test with unrecognized format
        assert_eq!(
            mask_db_url("some-random-string"),
            "database-url-with-masked-credentials",
            "Unrecognized format should return generic masked string"
        );
    }
}