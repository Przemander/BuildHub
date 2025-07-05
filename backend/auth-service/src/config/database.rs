//! # Database Configuration and Connection Pool Management
//!
//! This module provides production-ready database infrastructure for the BuildHub
//! authentication service. It handles SQLite database connection pooling, schema
//! migrations, and comprehensive observability with a focus on reliability and
//! performance optimization.
//!
//! ## Features
//!
//! - **Thread-Safe Connection Pooling**: Optimized r2d2 pool configuration for SQLite
//! - **Automatic Schema Migrations**: Embedded migrations with rollback safety
//! - **Production Observability**: Comprehensive metrics and structured logging
//! - **Error Resilience**: Graceful degradation with detailed error context
//! - **Security**: Safe credential handling and URL masking for logs
//! - **Performance Optimization**: Tuned pool settings for high-concurrency workloads
//!
//! ## Architecture
//!
//! The module follows a layered approach:
//! - Connection pool initialization and management
//! - Connection acquisition with error handling
//! - Schema migration management with embedded migrations
//! - Comprehensive observability and metrics collection
//!
//! ## Configuration
//!
//! Requires the `DATABASE_URL` environment variable pointing to a SQLite database:
//! ```
//! DATABASE_URL=sqlite:///path/to/production.db
//! DATABASE_URL=sqlite::memory:  # For testing
//! ```
//!
//! ## Pool Configuration
//!
//! Optimized for SQLite characteristics:
//! - **Max Connections**: 15 (SQLite write serialization limit)
//! - **Min Idle**: 1 (faster response times)
//! - **Timeout**: 10 seconds (prevents hanging requests)
//!
//! ## Usage Example
//!
//! ```rust
//! use crate::config::database::{init_pool, get_connection, run_migrations};
//!
//! async fn setup_database() -> Result<(), DatabaseError> {
//!     // Initialize connection pool
//!     let pool = init_pool();
//!     
//!     // Run pending migrations
//!     run_migrations(&pool)?;
//!     
//!     // Use connection for operations
//!     let conn = get_connection(&pool)?;
//!     // ... database operations
//!     
//!     Ok(())
//! }
//! ```

use crate::utils::error_new::DatabaseError;
use crate::utils::metrics::{DB_CONNECTION_OPERATIONS, DB_MIGRATION_OPERATIONS, DB_POOL_OPERATIONS};
use crate::{log_error, log_info};
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::SqliteConnection;
use std::env;
use std::time::Duration;
use tracing_error::SpanTrace;

// =============================================================================
// TYPE DEFINITIONS AND CONSTANTS
// =============================================================================

/// Type alias for the database connection pool using r2d2 and Diesel.
///
/// This pool manages SQLite connections with optimized settings for the
/// authentication service's workload patterns.
pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Type alias for a pooled database connection.
///
/// Represents a connection acquired from the pool that automatically
/// returns to the pool when dropped, ensuring efficient resource management.
pub type DbConnection = PooledConnection<ConnectionManager<SqliteConnection>>;

/// Environment variable name for the database URL configuration.
const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Default connection timeout in seconds.
///
/// Chosen to balance user experience (not too long) with system stability
/// (long enough for legitimate operations under load).
const DEFAULT_CONNECTION_TIMEOUT_SECONDS: u64 = 10;

/// Default maximum pool size.
///
/// SQLite has limitations on concurrent writers, so we limit the pool size
/// to prevent contention and ensure stable performance.
const DEFAULT_MAX_POOL_SIZE: u32 = 15;

/// Default minimum idle connections.
///
/// Maintaining at least one idle connection ensures faster response times
/// for the first request after periods of inactivity.
const DEFAULT_MIN_IDLE: u32 = 1;

// =============================================================================
// POOL INITIALIZATION AND MANAGEMENT
// =============================================================================

/// Initializes the database connection pool with production-ready configuration.
///
/// This function creates and configures a connection pool optimized for SQLite
/// with appropriate settings for the authentication service's performance
/// requirements and concurrency patterns.
///
/// # Configuration Details
///
/// - **Max Size**: 15 connections (optimal for SQLite's write serialization)
/// - **Min Idle**: 1 connection (ensures fast cold starts)
/// - **Timeout**: 10 seconds (balances UX and stability)
/// - **Manager**: Diesel's SQLite connection manager
///
/// # Environment Variables
///
/// - `DATABASE_URL`: Required. SQLite database path or `:memory:` for testing
///
/// # Panics
///
/// This function will panic if:
/// - `DATABASE_URL` environment variable is not set
/// - The database URL is invalid or inaccessible
/// - Pool creation fails due to filesystem permissions or other system issues
///
/// # Production Considerations
///
/// In production environments, ensure:
/// - Database file permissions are correctly set
/// - Sufficient disk space is available
/// - The database directory exists and is writable
///
/// # Examples
///
/// ```rust
/// // Production setup
/// std::env::set_var("DATABASE_URL", "sqlite:///var/lib/buildhub/auth.db");
/// let pool = init_pool();
///
/// // Development setup
/// std::env::set_var("DATABASE_URL", "sqlite::memory:");
/// let pool = init_pool();
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

    // Configure the pool with production-optimized settings
    // These values are specifically tuned for SQLite's characteristics
    let pool = Pool::builder()
        .max_size(DEFAULT_MAX_POOL_SIZE) // SQLite serializes writes, so limit concurrency
        .min_idle(Some(DEFAULT_MIN_IDLE)) // Keep connections warm for better latency
        .connection_timeout(Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECONDS))
        .build(manager)
        .unwrap_or_else(|e| {
            log_error!(
                "Database", 
                &format!("Failed to create connection pool: {}", e), 
                "initialization_error"
            );
            DB_POOL_OPERATIONS.with_label_values(&["failure"]).inc();
            panic!("Failed to create database connection pool: {}", e);
        });

    log_info!(
        "Database", 
        &format!(
            "Connection pool initialized successfully (max_size={}, min_idle={}, timeout={}s)", 
            DEFAULT_MAX_POOL_SIZE, 
            DEFAULT_MIN_IDLE, 
            DEFAULT_CONNECTION_TIMEOUT_SECONDS
        ), 
        "initialization_success"
    );
    
    DB_POOL_OPERATIONS.with_label_values(&["success"]).inc();
    
    pool
}

// =============================================================================
// CONNECTION ACQUISITION AND MANAGEMENT
// =============================================================================

/// Acquires a database connection from the pool with comprehensive error handling.
///
/// This function provides a safe, instrumented way to get database connections
/// with proper error mapping, metrics collection, and observability. It wraps
/// potential pool errors in structured `DatabaseError` types for consistent
/// error handling throughout the application.
///
/// # Arguments
///
/// * `pool` - Reference to the initialized database connection pool
///
/// # Returns
///
/// * `Ok(DbConnection)` - A successfully acquired pooled connection
/// * `Err(DatabaseError)` - Detailed error information if acquisition fails
///
/// # Error Scenarios
///
/// This function can fail in several scenarios:
/// - **Pool Exhaustion**: All connections are in use (returns timeout error)
/// - **Connection Timeout**: Unable to get connection within configured timeout
/// - **Database Unavailable**: Database file locked or inaccessible
/// - **System Resources**: OS-level resource exhaustion
///
/// # Performance Considerations
///
/// - Connection acquisition is typically fast (< 1ms) under normal load
/// - Under high concurrency, may take up to the configured timeout (10s)
/// - Metrics are collected for monitoring and alerting purposes
///
/// # Examples
///
/// ```rust
/// async fn user_operation(pool: &DbPool) -> Result<User, DatabaseError> {
///     let mut conn = get_connection(pool)?;
///     
///     // Perform database operations
///     let user = users::table
///         .filter(users::id.eq(user_id))
///         .first::<User>(&mut conn)?;
///         
///     Ok(user)
/// }
/// ```
pub fn get_connection(pool: &DbPool) -> Result<DbConnection, DatabaseError> {
    match pool.get() {
        Ok(conn) => {
            DB_CONNECTION_OPERATIONS.with_label_values(&["success"]).inc();
            Ok(conn)
        }
        Err(e) => {
            log_error!(
                "Database", 
                &format!("Failed to acquire connection from pool: {}", e), 
                "connection_error"
            );
            DB_CONNECTION_OPERATIONS.with_label_values(&["failure"]).inc();
            
            // Map r2d2 error to our structured error type with context
            Err(DatabaseError::ConnectionPool {
                source: e,
                span: SpanTrace::capture(),
            })
        }
    }
}

// =============================================================================
// SCHEMA MIGRATION MANAGEMENT
// =============================================================================

/// Executes pending database migrations with comprehensive error handling.
///
/// This function applies any pending schema migrations from the embedded
/// migrations directory. It's designed to be safe for production deployment
/// and can be called multiple times idempotently.
///
/// # Migration Safety
///
/// - **Idempotent**: Safe to run multiple times, only applies new migrations
/// - **Atomic**: Each migration runs in a transaction (rollback on failure)
/// - **Embedded**: Migrations are compiled into the binary for deployment safety
/// - **Versioned**: Diesel tracks applied migrations to prevent duplicates
///
/// # Arguments
///
/// * `pool` - Database connection pool for migration execution
///
/// # Returns
///
/// * `Ok(())` - All migrations applied successfully or no migrations pending
/// * `Err(DatabaseError)` - Migration execution failed with detailed context
///
/// # Migration Process
///
/// 1. Acquire connection from pool
/// 2. Check for pending migrations
/// 3. Execute each migration in order within transactions
/// 4. Update migration tracking table
/// 5. Report results with detailed logging
///
/// # Production Deployment
///
/// Best practices for production migration deployment:
/// - Run migrations during maintenance windows when possible
/// - Monitor migration execution time and resource usage
/// - Have rollback plan for complex schema changes
/// - Test migrations thoroughly in staging environment
///
/// # Examples
///
/// ```rust
/// // Application startup migration
/// async fn initialize_schema() -> Result<(), DatabaseError> {
///     let pool = init_pool();
///     run_migrations(&pool)?;
///     log_info!("Database", "Schema initialized successfully", "startup");
///     Ok(())
/// }
///
/// // Deployment migration check
/// async fn deploy_check() -> Result<(), DatabaseError> {
///     let pool = get_existing_pool();
///     match run_migrations(&pool) {
///         Ok(()) => log_info!("Deploy", "Schema up to date", "migration_check"),
///         Err(e) => return Err(e),
///     }
///     Ok(())
/// }
/// ```
pub fn run_migrations(pool: &DbPool) -> Result<(), DatabaseError> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    // Embed migrations at compile time for deployment safety
    // This ensures migrations are always available and versioned with the binary
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

    // Acquire connection for migration execution
    let mut conn = get_connection(pool)?;

    log_info!("Database", "Starting migration execution...", "migration_attempt");
    DB_MIGRATION_OPERATIONS.with_label_values(&["attempt"]).inc();
    
    // Execute pending migrations with comprehensive result handling
    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(applied_migrations) => {
            let migration_count = applied_migrations.len();
            
            if migration_count > 0 {
                log_info!(
                    "Database", 
                    &format!("Successfully applied {} migration(s)", migration_count), 
                    "migration_success"
                );
            } else {
                log_info!(
                    "Database", 
                    "Database schema is up to date - no pending migrations", 
                    "migration_success"
                );
            }
            
            DB_MIGRATION_OPERATIONS.with_label_values(&["success"]).inc();
            Ok(())
        }
        Err(migration_error) => {
            log_error!(
                "Database",
                &format!("Migration execution failed: {}", migration_error),
                "migration_failure"
            );
            
            DB_MIGRATION_OPERATIONS.with_label_values(&["failure"]).inc();
            
            // Wrap migration error with context for debugging
            Err(DatabaseError::Migration {
                source: migration_error,
                span: SpanTrace::capture(),
            })
        }
    }
}

// =============================================================================
// SECURITY AND UTILITY FUNCTIONS
// =============================================================================

/// Masks sensitive information in database URLs for secure logging.
///
/// This function sanitizes database URLs by hiding passwords and other
/// sensitive authentication information, making them safe to include
/// in application logs and monitoring systems.
///
/// # Security Considerations
///
/// - Never log database credentials in plain text
/// - Mask passwords while preserving debugging information
/// - Handle various database URL formats consistently
/// - Provide fallback for unrecognized formats
///
/// # Supported Formats
///
/// - **SQLite**: `sqlite:///path/to/db.sqlite` (no masking needed)
/// - **PostgreSQL**: `postgres://user:password@host:port/db` → `postgres://user:****@host:port/db`
/// - **MySQL**: `mysql://user:password@host:port/db` → `mysql://user:****@host:port/db`
/// - **Generic**: Unknown formats return safe placeholder
///
/// # Arguments
///
/// * `url` - Database URL that may contain sensitive authentication information
///
/// # Returns
///
/// A sanitized URL string safe for logging and monitoring
///
/// # Examples
///
/// ```rust
/// // SQLite URL (no credentials to mask)
/// assert_eq!(
///     mask_db_url("sqlite:///tmp/auth.db"),
///     "sqlite:///tmp/auth.db"
/// );
///
/// // PostgreSQL URL with credentials
/// assert_eq!(
///     mask_db_url("postgres://admin:secret123@db.example.com:5432/auth"),
///     "postgres://admin:****@db.example.com:5432/auth"
/// );
///
/// // Unknown format
/// assert_eq!(
///     mask_db_url("custom://unknown-format"),
///     "database-url-with-masked-credentials"
/// );
/// ```
fn mask_db_url(url: &str) -> String {
    // SQLite URLs are file paths and contain no credentials
    if url.starts_with("sqlite:") {
        return url.to_string();
    }
    
    // Handle URLs with potential credentials (postgres, mysql, etc.)
    // Format: protocol://username:password@host:port/database
    if let Some(at_position) = url.find('@') {
        if let Some(protocol_end) = url.find("://") {
            let protocol_end = protocol_end + 3; // Skip past "://"
            
            // Ensure @ comes after protocol and there's a potential credentials section
            if at_position > protocol_end {
                if let Some(password_start) = url[protocol_end..at_position].find(':') {
                    let password_start = protocol_end + password_start + 1;
                    
                    // Reconstruct URL with masked password
                    return format!(
                        "{}{}{}",
                        &url[0..password_start], // protocol://username:
                        "****",                  // masked password
                        &url[at_position..]      // @host:port/database
                    );
                }
            }
        }
    }
    
    // Fallback for unrecognized formats - return safe placeholder
    "database-url-with-masked-credentials".to_string()
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, time::{SystemTime, UNIX_EPOCH}};
    
    /// Sets up a clean test environment by removing any existing DATABASE_URL.
    ///
    /// This ensures tests don't interfere with each other and have predictable
    /// starting conditions.
    fn setup_test_environment() {
        env::remove_var(DATABASE_URL_ENV);
    }
    
    /// Generates a unique SQLite database path for isolated testing.
    ///
    /// Uses nanosecond timestamps to ensure each test gets a fresh database
    /// file, preventing test interference and ensuring clean state.
    ///
    /// # Returns
    ///
    /// A unique SQLite database URL suitable for testing
    fn create_unique_test_db_url() -> String {
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        let mut temp_path = env::temp_dir();
        temp_path.push(format!("buildhub_auth_test_{}.sqlite", timestamp_nanos));
        
        format!("sqlite://{}", temp_path.to_str().unwrap())
    }

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn test_init_pool_fails_without_database_url() {
        setup_test_environment();
        
        // Explicitly ensure DATABASE_URL is not set
        env::remove_var(DATABASE_URL_ENV);
        assert!(env::var(DATABASE_URL_ENV).is_err(), "DATABASE_URL should not be set for this test");
        
        // This should panic with the expected message
        let _pool = init_pool();
    }

    #[test]
    fn test_successful_pool_initialization_and_connection() {
        setup_test_environment();
        let db_url = create_unique_test_db_url();
        env::set_var(DATABASE_URL_ENV, &db_url);
        
        // Test pool initialization
        let pool = init_pool();
        
        // Test connection acquisition
        let connection_result = pool.get();
        assert!(
            connection_result.is_ok(), 
            "Should successfully acquire connection from initialized pool"
        );
        
        // Verify connection is functional
        let _connection = connection_result.unwrap();
        // Connection automatically returns to pool when dropped
    }

    #[test]
    #[should_panic(expected = "Failed to create database connection pool")]
    fn test_init_pool_panics_with_invalid_database_url() {
        setup_test_environment();
        
        // Create a path that can't be created (invalid directory)
        let mut invalid_path = env::temp_dir();
        invalid_path.push("nonexistent_directory_that_cannot_be_created");
        invalid_path.push("impossible_database.sqlite");
        
        let invalid_url = format!("sqlite://{}", invalid_path.to_str().unwrap());
        env::set_var(DATABASE_URL_ENV, &invalid_url);
        
        // This should panic during pool creation
        let _pool = init_pool();
    }

    #[test]
    fn test_migration_execution_is_idempotent() {
        setup_test_environment();
        let db_url = create_unique_test_db_url();
        env::set_var(DATABASE_URL_ENV, &db_url);
        let pool = init_pool();
        
        // First migration run
        let first_result = run_migrations(&pool);
        assert!(first_result.is_ok(), "Initial migration should succeed");
        
        // Second migration run (should be idempotent)
        let second_result = run_migrations(&pool);
        assert!(second_result.is_ok(), "Repeated migration should succeed (idempotent behavior)");
        
        // Third run to ensure consistency
        let third_result = run_migrations(&pool);
        assert!(third_result.is_ok(), "Multiple repeated migrations should always succeed");
    }
    
    #[test]
    fn test_get_connection_properly_handles_pool_exhaustion() {
        setup_test_environment();
        let db_url = create_unique_test_db_url();
        env::set_var(DATABASE_URL_ENV, &db_url);
        
        let manager = ConnectionManager::<SqliteConnection>::new(db_url);
        
        // Create a pool with minimal configuration to force timeouts
        let constrained_pool = Pool::builder()
            .connection_timeout(Duration::from_millis(50)) // Very short timeout
            .max_size(1) // Only one connection allowed
            .build(manager)
            .expect("Should create constrained pool");
        
        // Acquire the only available connection
        let _held_connection = constrained_pool.get()
            .expect("Should acquire the single available connection");
        
        // Attempt to get another connection (should timeout and fail)
        let timeout_result = get_connection(&constrained_pool);
        
        assert!(timeout_result.is_err(), "Should fail when pool is exhausted");
        
        // Verify the error type is correct
        match timeout_result {
            Err(DatabaseError::ConnectionPool { source: _, span: _ }) => {
                // Expected error type - test passes
            },
            _ => {
                panic!("Expected DatabaseError::ConnectionPool, got different error type");
            }
        }
    }
    
    #[test]
    fn test_url_masking_handles_various_formats() {
        // Test SQLite URLs (should not be masked)
        assert_eq!(
            mask_db_url("sqlite:///tmp/test.db"),
            "sqlite:///tmp/test.db",
            "SQLite URLs should remain unmasked"
        );
        
        assert_eq!(
            mask_db_url("sqlite::memory:"),
            "sqlite::memory:",
            "In-memory SQLite URLs should remain unmasked"
        );
        
        // Test PostgreSQL URL with credentials
        assert_eq!(
            mask_db_url("postgres://username:secretpassword@localhost:5432/database"),
            "postgres://username:****@localhost:5432/database",
            "PostgreSQL passwords should be masked with asterisks"
        );
        
        // Test MySQL URL with credentials
        assert_eq!(
            mask_db_url("mysql://admin:admin123@mysql.example.com:3306/auth_db"),
            "mysql://admin:****@mysql.example.com:3306/auth_db",
            "MySQL passwords should be masked with asterisks"
        );
        
        // Test URL without credentials
        assert_eq!(
            mask_db_url("postgres://localhost:5432/database"),
            "database-url-with-masked-credentials",
            "URLs without clear credential format should use generic mask"
        );
        
        // Test unrecognized format
        assert_eq!(
            mask_db_url("unknown-database-format"),
            "database-url-with-masked-credentials",
            "Unrecognized formats should use generic mask"
        );
        
        // Test edge case: empty string
        assert_eq!(
            mask_db_url(""),
            "database-url-with-masked-credentials",
            "Empty string should use generic mask"
        );
    }

    #[test]
    fn test_database_url_environment_variable_constant() {
        // Verify the constant matches expected value
        assert_eq!(DATABASE_URL_ENV, "DATABASE_URL");
    }

    #[test]
    fn test_pool_configuration_constants() {
        // Verify pool configuration constants are reasonable
        assert!(DEFAULT_MAX_POOL_SIZE > 0, "Max pool size must be positive");
        assert!(DEFAULT_MIN_IDLE > 0, "Min idle connections must be positive");
        assert!(DEFAULT_MIN_IDLE <= DEFAULT_MAX_POOL_SIZE, "Min idle must not exceed max pool size");
        assert!(DEFAULT_CONNECTION_TIMEOUT_SECONDS > 0, "Timeout must be positive");
        
        // Verify SQLite-appropriate values
        assert!(DEFAULT_MAX_POOL_SIZE <= 20, "Pool size should be reasonable for SQLite");
        assert!(DEFAULT_CONNECTION_TIMEOUT_SECONDS >= 5, "Timeout should allow for legitimate operations");
    }
}