//! # Database Configuration and Connection Pool Management
//!
//! This module provides production-ready database infrastructure for the BuildHub
//! authentication service. It handles PostgreSQL database connection pooling, schema
//! migrations, and comprehensive observability with a focus on reliability and
//! performance optimization.
//!
//! ## Features
//!
//! - **Thread-Safe Connection Pooling**: Optimized r2d2 pool configuration for PostgreSQL
//! - **Automatic Schema Migrations**: Embedded migrations with rollback safety
//! - **Production Observability**: Contextual metrics and structured logging
//! - **Error Resilience**: Graceful degradation with detailed error context
//! - **Security**: Safe credential handling and URL masking for logs
//! - **Performance Optimization**: Tuned pool settings for high-concurrency workloads

use crate::metricss::database_metrics::{connection, migration, pool};
use crate::utils::error_new::DatabaseError;
use crate::utils::log_new::Log;
use crate::utils::telemetry::{business_operation_span, SpanExt};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use std::env;
use std::time::Duration;
use tracing::Instrument;
use tracing_error::SpanTrace;

// =============================================================================
// TYPE DEFINITIONS AND CONSTANTS
// =============================================================================

/// Type alias for the database connection pool using r2d2 and Diesel.
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Type alias for a pooled database connection.
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Environment variable name for the database URL configuration.
const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Default connection timeout in seconds.
const DEFAULT_CONNECTION_TIMEOUT_SECONDS: u64 = 10;

/// Default maximum pool size - PostgreSQL can handle more concurrent connections
const DEFAULT_MAX_POOL_SIZE: u32 = 25;

/// Default minimum idle connections.
const DEFAULT_MIN_IDLE: u32 = 2;

/// Default connection idle timeout in seconds
const DEFAULT_IDLE_TIMEOUT_SECONDS: u64 = 600; // 10 minutes

// =============================================================================
// POOL INITIALIZATION AND MANAGEMENT
// =============================================================================

/// Initializes the database connection pool with production-ready configuration.
///
/// This function creates and configures a connection pool optimized for PostgreSQL
/// with appropriate settings for the authentication service's performance
/// requirements and concurrency patterns.
///
/// # Panics
///
/// This function will panic if:
/// - `DATABASE_URL` environment variable is not set
/// - The database URL is invalid or inaccessible
/// - Pool creation fails due to connection or authentication issues
pub fn init_pool() -> DbPool {
    // Create span for pool initialization
    let span = business_operation_span("init_database_pool");
    span.record("max_pool_size", &DEFAULT_MAX_POOL_SIZE);
    span.record("min_idle", &DEFAULT_MIN_IDLE);
    span.record("timeout_seconds", &DEFAULT_CONNECTION_TIMEOUT_SECONDS);
    span.record("database_type", &"postgresql");

    // Use span to wrap the initialization logic
    span.in_scope(|| {
        let database_url = env::var(DATABASE_URL_ENV).unwrap_or_else(|e| {
            Log::event(
                "ERROR",
                "Database Configuration",
                &format!("Missing {} environment variable", DATABASE_URL_ENV),
                "initialization_error",
                "init_pool"
            );
            span.record("result", &"failure");
            span.record("failure_reason", &"missing_env_var");
            span.record_error(&e);
            panic!("DATABASE_URL must be set in .env or environment variables");
        });

        pool::record_startup_attempt();

        Log::event(
            "INFO",
            "Database Configuration",
            &format!("Initializing PostgreSQL connection pool with URL: {}", mask_db_url(&database_url)),
            "initialization_attempt",
            "init_pool"
        );
        
        span.record("database_url_masked", &mask_db_url(&database_url));
        
        let manager = ConnectionManager::<PgConnection>::new(database_url);

        // Configure the pool with production-optimized settings for PostgreSQL
        let pool = Pool::builder()
            .max_size(DEFAULT_MAX_POOL_SIZE)
            .min_idle(Some(DEFAULT_MIN_IDLE))
            .connection_timeout(Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECONDS))
            .idle_timeout(Some(Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECONDS)))
            .test_on_check_out(true)
            .build(manager)
            .unwrap_or_else(|e| {
                Log::event(
                    "ERROR",
                    "Database Configuration",
                    &format!("Failed to create PostgreSQL connection pool: {}", e),
                    "initialization_error",
                    "init_pool"
                );
                
                pool::record_startup_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"pool_creation_failed");
                span.record_error(&e);
                panic!("Failed to create database connection pool: {}", e);
            });

        Log::event(
            "INFO",
            "Database Configuration",
            &format!(
                "PostgreSQL connection pool initialized successfully (max_size={}, min_idle={}, timeout={}s, idle_timeout={}s)",
                DEFAULT_MAX_POOL_SIZE,
                DEFAULT_MIN_IDLE,
                DEFAULT_CONNECTION_TIMEOUT_SECONDS,
                DEFAULT_IDLE_TIMEOUT_SECONDS
            ),
            "initialization_success",
            "init_pool"
        );
        
        pool::record_startup_success();
        span.record("result", &"success");
        
        pool
    })
}

// =============================================================================
// CONNECTION ACQUISITION AND MANAGEMENT
// =============================================================================

/// Acquires a database connection with automatic metrics recording.
///
/// This function provides a safe, instrumented way to get database connections
/// with proper error mapping, metrics collection, and observability.
///
/// # Arguments
/// * `pool` - Database connection pool
#[allow(dead_code)]
pub fn get_connection(pool: &DbPool) -> Result<DbConnection, DatabaseError> {
    // Create span for connection acquisition
    let span = business_operation_span("get_database_connection");
    span.record("connection_type", &"runtime");
    span.record("database_type", &"postgresql");

    // Use span to wrap the connection acquisition
    span.in_scope(|| {
        connection::record_runtime_attempt();

        Log::event(
            "DEBUG",
            "Database Connection",
            "Acquiring runtime connection from PostgreSQL pool",
            "connection_attempt",
            "get_connection",
        );

        match pool.get() {
            Ok(conn) => {
                connection::record_runtime_success();
                span.record("result", &"success");

                Log::event(
                    "DEBUG",
                    "Database Connection",
                    "PostgreSQL runtime connection acquired successfully",
                    "connection_success",
                    "get_connection",
                );

                Ok(conn)
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Database Connection",
                    &format!("Failed to acquire PostgreSQL connection from pool: {}", e),
                    "connection_error",
                    "get_connection",
                );

                connection::record_runtime_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"pool_acquisition_failed");
                span.record_error(&e);

                Err(DatabaseError::ConnectionPool {
                    source: e,
                    span: SpanTrace::capture(),
                })
            }
        }
    })
}

/// Acquires a database connection for startup operations (migrations, health checks).
///
/// This function is specifically for operations that happen during application startup
/// and records metrics with the appropriate startup context.
///
/// # Arguments
/// * `pool` - Database connection pool
pub fn get_startup_connection(pool: &DbPool) -> Result<DbConnection, DatabaseError> {
    // Create span for startup connection acquisition
    let span = business_operation_span("get_startup_connection");
    span.record("connection_type", &"startup");
    span.record("database_type", &"postgresql");

    // Use span to wrap the connection acquisition
    span.in_scope(|| {
        connection::record_startup_attempt();

        Log::event(
            "DEBUG",
            "Database Connection",
            "Acquiring startup connection from PostgreSQL pool",
            "startup_connection_attempt",
            "get_startup_connection",
        );

        match pool.get() {
            Ok(conn) => {
                connection::record_startup_success();
                span.record("result", &"success");

                Log::event(
                    "DEBUG",
                    "Database Connection",
                    "PostgreSQL startup connection acquired successfully",
                    "startup_connection_success",
                    "get_startup_connection",
                );

                Ok(conn)
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Database Connection",
                    &format!(
                        "Failed to acquire PostgreSQL startup connection from pool: {}",
                        e
                    ),
                    "startup_connection_error",
                    "get_startup_connection",
                );

                connection::record_startup_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"startup_pool_acquisition_failed");
                span.record_error(&e);

                Err(DatabaseError::ConnectionPool {
                    source: e,
                    span: SpanTrace::capture(),
                })
            }
        }
    })
}

// =============================================================================
// SCHEMA MIGRATION MANAGEMENT
// =============================================================================

/// Executes pending database migrations with comprehensive error handling.
///
/// This function applies any pending schema migrations from the embedded
/// migrations directory. It's designed to be safe for production deployment
/// and can be called multiple times idempotently.
pub fn run_migrations(pool: &DbPool) -> Result<(), DatabaseError> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

    // Create span for migration execution
    let span = business_operation_span("run_database_migrations");
    span.record("migration_source", &"embedded");
    span.record("database_type", &"postgresql");

    // Use span to wrap the migration logic
    span.in_scope(|| {
        Log::event(
            "INFO",
            "Database Migration",
            "Starting PostgreSQL migration execution...",
            "migration_attempt",
            "run_migrations",
        );

        migration::record_startup_attempt();

        // Acquire connection for migration execution using startup context
        let mut conn = get_startup_connection(pool)?;

        // Execute pending migrations with comprehensive result handling
        match conn.run_pending_migrations(MIGRATIONS) {
            Ok(applied_migrations) => {
                let migration_count = applied_migrations.len();
                span.record("migrations_applied", &migration_count);
                span.record("result", &"success");

                if migration_count > 0 {
                    Log::event(
                        "INFO",
                        "Database Migration",
                        &format!(
                            "Successfully applied {} PostgreSQL migration(s): {:?}",
                            migration_count,
                            applied_migrations
                        ),
                        "migration_success",
                        "run_migrations",
                    );
                } else {
                    Log::event(
                        "INFO",
                        "Database Migration",
                        "PostgreSQL database schema is up to date - no pending migrations",
                        "migration_success",
                        "run_migrations",
                    );
                }

                migration::record_startup_success();
                Ok(())
            }
            Err(migration_error) => {
                Log::event(
                    "ERROR",
                    "Database Migration",
                    &format!("PostgreSQL migration execution failed: {}", migration_error),
                    "migration_failure",
                    "run_migrations",
                );

                migration::record_startup_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"migration_execution_failed");
                span.record_error(&migration_error);

                // Wrap migration error with context for debugging
                Err(DatabaseError::Migration {
                    source: migration_error,
                    span: SpanTrace::capture(),
                })
            }
        }
    })
}

/// Performs a comprehensive database health check with detailed diagnostics.
pub async fn check_database_health(pool: &DbPool) -> Result<bool, DatabaseError> {
    // Create span for health check
    let span = business_operation_span("database_health_check");
    span.record("database_type", &"postgresql");

    // Clone span before moving it into async operation
    let span_clone = span.clone();

    // Wrap the health check in async instrumentation
    async move {
        Log::event(
            "DEBUG",
            "Database Health",
            "Starting PostgreSQL database health check",
            "health_check_attempt",
            "check_database_health",
        );

        // Test connection acquisition
        match get_connection(pool) {
            Ok(mut conn) => {
                span.record("connection_acquired", &true);

                // PostgreSQL-specific health check query
                match diesel::sql_query("SELECT 1").execute(&mut conn) {
                    Ok(_) => {
                        span.record("query_successful", &true);
                        span.record("result", &"healthy");

                        Log::event(
                            "INFO",
                            "Database Health",
                            "PostgreSQL database health check successful",
                            "health_check_success",
                            "check_database_health",
                        );

                        Ok(true)
                    }
                    Err(e) => {
                        span.record("query_successful", &false);
                        span.record("result", &"unhealthy");
                        span.record("failure_reason", &"query_failed");
                        span.record_error(&e);

                        Log::event(
                            "ERROR",
                            "Database Health",
                            &format!("PostgreSQL database health check query failed: {}", e),
                            "health_check_query_failure",
                            "check_database_health",
                        );

                        Err(DatabaseError::Query {
                            source: e,
                            span: SpanTrace::capture(),
                        })
                    }
                }
            }
            Err(e) => {
                span.record("connection_acquired", &false);
                span.record("result", &"unhealthy");
                span.record("failure_reason", &"connection_failed");
                span.record_error(&e);

                Log::event(
                    "ERROR",
                    "Database Health",
                    &format!("PostgreSQL database health check connection failed: {}", e),
                    "health_check_connection_failure",
                    "check_database_health",
                );

                Err(e)
            }
        }
    }
    .instrument(span_clone)
    .await
}

// =============================================================================
// SECURITY AND UTILITY FUNCTIONS
// =============================================================================

/// Masks sensitive information in database URLs for secure logging.
///
/// This function prevents credentials from appearing in logs by replacing
/// password sections of database URLs with asterisks.
fn mask_db_url(url: &str) -> String {
    // Handle PostgreSQL URLs with credentials
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        if let Some(at_position) = url.find('@') {
            if let Some(protocol_end) = url.find("://") {
                let protocol_end = protocol_end + 3;

                if at_position > protocol_end {
                    if let Some(password_start) = url[protocol_end..at_position].find(':') {
                        let password_start = protocol_end + password_start + 1;

                        return format!(
                            "{}{}{}",
                            &url[0..password_start],
                            "****",
                            &url[at_position..]
                        );
                    }
                }
            }
        }
    }

    // SQLite URLs (for backward compatibility)
    if url.starts_with("sqlite:") {
        return url.to_string();
    }

    // Handle other database URLs with potential credentials
    if let Some(at_position) = url.find('@') {
        if let Some(protocol_end) = url.find("://") {
            let protocol_end = protocol_end + 3;

            if at_position > protocol_end {
                if let Some(password_start) = url[protocol_end..at_position].find(':') {
                    let password_start = protocol_end + password_start + 1;

                    return format!(
                        "{}{}{}",
                        &url[0..password_start],
                        "****",
                        &url[at_position..]
                    );
                }
            }
        }
    }

    "database-url-with-masked-credentials".to_string()
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn setup_test_environment() {
        env::remove_var(DATABASE_URL_ENV);
    }

    fn create_test_postgres_url() -> String {
        // Use a test database URL - adjust as needed for your test environment
        env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:password@localhost:5432/buildhub_auth_test".to_string()
        })
    }

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn test_init_pool_fails_without_database_url() {
        setup_test_environment();
        env::remove_var(DATABASE_URL_ENV);
        assert!(env::var(DATABASE_URL_ENV).is_err());
        let _pool = init_pool();
    }

    #[test]
    #[ignore] // Requires PostgreSQL running
    fn test_successful_pool_initialization_and_connection() {
        setup_test_environment();
        let db_url = create_test_postgres_url();
        env::set_var(DATABASE_URL_ENV, &db_url);

        let pool = init_pool();
        let connection_result = get_connection(&pool);
        assert!(connection_result.is_ok());
    }

    #[test]
    #[should_panic(expected = "Failed to create database connection pool")]
    fn test_init_pool_panics_with_invalid_database_url() {
        setup_test_environment();

        let invalid_url = "postgres://invalid:invalid@nonexistent:5432/invalid";
        env::set_var(DATABASE_URL_ENV, invalid_url);

        let _pool = init_pool();
    }

    #[tokio::test]
    #[ignore] // Requires PostgreSQL running
    async fn test_database_health_check() {
        setup_test_environment();
        let db_url = create_test_postgres_url();
        env::set_var(DATABASE_URL_ENV, &db_url);

        let pool = init_pool();
        let health_result = check_database_health(&pool).await;
        assert!(health_result.is_ok());
        assert_eq!(health_result.unwrap(), true);
    }

    #[test]
    #[ignore] // Requires PostgreSQL running
    fn test_migration_execution_is_idempotent() {
        setup_test_environment();
        let db_url = create_test_postgres_url();
        env::set_var(DATABASE_URL_ENV, &db_url);
        let pool = init_pool();

        let first_result = run_migrations(&pool);
        assert!(first_result.is_ok());

        let second_result = run_migrations(&pool);
        assert!(second_result.is_ok());

        let third_result = run_migrations(&pool);
        assert!(third_result.is_ok());
    }

    #[test]
    fn test_postgres_url_masking() {
        assert_eq!(
            mask_db_url("postgres://username:secretpassword@localhost:5432/database"),
            "postgres://username:****@localhost:5432/database"
        );

        assert_eq!(
            mask_db_url("postgresql://admin:admin123@postgres.example.com:5432/auth_db"),
            "postgresql://admin:****@postgres.example.com:5432/auth_db"
        );

        assert_eq!(
            mask_db_url("postgres://localhost:5432/database"),
            "database-url-with-masked-credentials"
        );

        assert_eq!(
            mask_db_url("sqlite:///tmp/test.db"),
            "sqlite:///tmp/test.db"
        );
    }

    #[test]
    fn test_database_url_environment_variable_constant() {
        assert_eq!(DATABASE_URL_ENV, "DATABASE_URL");
    }

    #[test]
    fn test_postgresql_pool_configuration_constants() {
        assert!(DEFAULT_MAX_POOL_SIZE > 0);
        assert!(DEFAULT_MIN_IDLE > 0);
        assert!(DEFAULT_MIN_IDLE <= DEFAULT_MAX_POOL_SIZE);
        assert!(DEFAULT_CONNECTION_TIMEOUT_SECONDS > 0);
        assert_eq!(DEFAULT_MAX_POOL_SIZE, 25); // PostgreSQL-optimized value
        assert_eq!(DEFAULT_MIN_IDLE, 2); // PostgreSQL-optimized value
    }
}