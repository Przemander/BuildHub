//! # Database Metrics for BuildHub Auth Service
//!
//! Production-grade database observability infrastructure for monitoring connection
//! management, query performance, and database operations with comprehensive error tracking.
//!
//! ## Design Philosophy
//! - **Complete Visibility**: Track every database interaction from connection to query
//! - **Performance Awareness**: Monitor timing for all critical database operations
//! - **Error Classification**: Detailed error taxonomies for pinpointing issues
//! - **Lifecycle Tracking**: Separate startup and runtime metrics for deployment observability
//! - **Dimensionality**: Multi-dimensional metrics for deep analysis
//!
//! ## Core Metric Categories
//! - **Connection Metrics**: Pool management and connection acquisition
//! - **Performance Metrics**: Query execution times with standardized buckets
//! - **Operation Metrics**: Success/failure rates for all database operations
//! - **Error Metrics**: Detailed error classification by operation and type
//! - **Migration Metrics**: Schema evolution tracking

use crate::log_info;
use crate::metricss::core::{
    create_counter_vec, create_histogram_vec, observe_counter_vec, observe_histogram_vec,
    LATENCY_BUCKETS_MEDIUM,
};
use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

// =============================================================================
// CONSTANTS - Label Values (Type Safety)
// =============================================================================

/// Result constants for operation tracking
pub mod result {
    /// Operation was attempted
    pub const ATTEMPT: &str = "attempt";
    /// Operation succeeded
    pub const SUCCESS: &str = "success";
    /// Operation failed
    pub const FAILURE: &str = "failure";
}

/// Context constants for connection operations
pub mod context {
    /// Operation during service startup
    pub const STARTUP: &str = "startup";
    /// Operation during normal application runtime
    pub const APPLICATION: &str = "application";
}

/// Operation type constants for user database operations
pub mod operation {
    /// User creation operation
    pub const CREATE: &str = "create";
    /// User lookup by username
    pub const LOOKUP_USERNAME: &str = "lookup_username";
    /// User lookup by email
    pub const LOOKUP_EMAIL: &str = "lookup_email";
    /// General user update
    pub const UPDATE: &str = "update";
    /// Account activation
    pub const ACTIVATE: &str = "activate";
    /// Password update
    pub const PASSWORD_UPDATE: &str = "password_update";
}

/// Error type constants for standardized error classification
#[allow(dead_code)]
pub mod error_type {
    /// Entity not found
    pub const NOT_FOUND: &str = "not_found";
    /// Query execution error
    pub const QUERY_ERROR: &str = "query_error";
    /// Duplicate entry violation
    pub const DUPLICATE: &str = "duplicate";
    /// Constraint violation
    pub const CONSTRAINT: &str = "constraint";
    /// Password hashing error
    pub const HASH_ERROR: &str = "hash_error";
    /// Missing ID in update
    pub const NO_ID: &str = "no_id";
    /// Database connection error
    pub const CONNECTION_ERROR: &str = "connection_error";
    /// Transaction error
    pub const TRANSACTION_ERROR: &str = "transaction_error";
    /// Unknown/unexpected error
    pub const UNKNOWN: &str = "unknown";
}

// =============================================================================
// CORE METRICS
// =============================================================================

lazy_static! {
    /// Connection pool lifecycle metrics
    ///
    /// Tracks pool creation, shutdown, and health at both startup and runtime.
    /// Critical for monitoring database availability and connection issues.
    ///
    /// # Labels
    /// * `result`: Operation result (attempt, success, failure)
    /// * `context`: Operation context (startup, application)
    ///
    /// # Interpretation
    /// - Startup failures indicate configuration or connectivity issues
    /// - Runtime failures indicate database health problems
    pub static ref DB_POOL_OPERATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_db_pool_operations_total",
        "Database connection pool operations by result and context",
        &["result", "context"]
    ).expect("Failed to create DB_POOL_OPERATIONS metric");

    /// Individual connection acquisition metrics
    ///
    /// Tracks checkout/release of database connections from the pool.
    /// Essential for detecting connection leaks and pool exhaustion.
    ///
    /// # Labels
    /// * `result`: Operation result (attempt, success, failure)
    /// * `context`: Operation context (startup, application)
    ///
    /// # Interpretation
    /// - High failure rates indicate pool exhaustion or connection issues
    /// - Startup failures can predict runtime behavior
    pub static ref DB_CONNECTION_OPERATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_db_connection_operations_total",
        "Database connection operations by result and context",
        &["result", "context"]
    ).expect("Failed to create DB_CONNECTION_OPERATIONS metric");

    /// Database migration tracking
    ///
    /// Tracks schema migration execution and success rates.
    /// Critical for deployment verification and troubleshooting.
    ///
    /// # Labels
    /// * `result`: Operation result (attempt, success, failure)
    /// * `context`: Operation context (startup, application)
    ///
    /// # Interpretation
    /// - Migration failures indicate schema compatibility issues
    /// - Startup migration success is essential for service health
    pub static ref DB_MIGRATION_OPERATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_db_migration_operations_total",
        "Database migration operations by result and context",
        &["result", "context"]
    ).expect("Failed to create DB_MIGRATION_OPERATIONS metric");

    /// User operation success/failure metrics
    ///
    /// Comprehensive tracking of all user-related database operations.
    /// Essential for monitoring API reliability and database performance.
    ///
    /// # Labels
    /// * `operation`: Operation type (create, lookup_username, etc.)
    /// * `result`: Operation result (attempt, success, failure)
    ///
    /// # Interpretation
    /// - Operations with high failure rates require investigation
    /// - Success rate changes can indicate database issues
    pub static ref USER_DB_OPERATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_user_db_operations_total",
        "User database operations by operation type and result",
        &["operation", "result"]
    ).expect("Failed to create USER_DB_OPERATIONS metric");

    /// Detailed user operation failure classification
    ///
    /// Provides fine-grained error tracking for all user operations.
    /// Critical for pinpointing specific database issues.
    ///
    /// # Labels
    /// * `operation`: Operation type (create, lookup_username, etc.)
    /// * `error_type`: Specific error category (not_found, duplicate, etc.)
    ///
    /// # Interpretation
    /// - Error patterns indicate application or database issues
    /// - Unexpected error types require investigation
    pub static ref USER_DB_FAILURES: CounterVec = create_counter_vec(
        "buildhub_auth_user_db_failures_total",
        "User database failures by operation type and error type",
        &["operation", "error_type"]
    ).expect("Failed to create USER_DB_FAILURES metric");

    /// Database query duration metrics
    ///
    /// Tracks execution time for all database operations with standardized buckets.
    /// Essential for performance monitoring and optimization.
    ///
    /// # Labels
    /// * `operation`: Operation type (create, lookup_username, etc.)
    /// * `result`: Operation result (success, failure)
    ///
    /// # Performance Targets
    /// - Fast queries (lookups): p95 < 50ms, p99 < 100ms
    /// - Medium queries (updates): p95 < 100ms, p99 < 200ms
    /// - Slow operations (create with validation): p95 < 200ms, p99 < 500ms
    pub static ref USER_DB_DURATION: HistogramVec = create_histogram_vec(
        "buildhub_auth_user_db_duration_seconds",
        "User database operation duration by operation type and result",
        &["operation", "result"],
        LATENCY_BUCKETS_MEDIUM
    ).expect("Failed to create USER_DB_DURATION metric");
}

// Thread-safe initialization guard
static DATABASE_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes all database metrics safely for multi-threaded environments.
///
/// This function ensures metrics are initialized exactly once, regardless of how
/// many threads attempt to initialize them simultaneously.
pub fn init_database_metrics() {
    // Thread-safe initialization with compare_exchange
    if DATABASE_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // Already initialized
    }

    // Force initialization of all metrics
    lazy_static::initialize(&DB_POOL_OPERATIONS);
    lazy_static::initialize(&DB_CONNECTION_OPERATIONS);
    lazy_static::initialize(&DB_MIGRATION_OPERATIONS);
    lazy_static::initialize(&USER_DB_OPERATIONS);
    lazy_static::initialize(&USER_DB_FAILURES);
    lazy_static::initialize(&USER_DB_DURATION);

    log_info!(
        "Metrics",
        "Database metrics initialized (pool, connection, user operations)",
        "database_metrics_init"
    );
}

// =============================================================================
// POOL OPERATION HELPERS
// =============================================================================

/// Pool operation helpers for tracking database connection pool lifecycle.
pub mod pool {
    use super::*;

    /// Records a connection pool creation attempt during service startup.
    pub fn record_startup_attempt() {
        observe_counter_vec(
            &DB_POOL_OPERATIONS,
            "buildhub_auth_db_pool_operations_total",
            &[result::ATTEMPT, context::STARTUP],
        );
    }

    /// Records a successful connection pool creation during service startup.
    pub fn record_startup_success() {
        observe_counter_vec(
            &DB_POOL_OPERATIONS,
            "buildhub_auth_db_pool_operations_total",
            &[result::SUCCESS, context::STARTUP],
        );
    }

    /// Records a failed connection pool creation during service startup.
    pub fn record_startup_failure() {
        observe_counter_vec(
            &DB_POOL_OPERATIONS,
            "buildhub_auth_db_pool_operations_total",
            &[result::FAILURE, context::STARTUP],
        );
    }
}

// =============================================================================
// CONNECTION OPERATION HELPERS
// =============================================================================

/// Connection operation helpers for tracking database connection acquisition.
pub mod connection {
    use super::*;

    /// Records a connection acquisition attempt during service startup.
    pub fn record_startup_attempt() {
        observe_counter_vec(
            &DB_CONNECTION_OPERATIONS,
            "buildhub_auth_db_connection_operations_total",
            &[result::ATTEMPT, context::STARTUP],
        );
    }

    /// Records a successful connection acquisition during service startup.
    pub fn record_startup_success() {
        observe_counter_vec(
            &DB_CONNECTION_OPERATIONS,
            "buildhub_auth_db_connection_operations_total",
            &[result::SUCCESS, context::STARTUP],
        );
    }

    /// Records a failed connection acquisition during service startup.
    pub fn record_startup_failure() {
        observe_counter_vec(
            &DB_CONNECTION_OPERATIONS,
            "buildhub_auth_db_connection_operations_total",
            &[result::FAILURE, context::STARTUP],
        );
    }

    /// Records a connection acquisition attempt during normal application runtime.
    pub fn record_runtime_attempt() {
        observe_counter_vec(
            &DB_CONNECTION_OPERATIONS,
            "buildhub_auth_db_connection_operations_total",
            &[result::ATTEMPT, context::APPLICATION],
        );
    }

    /// Records a successful connection acquisition during normal application runtime.
    pub fn record_runtime_success() {
        observe_counter_vec(
            &DB_CONNECTION_OPERATIONS,
            "buildhub_auth_db_connection_operations_total",
            &[result::SUCCESS, context::APPLICATION],
        );
    }

    /// Records a failed connection acquisition during normal application runtime.
    pub fn record_runtime_failure() {
        observe_counter_vec(
            &DB_CONNECTION_OPERATIONS,
            "buildhub_auth_db_connection_operations_total",
            &[result::FAILURE, context::APPLICATION],
        );
    }
}

// =============================================================================
// MIGRATION OPERATION HELPERS
// =============================================================================

/// Migration operation helpers for tracking database schema migrations.
pub mod migration {
    use super::*;

    /// Records a migration attempt during service startup.
    pub fn record_startup_attempt() {
        observe_counter_vec(
            &DB_MIGRATION_OPERATIONS,
            "buildhub_auth_db_migration_operations_total",
            &[result::ATTEMPT, context::STARTUP],
        );
    }

    /// Records a successful migration during service startup.
    pub fn record_startup_success() {
        observe_counter_vec(
            &DB_MIGRATION_OPERATIONS,
            "buildhub_auth_db_migration_operations_total",
            &[result::SUCCESS, context::STARTUP],
        );
    }

    /// Records a failed migration during service startup.
    pub fn record_startup_failure() {
        observe_counter_vec(
            &DB_MIGRATION_OPERATIONS,
            "buildhub_auth_db_migration_operations_total",
            &[result::FAILURE, context::STARTUP],
        );
    }
}

// =============================================================================
// USER OPERATION HELPERS
// =============================================================================

/// User operation helpers for tracking database operations on user records.
pub mod user {
    use super::*;

    // =============================================================================
    // TIMER STRUCT - For measuring operation duration
    // =============================================================================

    /// Timer for measuring the duration of database operations.
    pub struct DbOperationTimer {
        operation: String,
        start_time: Instant,
    }

    impl DbOperationTimer {
        /// Creates a new timer for measuring a database operation.
        ///
        /// # Arguments
        ///
        /// * `operation` - The operation being timed
        ///
        /// # Returns
        ///
        /// A timer that will automatically record the duration when dropped.
        #[allow(dead_code)]
        pub fn new(operation: &str) -> Self {
            observe_counter_vec(
                &USER_DB_OPERATIONS,
                "buildhub_auth_user_db_operations_total",
                &[operation, result::ATTEMPT],
            );

            DbOperationTimer {
                operation: operation.to_string(),
                start_time: Instant::now(),
            }
        }

        /// Records a successful database operation with its duration.
        #[allow(dead_code)]
        pub fn record_success(self) {
            let duration = self.start_time.elapsed().as_secs_f64();
            
            observe_counter_vec(
                &USER_DB_OPERATIONS,
                "buildhub_auth_user_db_operations_total",
                &[&self.operation, result::SUCCESS],
            );
            
            observe_histogram_vec(
                &USER_DB_DURATION,
                "buildhub_auth_user_db_duration_seconds",
                &[&self.operation, result::SUCCESS],
                duration,
            );
            
            // Prevent drop from being called
            std::mem::forget(self);
        }

        /// Records a failed database operation with its duration and error type.
        #[allow(dead_code)]
        pub fn record_failure(self, error_type: &str) {
            let duration = self.start_time.elapsed().as_secs_f64();
            
            observe_counter_vec(
                &USER_DB_OPERATIONS,
                "buildhub_auth_user_db_operations_total",
                &[&self.operation, result::FAILURE],
            );
            
            observe_counter_vec(
                &USER_DB_FAILURES,
                "buildhub_auth_user_db_failures_total",
                &[&self.operation, error_type],
            );
            
            observe_histogram_vec(
                &USER_DB_DURATION,
                "buildhub_auth_user_db_duration_seconds",
                &[&self.operation, result::FAILURE],
                duration,
            );
            
            // Prevent drop from being called
            std::mem::forget(self);
        }
    }

    // Implement Drop to ensure metrics are recorded even if forgotten
    impl Drop for DbOperationTimer {
        fn drop(&mut self) {
            // If neither success nor failure was explicitly recorded, record as failure
            let duration = self.start_time.elapsed().as_secs_f64();
            
            observe_counter_vec(
                &USER_DB_OPERATIONS,
                "buildhub_auth_user_db_operations_total",
                &[&self.operation, result::FAILURE],
            );
            
            observe_counter_vec(
                &USER_DB_FAILURES,
                "buildhub_auth_user_db_failures_total",
                &[&self.operation, error_type::UNKNOWN],
            );
            
            observe_histogram_vec(
                &USER_DB_DURATION,
                "buildhub_auth_user_db_duration_seconds",
                &[&self.operation, result::FAILURE],
                duration,
            );
        }
    }

    // =============================================================================
    // CONVENIENCE WRAPPERS - For backwards compatibility
    // =============================================================================

    /// Records a user creation attempt.
    pub fn record_create_attempt() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::CREATE, result::ATTEMPT],
        );
    }

    /// Records a successful user creation.
    pub fn record_create_success() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::CREATE, result::SUCCESS],
        );
    }

    /// Records a failed user creation with the specific error type.
    ///
    /// # Arguments
    ///
    /// * `error_type` - The specific type of error that occurred
    pub fn record_create_failure(error_type: &str) {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::CREATE, result::FAILURE],
        );
        observe_counter_vec(
            &USER_DB_FAILURES,
            "buildhub_auth_user_db_failures_total",
            &[operation::CREATE, error_type],
        );
    }

    /// Records a user lookup by username attempt.
    pub fn record_lookup_username_attempt() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::LOOKUP_USERNAME, result::ATTEMPT],
        );
    }

    /// Records a successful user lookup by username.
    pub fn record_lookup_username_success() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::LOOKUP_USERNAME, result::SUCCESS],
        );
    }

    /// Records a failed user lookup by username with the specific error type.
    ///
    /// # Arguments
    ///
    /// * `error_type` - The specific type of error that occurred
    pub fn record_lookup_username_failure(error_type: &str) {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::LOOKUP_USERNAME, result::FAILURE],
        );
        observe_counter_vec(
            &USER_DB_FAILURES,
            "buildhub_auth_user_db_failures_total",
            &[operation::LOOKUP_USERNAME, error_type],
        );
    }

    /// Records a user lookup by email attempt.
    pub fn record_lookup_email_attempt() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::LOOKUP_EMAIL, result::ATTEMPT],
        );
    }

    /// Records a successful user lookup by email.
    pub fn record_lookup_email_success() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::LOOKUP_EMAIL, result::SUCCESS],
        );
    }

    /// Records a failed user lookup by email with the specific error type.
    ///
    /// # Arguments
    ///
    /// * `error_type` - The specific type of error that occurred
    pub fn record_lookup_email_failure(error_type: &str) {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::LOOKUP_EMAIL, result::FAILURE],
        );
        observe_counter_vec(
            &USER_DB_FAILURES,
            "buildhub_auth_user_db_failures_total",
            &[operation::LOOKUP_EMAIL, error_type],
        );
    }

    /// Records a user update attempt.
    pub fn record_update_attempt() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::UPDATE, result::ATTEMPT],
        );
    }

    /// Records a successful user update.
    pub fn record_update_success() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::UPDATE, result::SUCCESS],
        );
    }

    /// Records a failed user update with the specific error type.
    ///
    /// # Arguments
    ///
    /// * `error_type` - The specific type of error that occurred
    pub fn record_update_failure(error_type: &str) {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::UPDATE, result::FAILURE],
        );
        observe_counter_vec(
            &USER_DB_FAILURES,
            "buildhub_auth_user_db_failures_total",
            &[operation::UPDATE, error_type],
        );
    }

    /// Records an account activation attempt.
    pub fn record_activate_attempt() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::ACTIVATE, result::ATTEMPT],
        );
    }

    /// Records a successful account activation.
    pub fn record_activate_success() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::ACTIVATE, result::SUCCESS],
        );
    }

    /// Records a failed account activation with the specific error type.
    ///
    /// # Arguments
    ///
    /// * `error_type` - The specific type of error that occurred
    pub fn record_activate_failure(error_type: &str) {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::ACTIVATE, result::FAILURE],
        );
        observe_counter_vec(
            &USER_DB_FAILURES,
            "buildhub_auth_user_db_failures_total",
            &[operation::ACTIVATE, error_type],
        );
    }

    /// Records a password update attempt.
    pub fn record_password_update_attempt() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::PASSWORD_UPDATE, result::ATTEMPT],
        );
    }

    /// Records a successful password update.
    pub fn record_password_update_success() {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::PASSWORD_UPDATE, result::SUCCESS],
        );
    }

    /// Records a failed password update with the specific error type.
    ///
    /// # Arguments
    ///
    /// * `error_type` - The specific type of error that occurred
    pub fn record_password_update_failure(error_type: &str) {
        observe_counter_vec(
            &USER_DB_OPERATIONS,
            "buildhub_auth_user_db_operations_total",
            &[operation::PASSWORD_UPDATE, result::FAILURE],
        );
        observe_counter_vec(
            &USER_DB_FAILURES,
            "buildhub_auth_user_db_failures_total",
            &[operation::PASSWORD_UPDATE, error_type],
        );
    }

    // =============================================================================
    // MODERN API - For new code using the timer pattern
    // =============================================================================

    /// Creates a timer for measuring a user creation operation.
    ///
    /// # Returns
    ///
    /// A timer that will automatically record the duration when completed.
    ///
    /// # Example
    ///
    /// ```
    /// let timer = user::time_create_operation();
    /// // Perform database operation...
    /// if success {
    ///    timer.record_success();
    /// } else {
    ///    timer.record_failure(error_type::DUPLICATE);
    /// }
    /// ```
    #[allow(dead_code)]
    pub fn time_create_operation() -> DbOperationTimer {
        DbOperationTimer::new(operation::CREATE)
    }

    /// Creates a timer for measuring a user lookup by username operation.
    #[allow(dead_code)]
    pub fn time_lookup_username_operation() -> DbOperationTimer {
        DbOperationTimer::new(operation::LOOKUP_USERNAME)
    }

    /// Creates a timer for measuring a user lookup by email operation.
    #[allow(dead_code)]
    pub fn time_lookup_email_operation() -> DbOperationTimer {
        DbOperationTimer::new(operation::LOOKUP_EMAIL)
    }

    /// Creates a timer for measuring a user update operation.
    #[allow(dead_code)]
    pub fn time_update_operation() -> DbOperationTimer {
        DbOperationTimer::new(operation::UPDATE)
    }

    /// Creates a timer for measuring an account activation operation.
    #[allow(dead_code)]
    pub fn time_activate_operation() -> DbOperationTimer {
        DbOperationTimer::new(operation::ACTIVATE)
    }

    /// Creates a timer for measuring a password update operation.
    #[allow(dead_code)]
    pub fn time_password_update_operation() -> DbOperationTimer {
        DbOperationTimer::new(operation::PASSWORD_UPDATE)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_database_operations() {
        init_database_metrics();

        let before_startup = DB_POOL_OPERATIONS
            .with_label_values(&[result::ATTEMPT, context::STARTUP])
            .get();

        pool::record_startup_attempt();

        let after_startup = DB_POOL_OPERATIONS
            .with_label_values(&[result::ATTEMPT, context::STARTUP])
            .get();

        assert_eq!(after_startup, before_startup + 1.0);
    }

    #[test]
    fn test_context_separation() {
        init_database_metrics();

        // Test startup operations
        connection::record_startup_attempt();
        connection::record_startup_success();

        // Test runtime operations
        connection::record_runtime_attempt();
        connection::record_runtime_failure();

        // Verify startup has 100% success rate
        let startup_attempts = DB_CONNECTION_OPERATIONS
            .with_label_values(&[result::ATTEMPT, context::STARTUP])
            .get();
        let startup_successes = DB_CONNECTION_OPERATIONS
            .with_label_values(&[result::SUCCESS, context::STARTUP])
            .get();
        assert_eq!(startup_attempts, startup_successes);

        // Verify runtime has 0% success rate
        let runtime_attempts = DB_CONNECTION_OPERATIONS
            .with_label_values(&[result::ATTEMPT, context::APPLICATION])
            .get();
        let runtime_failures = DB_CONNECTION_OPERATIONS
            .with_label_values(&[result::FAILURE, context::APPLICATION])
            .get();
        assert_eq!(runtime_attempts, runtime_failures);
    }

    #[test]
    fn test_all_helper_functions() {
        init_database_metrics();

        // Test all pool helpers
        pool::record_startup_attempt();
        pool::record_startup_success();
        pool::record_startup_failure();

        // Test all connection helpers
        connection::record_startup_attempt();
        connection::record_startup_success();
        connection::record_startup_failure();
        connection::record_runtime_attempt();
        connection::record_runtime_success();
        connection::record_runtime_failure();

        // Test all migration helpers
        migration::record_startup_attempt();
        migration::record_startup_success();
        migration::record_startup_failure();

        // Test all user helpers
        user::record_create_attempt();
        user::record_create_success();
        user::record_create_failure(error_type::NOT_FOUND);

        user::record_lookup_username_attempt();
        user::record_lookup_username_success();
        user::record_lookup_username_failure(error_type::NOT_FOUND);

        user::record_lookup_email_attempt();
        user::record_lookup_email_success();
        user::record_lookup_email_failure(error_type::NOT_FOUND);

        user::record_update_attempt();
        user::record_update_success();
        user::record_update_failure(error_type::QUERY_ERROR);

        user::record_activate_attempt();
        user::record_activate_success();
        user::record_activate_failure(error_type::NO_ID);

        user::record_password_update_attempt();
        user::record_password_update_success();
        user::record_password_update_failure(error_type::HASH_ERROR);

        // If we get here, all helpers work without panicking
        assert!(true);
    }

    #[test]
    fn test_user_metrics_separation() {
        init_database_metrics();

        // Test create operations
        user::record_create_attempt();
        user::record_create_success();

        // Test lookup operations
        user::record_lookup_username_attempt();
        user::record_lookup_username_failure(error_type::NOT_FOUND);

        // Verify create has 100% success rate
        let create_attempts = USER_DB_OPERATIONS
            .with_label_values(&[operation::CREATE, result::ATTEMPT])
            .get();
        let create_successes = USER_DB_OPERATIONS
            .with_label_values(&[operation::CREATE, result::SUCCESS])
            .get();
        assert_eq!(create_attempts, create_successes);

        // Verify lookup_username has 0% success rate
        let lookup_attempts = USER_DB_OPERATIONS
            .with_label_values(&[operation::LOOKUP_USERNAME, result::ATTEMPT])
            .get();
        let lookup_failures = USER_DB_OPERATIONS
            .with_label_values(&[operation::LOOKUP_USERNAME, result::FAILURE])
            .get();
        assert_eq!(lookup_attempts, lookup_failures);

        // Verify specific failure type
        let not_found_failures = USER_DB_FAILURES
            .with_label_values(&[operation::LOOKUP_USERNAME, error_type::NOT_FOUND])
            .get();
        assert_eq!(not_found_failures, 1.0);
    }

    #[test]
    fn test_timer_pattern() {
        init_database_metrics();

        // Test successful operation timing
        {
            let timer = user::DbOperationTimer::new(operation::CREATE);
            thread::sleep(Duration::from_millis(10)); // Simulate work
            timer.record_success();
        }

        // Test failed operation timing
        {
            let timer = user::DbOperationTimer::new(operation::LOOKUP_EMAIL);
            thread::sleep(Duration::from_millis(5)); // Simulate work
            timer.record_failure(error_type::NOT_FOUND);
        }

        // Verify metrics were recorded
        let create_successes = USER_DB_OPERATIONS
            .with_label_values(&[operation::CREATE, result::SUCCESS])
            .get();
        let lookup_failures = USER_DB_OPERATIONS
            .with_label_values(&[operation::LOOKUP_EMAIL, result::FAILURE])
            .get();
        
        assert_eq!(create_successes, 1.0);
        assert_eq!(lookup_failures, 1.0);

        // Verify durations were recorded
        let create_duration_samples = USER_DB_DURATION
            .with_label_values(&[operation::CREATE, result::SUCCESS])
            .get_sample_count();
        let lookup_duration_samples = USER_DB_DURATION
            .with_label_values(&[operation::LOOKUP_EMAIL, result::FAILURE])
            .get_sample_count();
        
        assert_eq!(create_duration_samples, 1);
        assert_eq!(lookup_duration_samples, 1);
    }

    #[test]
    fn test_timer_implicit_failure() {
        init_database_metrics();

        // Timer dropped without explicit success/failure
        {
            let _timer = user::DbOperationTimer::new(operation::UPDATE);
            // Intentionally don't call record_success or record_failure
        }

        // Verify implicit failure was recorded
        let update_failures = USER_DB_OPERATIONS
            .with_label_values(&[operation::UPDATE, result::FAILURE])
            .get();
        let unknown_failures = USER_DB_FAILURES
            .with_label_values(&[operation::UPDATE, error_type::UNKNOWN])
            .get();
        
        assert_eq!(update_failures, 1.0);
        assert_eq!(unknown_failures, 1.0);
    }

    #[test]
    fn test_constants_type_safety() {
        // Verify our constants are valid and type-safe
        assert_eq!(result::ATTEMPT, "attempt");
        assert_eq!(result::SUCCESS, "success");
        assert_eq!(result::FAILURE, "failure");

        assert_eq!(context::STARTUP, "startup");
        assert_eq!(context::APPLICATION, "application");

        assert_eq!(operation::CREATE, "create");
        assert_eq!(operation::LOOKUP_USERNAME, "lookup_username");
        assert_eq!(operation::LOOKUP_EMAIL, "lookup_email");
        assert_eq!(operation::UPDATE, "update");
        assert_eq!(operation::ACTIVATE, "activate");
        assert_eq!(operation::PASSWORD_UPDATE, "password_update");

        assert_eq!(error_type::NOT_FOUND, "not_found");
        assert_eq!(error_type::QUERY_ERROR, "query_error");
        assert_eq!(error_type::DUPLICATE, "duplicate");
        assert_eq!(error_type::HASH_ERROR, "hash_error");
    }
}
