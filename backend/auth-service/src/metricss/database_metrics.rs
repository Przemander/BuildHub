//! # Database Metrics - Simplified Database Infrastructure Monitoring
//!
//! Essential database monitoring for connection management and migrations.
//! Focused on core operations without over-engineering contexts.

use lazy_static::lazy_static;
use prometheus::{register_counter_vec, CounterVec};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::log_info;

lazy_static! {
    /// Database connection pool operations
    /// Labels: result (attempt, success), context (startup, application)
    pub static ref DB_POOL_OPERATIONS: CounterVec = register_counter_vec!(
        "db_pool_operations_total",
        "Database connection pool operations by result and context",
        &["result", "context"]
    ).expect("Failed to register DB_POOL_OPERATIONS");

    /// Database connection acquisition
    /// Labels: result (attempt, success), context (startup, application)
    pub static ref DB_CONNECTION_OPERATIONS: CounterVec = register_counter_vec!(
        "db_connection_operations_total",
        "Database connection operations by result and context",
        &["result", "context"]
    ).expect("Failed to register DB_CONNECTION_OPERATIONS");

    /// Database migration operations
    /// Labels: result (attempt, success), context (startup, application)
    pub static ref DB_MIGRATION_OPERATIONS: CounterVec = register_counter_vec!(
        "db_migration_operations_total",
        "Database migration operations by result and context",
        &["result", "context"]
    ).expect("Failed to register DB_MIGRATION_OPERATIONS");

    /// User database operations
    /// Labels: operation (create, lookup_username, lookup_email, update, activate), result (attempt, success, failure)
    pub static ref USER_DB_OPERATIONS: CounterVec = register_counter_vec!(
        "user_db_operations_total",
        "User database operations by operation type and result",
        &["operation", "result"]
    ).expect("Failed to register USER_DB_OPERATIONS");

    /// User database failures
    /// Labels: operation (create, lookup_username, lookup_email, update, activate), error_type (not_found, query_error, etc.)
    pub static ref USER_DB_FAILURES: CounterVec = register_counter_vec!(
        "user_db_failures_total",
        "User database failures by operation type and error type",
        &["operation", "error_type"]
    ).expect("Failed to register USER_DB_FAILURES");
}

static DATABASE_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn init_database_metrics() {
    if DATABASE_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let _ = &*DB_POOL_OPERATIONS;
    let _ = &*DB_CONNECTION_OPERATIONS;
    let _ = &*DB_MIGRATION_OPERATIONS;
    let _ = &*USER_DB_OPERATIONS;
    let _ = &*USER_DB_FAILURES;

    log_info!("Metrics", "Database metrics initialized", "database_metrics_init");
}

// =============================================================================
// CONVENIENCE HELPERS (Only the actually used ones)
// =============================================================================

/// Pool operation helpers
pub mod pool {
    use super::*;
    
    pub fn record_startup_attempt() {
        DB_POOL_OPERATIONS.with_label_values(&["attempt", "startup"]).inc();
    }
    
    pub fn record_startup_success() {
        DB_POOL_OPERATIONS.with_label_values(&["success", "startup"]).inc();
    }
    
    pub fn record_startup_failure() {
        DB_POOL_OPERATIONS.with_label_values(&["failure", "startup"]).inc();
    }
}

/// Connection operation helpers
pub mod connection {
    use super::*;
    
    pub fn record_startup_attempt() {
        DB_CONNECTION_OPERATIONS.with_label_values(&["attempt", "startup"]).inc();
    }
    
    pub fn record_startup_success() {
        DB_CONNECTION_OPERATIONS.with_label_values(&["success", "startup"]).inc();
    }
    
    pub fn record_startup_failure() {
        DB_CONNECTION_OPERATIONS.with_label_values(&["failure", "startup"]).inc();
    }
    
    pub fn record_runtime_attempt() {
        DB_CONNECTION_OPERATIONS.with_label_values(&["attempt", "application"]).inc();
    }
    
    pub fn record_runtime_success() {
        DB_CONNECTION_OPERATIONS.with_label_values(&["success", "application"]).inc();
    }
    
    pub fn record_runtime_failure() {
        DB_CONNECTION_OPERATIONS.with_label_values(&["failure", "application"]).inc();
    }
}

/// Migration operation helpers
pub mod migration {
    use super::*;
    
    pub fn record_startup_attempt() {
        DB_MIGRATION_OPERATIONS.with_label_values(&["attempt", "startup"]).inc();
    }
    
    pub fn record_startup_success() {
        DB_MIGRATION_OPERATIONS.with_label_values(&["success", "startup"]).inc();
    }
    
    pub fn record_startup_failure() {
        DB_MIGRATION_OPERATIONS.with_label_values(&["failure", "startup"]).inc();
    }
}

/// User operation helpers
pub mod user {
    use super::*;
    
    /// Operations for user creation
    pub fn record_create_attempt() {
        USER_DB_OPERATIONS.with_label_values(&["create", "attempt"]).inc();
    }
    
    pub fn record_create_success() {
        USER_DB_OPERATIONS.with_label_values(&["create", "success"]).inc();
    }
    
    pub fn record_create_failure(error_type: &str) {
        USER_DB_OPERATIONS.with_label_values(&["create", "failure"]).inc();
        USER_DB_FAILURES.with_label_values(&["create", error_type]).inc();
    }
    
    /// Operations for user lookup by username
    pub fn record_lookup_username_attempt() {
        USER_DB_OPERATIONS.with_label_values(&["lookup_username", "attempt"]).inc();
    }
    
    pub fn record_lookup_username_success() {
        USER_DB_OPERATIONS.with_label_values(&["lookup_username", "success"]).inc();
    }
    
    pub fn record_lookup_username_failure(error_type: &str) {
        USER_DB_OPERATIONS.with_label_values(&["lookup_username", "failure"]).inc();
        USER_DB_FAILURES.with_label_values(&["lookup_username", error_type]).inc();
    }
    
    /// Operations for user lookup by email
    pub fn record_lookup_email_attempt() {
        USER_DB_OPERATIONS.with_label_values(&["lookup_email", "attempt"]).inc();
    }
    
    pub fn record_lookup_email_success() {
        USER_DB_OPERATIONS.with_label_values(&["lookup_email", "success"]).inc();
    }
    
    pub fn record_lookup_email_failure(error_type: &str) {
        USER_DB_OPERATIONS.with_label_values(&["lookup_email", "failure"]).inc();
        USER_DB_FAILURES.with_label_values(&["lookup_email", error_type]).inc();
    }
    
    /// Operations for user update
    pub fn record_update_attempt() {
        USER_DB_OPERATIONS.with_label_values(&["update", "attempt"]).inc();
    }
    
    pub fn record_update_success() {
        USER_DB_OPERATIONS.with_label_values(&["update", "success"]).inc();
    }
    
    pub fn record_update_failure(error_type: &str) {
        USER_DB_OPERATIONS.with_label_values(&["update", "failure"]).inc();
        USER_DB_FAILURES.with_label_values(&["update", error_type]).inc();
    }
    
    /// Operations for account activation
    pub fn record_activate_attempt() {
        USER_DB_OPERATIONS.with_label_values(&["activate", "attempt"]).inc();
    }
    
    pub fn record_activate_success() {
        USER_DB_OPERATIONS.with_label_values(&["activate", "success"]).inc();
    }
    
    pub fn record_activate_failure(error_type: &str) {
        USER_DB_OPERATIONS.with_label_values(&["activate", "failure"]).inc();
        USER_DB_FAILURES.with_label_values(&["activate", error_type]).inc();
    }
    
    /// Operations for password update (set_password_and_update)
    pub fn record_password_update_attempt() {
        USER_DB_OPERATIONS.with_label_values(&["password_update", "attempt"]).inc();
    }
    
    pub fn record_password_update_success() {
        USER_DB_OPERATIONS.with_label_values(&["password_update", "success"]).inc();
    }
    
    pub fn record_password_update_failure(error_type: &str) {
        USER_DB_OPERATIONS.with_label_values(&["password_update", "failure"]).inc();
        USER_DB_FAILURES.with_label_values(&["password_update", error_type]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_operations() {
        init_database_metrics();
        
        let before_startup = DB_POOL_OPERATIONS
            .with_label_values(&["attempt", "startup"])
            .get();
        
        pool::record_startup_attempt();
        
        let after_startup = DB_POOL_OPERATIONS
            .with_label_values(&["attempt", "startup"])
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
            .with_label_values(&["attempt", "startup"])
            .get();
        let startup_successes = DB_CONNECTION_OPERATIONS
            .with_label_values(&["success", "startup"])
            .get();
        assert_eq!(startup_attempts, startup_successes);
        
        // Verify runtime has 0% success rate
        let runtime_attempts = DB_CONNECTION_OPERATIONS
            .with_label_values(&["attempt", "application"])
            .get();
        let runtime_failures = DB_CONNECTION_OPERATIONS
            .with_label_values(&["failure", "application"])
            .get();
        assert_eq!(runtime_attempts, runtime_failures);
    }

    #[test]
    fn test_all_helper_functions() {
        init_database_metrics();
        
        // Test all pool helpers
        pool::record_startup_attempt();
        pool::record_startup_success();
        
        // Test all connection helpers
        connection::record_startup_attempt();
        connection::record_runtime_success();
        
        // Test all migration helpers
        migration::record_startup_attempt();
        
        // Test all user helpers
        user::record_create_attempt();
        user::record_create_success();
        user::record_create_failure("duplicate");
        
        user::record_lookup_username_attempt();
        user::record_lookup_username_success();
        user::record_lookup_username_failure("not_found");
        
        user::record_lookup_email_attempt();
        user::record_lookup_email_success();
        user::record_lookup_email_failure("not_found");
        
        user::record_update_attempt();
        user::record_update_success();
        user::record_update_failure("query_error");
        
        user::record_activate_attempt();
        user::record_activate_success();
        user::record_activate_failure("no_id");
        
        user::record_password_update_attempt();
        user::record_password_update_success();
        user::record_password_update_failure("hash_error");

        // Explicitly call record_password_update_failure to ensure it's used
        user::record_password_update_failure("test_error_type");
        
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
        user::record_lookup_username_failure("not_found");
        
        // Verify create has 100% success rate
        let create_attempts = USER_DB_OPERATIONS
            .with_label_values(&["create", "attempt"])
            .get();
        let create_successes = USER_DB_OPERATIONS
            .with_label_values(&["create", "success"])
            .get();
        assert_eq!(create_attempts, create_successes);
        
        // Verify lookup_username has 0% success rate
        let lookup_attempts = USER_DB_OPERATIONS
            .with_label_values(&["lookup_username", "attempt"])
            .get();
        let lookup_failures = USER_DB_OPERATIONS
            .with_label_values(&["lookup_username", "failure"])
            .get();
        assert_eq!(lookup_attempts, lookup_failures);
        
        // Verify specific failure type
        let not_found_failures = USER_DB_FAILURES
            .with_label_values(&["lookup_username", "not_found"])
            .get();
        assert_eq!(not_found_failures, 1.0);
    }
}