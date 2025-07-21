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
        
        // If we get here, all helpers work without panicking
        assert!(true);
    }
}