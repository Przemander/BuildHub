//! # Debug Metrics for BuildHub Auth Service
//!
//! This module provides comprehensive metrics for auditing and monitoring debug/test endpoints,
//! which is critical for security, compliance, and operational visibility.
//!
//! ## Design Goals
//!
//! - **Complete Auditability**: Track all access to debug functionality
//! - **Performance Monitoring**: Measure execution time of debug operations
//! - **Security Compliance**: Record access patterns for security review
//! - **Operation Tracking**: Monitor all debug operations with success/failure status
//! - **Dependency Monitoring**: Track interactions with external systems (Redis)
//!
//! ## Usage Notes
//!
//! This module is intended for non-production environments only. In production,
//! these endpoints should be disabled, but the metrics remain available to track
//! any unauthorized access attempts.

use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, HistogramOpts, HistogramVec, IntCounterVec,
    Opts, Registry,
};
use std::time::Instant;

/// Debug operation type constants for type-safe operation tracking
#[allow(dead_code)]
pub mod operation_types {
    /// Clean user data from the system
    pub const CLEAN_USER: &str = "clean_user";
    /// Reset rate limiter counters for a user
    pub const RESET_RATE_LIMITER: &str = "reset_rate_limiter";
    /// Manually activate a user account
    pub const ACTIVATE_ACCOUNT: &str = "activate_account";
    /// Manually verify a user identity
    pub const VERIFY_USER: &str = "verify_user";
    /// Manually create a password reset token
    pub const CREATE_RESET_TOKEN: &str = "create_reset_token";
}

/// Access status constants for tracking debug endpoint access
#[allow(dead_code)]
pub mod access_status {
    /// Access allowed (user has debug permissions)
    pub const ALLOWED: &str = "allowed";
    /// Access denied (user lacks debug permissions)
    pub const DENIED: &str = "denied";
    /// Invalid authentication credentials
    pub const INVALID_AUTH: &str = "invalid_auth";
    /// Missing authentication credentials
    pub const MISSING_AUTH: &str = "missing_auth";
    /// Invalid request format or parameters
    pub const INVALID_REQUEST: &str = "invalid_request";
}

/// Redis operation constants for tracking debug-related Redis operations
#[allow(dead_code)]
pub mod redis_operations {
    /// Clear rate limiting data
    pub const CLEAR_RATE_LIMIT: &str = "clear_rate_limit";
    /// Remove session data
    pub const CLEAR_SESSION: &str = "clear_session";
    /// Remove verification tokens
    pub const CLEAR_VERIFICATION: &str = "clear_verification";
    /// Remove reset tokens
    pub const CLEAR_RESET_TOKEN: &str = "clear_reset_token";
}

lazy_static! {
    /// Histogram tracking duration of debug operations
    ///
    /// Measures how long each debug operation takes to execute.
    /// Critical for performance monitoring and detecting slow operations.
    ///
    /// # Labels
    /// * `operation`: The specific debug operation being executed
    static ref DEBUG_OPERATION_DURATION: HistogramVec = register_histogram_vec!(
        HistogramOpts::new(
            "debug_operation_duration_seconds",
            "Duration of debug operations in seconds"
        )
        .buckets(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]),
        &["operation"]
    )
    .unwrap();

    /// Counter tracking debug operation execution
    ///
    /// Counts all debug operations with their success/failure status.
    /// Essential for detecting problematic operations and usage patterns.
    ///
    /// # Labels
    /// * `operation`: The specific debug operation being executed
    /// * `result`: Operation result (success, failure)
    static ref DEBUG_OPERATION_TOTAL: IntCounterVec = register_int_counter_vec!(
        Opts::new("debug_operation_total", "Total number of debug operations"),
        &["operation", "result"]
    )
    .unwrap();

    /// Counter tracking attempts to access debug endpoints
    ///
    /// Records all access attempts to debug endpoints, whether successful or not.
    /// Critical for security monitoring and compliance auditing.
    ///
    /// # Labels
    /// * `status`: Access status (allowed, denied, invalid_auth, etc.)
    static ref DEBUG_ACCESS_ATTEMPT_TOTAL: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "debug_access_attempt_total",
            "Total number of attempts to access debug endpoints"
        ),
        &["status"]
    )
    .unwrap();

    /// Counter tracking Redis operations performed by debug endpoints
    ///
    /// Monitors interactions with Redis from debug endpoints.
    /// Important for tracking external system impacts and dependencies.
    ///
    /// # Labels
    /// * `operation`: The specific Redis operation being performed
    /// * `result`: Operation result (success, failure)
    static ref DEBUG_REDIS_OPERATION_TOTAL: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "debug_redis_operation_total",
            "Total number of Redis operations performed by debug endpoints"
        ),
        &["operation", "result"]
    )
    .unwrap();
}

/// Initialize all debug metrics
///
/// Forces initialization of all lazy_static metrics to ensure they're
/// properly registered and available for collection.
#[allow(dead_code)]
pub fn init() {
    lazy_static::initialize(&DEBUG_OPERATION_DURATION);
    lazy_static::initialize(&DEBUG_OPERATION_TOTAL);
    lazy_static::initialize(&DEBUG_ACCESS_ATTEMPT_TOTAL);
    lazy_static::initialize(&DEBUG_REDIS_OPERATION_TOTAL);
}

/// Records the start of a debug operation and returns a timer
///
/// Creates an RAII timer that will automatically record the operation
/// duration when it goes out of scope.
///
/// # Arguments
///
/// * `operation` - The name of the operation being timed
///
/// # Returns
///
/// An `OperationTimer` that will record the duration when dropped
///
/// # Example
///
/// ```
/// let timer = debug_metrics::time_operation(operation_types::CLEAN_USER);
/// // Perform operation...
/// // Timer automatically records duration when it goes out of scope
/// ```
#[allow(dead_code)]
pub fn time_operation(operation: &str) -> OperationTimer {
    OperationTimer {
        operation: operation.to_string(),
        start: Instant::now(),
    }
}

/// Records a successful debug operation
///
/// Increments the success counter for the specified operation type.
///
/// # Arguments
///
/// * `operation` - The name of the operation that succeeded
#[allow(dead_code)]
pub fn record_operation_success(operation: &str) {
    DEBUG_OPERATION_TOTAL
        .with_label_values(&[operation, "success"])
        .inc();
}

/// Records a failed debug operation
///
/// Increments the failure counter for the specified operation type.
///
/// # Arguments
///
/// * `operation` - The name of the operation that failed
#[allow(dead_code)]
pub fn record_operation_failure(operation: &str) {
    DEBUG_OPERATION_TOTAL
        .with_label_values(&[operation, "failure"])
        .inc();
}

/// Records an attempt to access debug endpoints
///
/// Tracks all access attempts to debug endpoints with their status.
///
/// # Arguments
///
/// * `status` - The status of the access attempt (see `access_status` constants)
#[allow(dead_code)]
pub fn record_access_attempt(status: &str) {
    DEBUG_ACCESS_ATTEMPT_TOTAL
        .with_label_values(&[status])
        .inc();
}

/// Records a successful Redis operation performed by debug endpoints
///
/// Increments the success counter for the specified Redis operation.
///
/// # Arguments
///
/// * `operation` - The Redis operation that succeeded
#[allow(dead_code)]
pub fn record_redis_operation_success(operation: &str) {
    DEBUG_REDIS_OPERATION_TOTAL
        .with_label_values(&[operation, "success"])
        .inc();
}

/// Records a failed Redis operation performed by debug endpoints
///
/// Increments the failure counter for the specified Redis operation.
///
/// # Arguments
///
/// * `operation` - The Redis operation that failed
#[allow(dead_code)]
pub fn record_redis_operation_failure(operation: &str) {
    DEBUG_REDIS_OPERATION_TOTAL
        .with_label_values(&[operation, "failure"])
        .inc();
}

/// Helper struct to time debug operations using RAII pattern
///
/// When this struct goes out of scope, it automatically records
/// the operation duration in the metrics.
#[allow(dead_code)]
pub struct OperationTimer {
    /// Name of the operation being timed
    operation: String,
    /// Start time of the operation
    start: Instant,
}

impl Drop for OperationTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        DEBUG_OPERATION_DURATION
            .with_label_values(&[&self.operation])
            .observe(duration);
    }
}

/// Register metrics with a custom registry
///
/// Useful for exposing metrics through a separate endpoint or for testing.
///
/// # Arguments
///
/// * `registry` - The registry to register metrics with
///
/// # Returns
///
/// Result indicating success or failure of registration
#[allow(dead_code)]
pub fn register_metrics(registry: &Registry) -> Result<(), prometheus::Error> {
    registry.register(Box::new(DEBUG_OPERATION_DURATION.clone()))?;
    registry.register(Box::new(DEBUG_OPERATION_TOTAL.clone()))?;
    registry.register(Box::new(DEBUG_ACCESS_ATTEMPT_TOTAL.clone()))?;
    registry.register(Box::new(DEBUG_REDIS_OPERATION_TOTAL.clone()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_operation_timer() {
        // Initialize metrics
        init();

        // Create and drop a timer
        {
            let _timer = time_operation("test_operation");
            thread::sleep(Duration::from_millis(10));
        }

        // Verify the duration was recorded
        let sample_count = DEBUG_OPERATION_DURATION
            .with_label_values(&["test_operation"])
            .get_sample_count();

        assert_eq!(sample_count, 1);
    }

    #[test]
    fn test_operation_tracking() {
        // Initialize metrics
        init();

        // Record success and failure
        record_operation_success("test_success");
        record_operation_failure("test_failure");

        // Verify counts
        let success_count = DEBUG_OPERATION_TOTAL
            .with_label_values(&["test_success", "success"])
            .get();
        let failure_count = DEBUG_OPERATION_TOTAL
            .with_label_values(&["test_failure", "failure"])
            .get();

        assert_eq!(success_count, 1);
        assert_eq!(failure_count, 1);
    }

    #[test]
    fn test_access_attempt_tracking() {
        // Initialize metrics
        init();

        // Record access attempts
        record_access_attempt(access_status::ALLOWED);
        record_access_attempt(access_status::DENIED);

        // Verify counts
        let allowed_count = DEBUG_ACCESS_ATTEMPT_TOTAL
            .with_label_values(&[access_status::ALLOWED])
            .get();
        let denied_count = DEBUG_ACCESS_ATTEMPT_TOTAL
            .with_label_values(&[access_status::DENIED])
            .get();

        assert_eq!(allowed_count, 1);
        assert_eq!(denied_count, 1);
    }

    #[test]
    fn test_redis_operation_tracking() {
        // Initialize metrics
        init();

        // Record Redis operations
        record_redis_operation_success(redis_operations::CLEAR_RATE_LIMIT);
        record_redis_operation_failure(redis_operations::CLEAR_SESSION);

        // Verify counts
        let success_count = DEBUG_REDIS_OPERATION_TOTAL
            .with_label_values(&[redis_operations::CLEAR_RATE_LIMIT, "success"])
            .get();
        let failure_count = DEBUG_REDIS_OPERATION_TOTAL
            .with_label_values(&[redis_operations::CLEAR_SESSION, "failure"])
            .get();

        assert_eq!(success_count, 1);
        assert_eq!(failure_count, 1);
    }
}
