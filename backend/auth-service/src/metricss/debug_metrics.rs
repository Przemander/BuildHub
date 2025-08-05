//! Metrics for debug operations to monitor usage and performance of test/debug endpoints.
//!
//! This module provides metrics for auditing and monitoring debug operations,
//! which is especially important for security and compliance.

use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, 
    register_histogram_vec, register_int_counter_vec
};
use lazy_static::lazy_static;
use std::time::Instant;

/// Debug operation type constants
pub mod operation_types {
    pub const CLEAN_USER: &str = "clean_user";
    pub const RESET_RATE_LIMITER: &str = "reset_rate_limiter";
    pub const ACTIVATE_ACCOUNT: &str = "activate_account";
    pub const VERIFY_USER: &str = "verify_user";
    pub const CREATE_RESET_TOKEN: &str = "create_reset_token";
}

lazy_static! {
    static ref DEBUG_OPERATION_DURATION: HistogramVec = register_histogram_vec!(
        HistogramOpts::new(
            "debug_operation_duration_seconds",
            "Duration of debug operations in seconds"
        )
        .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["operation"]
    )
    .unwrap();

    static ref DEBUG_OPERATION_TOTAL: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "debug_operation_total",
            "Total number of debug operations"
        ),
        &["operation", "result"]
    )
    .unwrap();
    
    static ref DEBUG_ACCESS_ATTEMPT_TOTAL: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "debug_access_attempt_total",
            "Total number of attempts to access debug endpoints"
        ),
        &["status"]
    )
    .unwrap();

    static ref DEBUG_REDIS_OPERATION_TOTAL: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "debug_redis_operation_total",
            "Total number of Redis operations performed by debug endpoints"
        ),
        &["operation", "result"]
    )
    .unwrap();
}

/// Initialize metrics by ensuring lazy_static initialization
pub fn init() {
    lazy_static::initialize(&DEBUG_OPERATION_DURATION);
    lazy_static::initialize(&DEBUG_OPERATION_TOTAL);
    lazy_static::initialize(&DEBUG_ACCESS_ATTEMPT_TOTAL);
    lazy_static::initialize(&DEBUG_REDIS_OPERATION_TOTAL);
}

/// Records the start of a debug operation and returns a timer that
/// will record the duration when dropped
pub fn time_operation(operation: &str) -> OperationTimer {
    OperationTimer {
        operation: operation.to_string(),
        start: Instant::now(),
    }
}

/// Records a successful debug operation
pub fn record_operation_success(operation: &str) {
    DEBUG_OPERATION_TOTAL
        .with_label_values(&[operation, "success"])
        .inc();
}

/// Records a failed debug operation
pub fn record_operation_failure(operation: &str) {
    DEBUG_OPERATION_TOTAL
        .with_label_values(&[operation, "failure"])
        .inc();
}

/// Records an attempt to access debug endpoints
pub fn record_access_attempt(status: &str) {
    DEBUG_ACCESS_ATTEMPT_TOTAL
        .with_label_values(&[status])
        .inc();
}

/// Records a Redis operation performed by debug endpoints
pub fn record_redis_operation_success(operation: &str) {
    DEBUG_REDIS_OPERATION_TOTAL
        .with_label_values(&[operation, "success"])
        .inc();
}

/// Records a failed Redis operation performed by debug endpoints
pub fn record_redis_operation_failure(operation: &str) {
    DEBUG_REDIS_OPERATION_TOTAL
        .with_label_values(&[operation, "failure"])
        .inc();
}

/// Helper struct to time debug operations
pub struct OperationTimer {
    operation: String,
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

/// Register metrics with the provided registry
pub fn register_metrics(registry: &Registry) -> Result<(), prometheus::Error> {
    registry.register(Box::new(DEBUG_OPERATION_DURATION.clone()))?;
    registry.register(Box::new(DEBUG_OPERATION_TOTAL.clone()))?;
    registry.register(Box::new(DEBUG_ACCESS_ATTEMPT_TOTAL.clone()))?;
    registry.register(Box::new(DEBUG_REDIS_OPERATION_TOTAL.clone()))?;
    Ok(())
}