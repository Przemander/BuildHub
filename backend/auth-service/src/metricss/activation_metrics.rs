//! # Activation Metrics - Production-Grade Account Activation Flow Monitoring
//!
//! Essential activation flow monitoring for complete user onboarding observability.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **End-to-End Flow Tracking**: Monitor complete activation journey
//! - **Step-by-Step Observability**: Track each activation phase separately
//! - **Business Intelligence**: Activation success rates and failure analysis
//! - **Performance Monitoring**: Activation flow latency and bottlenecks
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (5 Essential)
//! - `activation_operations_total`: Activation operations by step and result
//! - `activation_failures_total`: Activation failures by specific step and error type
//! - `activation_duration_seconds`: Activation flow duration for performance monitoring
//! - `activation_http_requests_total`: HTTP requests by method and status code
//! - `activation_http_duration_seconds`: HTTP request duration for API performance
//!
//! ## Production Alerts
//! - High activation failure rates (onboarding issues)
//! - Activation flow bottlenecks (user experience)
//! - Infrastructure failures during activation (system health)
//! - HTTP API health and performance monitoring

use crate::log_info;
use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramTimer, HistogramVec};
use std::sync::atomic::{AtomicBool, Ordering};

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_MEDIUM, // Involves Redis and DB
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Activation operations by step and result
    ///
    /// Essential for monitoring activation flow completion and identifying
    /// bottlenecks in the user onboarding process.
    ///
    /// # Labels
    /// * `step`: Activation flow step
    ///   - `"redis_check"`: Redis client availability check
    ///   - `"code_validation"`: Activation code verification
    ///   - `"user_lookup"`: User search by email
    ///   - `"account_activation"`: Account status update
    ///   - `"code_cleanup"`: Activation code removal
    ///   - `"complete_flow"`: End-to-end activation process
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Step completed successfully
    ///   - `"failure"`: Step failed for any reason
    ///
    /// # Business Impact
    /// - **User Onboarding**: Failed activations block new users
    /// - **Conversion Rates**: Activation success affects retention
    /// - **Support Load**: High failures increase support tickets
    pub static ref ACTIVATION_OPERATIONS: CounterVec = create_counter_vec(
        "activation_operations_total",
        "Activation operations by step and result",
        &["step", "result"]
    ).expect("Failed to create ACTIVATION_OPERATIONS metric");

    /// **Failure Analysis Metric**: Activation failures by specific step and error type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and
    /// onboarding optimization.
    ///
    /// # Labels
    /// * `step`: Activation step that failed
    /// * `error_type`: Specific type of failure
    ///   - `"redis_unavailable"`: Redis not available
    ///   - `"invalid_code"`: Code invalid or expired
    ///   - `"user_not_found"`: No user for code
    ///   - `"activation_failed"`: DB update failed
    ///   - `"cleanup_failed"`: Code deletion failed
    pub static ref ACTIVATION_FAILURES: CounterVec = create_counter_vec(
        "activation_failures_total",
        "Activation failures by step and error type",
        &["step", "error_type"]
    ).expect("Failed to create ACTIVATION_FAILURES metric");

    /// **Performance Metric**: Activation flow duration for SLA monitoring
    ///
    /// Tracks activation processing latency to ensure responsive onboarding
    /// and identify performance bottlenecks in the activation pipeline.
    ///
    /// # Labels
    /// * `step`: Activation step for performance analysis
    ///
    /// # Performance Targets
    /// - **Complete Flow**: p95 < 200ms, p99 < 500ms (Redis + DB)
    /// - **Code Validation**: p95 < 50ms, p99 < 100ms (Redis get)
    /// - **User Lookup**: p95 < 50ms, p99 < 100ms (DB query)
    /// - **Account Activation**: p95 < 100ms, p99 < 200ms (DB update)
    pub static ref ACTIVATION_DURATION: HistogramVec = create_histogram_vec(
        "activation_duration_seconds",
        "Activation step duration for performance monitoring",
        &["step"],
        LATENCY_BUCKETS_MEDIUM  // Involves Redis and DB
    ).expect("Failed to create ACTIVATION_DURATION metric");

    /// **HTTP API Metric**: Activation endpoint requests by method and status
    ///
    /// Tracks HTTP-level activation API usage and success rates for complete
    /// end-to-end monitoring from HTTP request to business logic completion.
    ///
    /// # Labels
    /// * `method`: HTTP method (should always be "GET" for activation)
    /// * `status_code`: HTTP response status code
    ///   - `"200"`: OK - activation result page
    ///   - `"400"`: Bad Request - validation errors
    ///   - `"500"`: Internal Server Error - system failures
    pub static ref ACTIVATION_HTTP_REQUESTS: CounterVec = create_counter_vec(
        "activation_http_requests_total",
        "HTTP requests to activation endpoint by method and status",
        &["method", "status_code"]
    ).expect("Failed to create ACTIVATION_HTTP_REQUESTS metric");

    /// **HTTP Performance Metric**: Activation endpoint response duration
    ///
    /// Tracks HTTP request-response latency for the activation API endpoint
    /// to ensure responsive onboarding at the API level.
    ///
    /// # Performance Targets
    /// - **Success (200)**: p95 < 200ms, p99 < 500ms (includes DB update)
    /// - **Errors (4xx/5xx)**: p95 < 100ms, p99 < 200ms (fast failures)
    pub static ref ACTIVATION_HTTP_DURATION: HistogramVec = create_histogram_vec(
        "activation_http_duration_seconds",
        "HTTP request duration for activation endpoint",
        &["method", "status_code"],
        LATENCY_BUCKETS_MEDIUM  // HTTP includes full activation flow
    ).expect("Failed to create ACTIVATION_HTTP_DURATION metric");
}

// Thread-safe initialization guard
static ACTIVATION_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes all activation metrics safely for multi-threaded environments.
///
/// This function ensures metrics are initialized exactly once, regardless of how
/// many threads attempt to initialize them simultaneously. It's safe to call
/// this function multiple times.
pub fn init_activation_metrics() {
    // Thread-safe initialization with compare_exchange
    if ACTIVATION_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // Already initialized
    }

    // Force initialization of all metrics
    lazy_static::initialize(&ACTIVATION_OPERATIONS);
    lazy_static::initialize(&ACTIVATION_FAILURES);
    lazy_static::initialize(&ACTIVATION_DURATION);
    lazy_static::initialize(&ACTIVATION_HTTP_REQUESTS);
    lazy_static::initialize(&ACTIVATION_HTTP_DURATION);

    log_info!(
        "Metrics",
        "Activation metrics initialized (production-ready with HTTP tracking)",
        "activation_metrics_init"
    );
}

// =============================================================================
// CORE API (Fully standardized - consistent with other modules)
// =============================================================================

/// Records activation operation result with proper error handling.
///
/// # Arguments
///
/// * `step` - The activation flow step (use constants from `steps` module)
/// * `result` - The operation result (use constants from `results` module)
///
/// # Examples
///
/// ```
/// use crate::metricss::activation_metrics::{record_activation_operation, steps, results};
///
/// // Record a successful code validation
/// record_activation_operation(steps::CODE_VALIDATION, results::SUCCESS);
/// ```
pub fn record_activation_operation(step: &str, result: &str) {
    observe_counter_vec(
        &ACTIVATION_OPERATIONS,
        "activation_operations_total",
        &[step, result],
    );
}

/// Records detailed information about specific activation failures.
///
/// # Arguments
///
/// * `step` - The activation step where the failure occurred
/// * `error_type` - The specific type of error (use constants from `error_types` module)
///
/// # Examples
///
/// ```
/// use crate::metricss::activation_metrics::{record_activation_failure_detailed, steps, error_types};
///
/// // Record a code validation failure due to invalid code
/// record_activation_failure_detailed(steps::CODE_VALIDATION, error_types::INVALID_CODE);
/// ```
pub fn record_activation_failure_detailed(step: &str, error_type: &str) {
    observe_counter_vec(
        &ACTIVATION_FAILURES,
        "activation_failures_total",
        &[step, error_type],
    );
}

/// Creates a timer for measuring activation step duration.
///
/// # Arguments
///
/// * `step` - The activation step to measure (use constants from `steps` module)
///
/// # Returns
///
/// A histogram timer that will automatically record the duration when dropped.
///
/// # Examples
///
/// ```
/// use crate::metricss::activation_metrics::{time_activation_step, steps};
///
/// // Measure code validation duration
/// let timer = time_activation_step(steps::CODE_VALIDATION);
/// // Perform validation...
/// drop(timer); // Timer automatically records duration when dropped
/// ```
pub fn time_activation_step(step: &str) -> HistogramTimer {
    ACTIVATION_DURATION.with_label_values(&[step]).start_timer()
}

// =============================================================================
// HTTP API HELPERS
// =============================================================================

/// Records an HTTP request to the activation endpoint.
///
/// # Arguments
///
/// * `method` - The HTTP method (typically "GET" for activation)
/// * `status_code` - The HTTP status code returned
///
/// # Examples
///
/// ```
/// use crate::metricss::activation_metrics::{record_http_request, http};
///
/// // Record a successful activation request
/// record_http_request(http::GET, http::OK);
/// ```
pub fn record_http_request(method: &str, status_code: u16) {
    observe_counter_vec(
        &ACTIVATION_HTTP_REQUESTS,
        "activation_http_requests_total",
        &[method, &status_code.to_string()],
    );
}

/// Constants for HTTP methods and status codes for type safety.
pub mod http {
    /// HTTP GET method - used for activation links
    pub const GET: &str = "GET";

    // Standard HTTP status codes
    /// Success status code
    pub const OK: u16 = 200;
    /// Bad request (client error) status code
    pub const BAD_REQUEST: u16 = 400;
    /// Server error status code
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
}

// =============================================================================
// CONSTANTS (Type-safe activation step classification)
// =============================================================================

/// Activation step constants for type safety and consistency.
pub mod steps {
    /// Redis availability check step
    pub const REDIS_CHECK: &str = "redis_check";
    /// Activation code validation step
    pub const CODE_VALIDATION: &str = "code_validation";
    /// User lookup by email step
    pub const USER_LOOKUP: &str = "user_lookup";
    /// Database account activation step
    pub const ACCOUNT_ACTIVATION: &str = "account_activation";
    /// Activation code cleanup step
    pub const CODE_CLEANUP: &str = "code_cleanup";
    /// Complete end-to-end activation flow
    pub const COMPLETE_FLOW: &str = "complete_flow";
}

/// Result constants for consistent metric labeling.
pub mod results {
    /// Successful operation
    pub const SUCCESS: &str = "success";
    /// Failed operation
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization.
pub mod error_types {
    /// Redis server unavailable
    pub const REDIS_UNAVAILABLE: &str = "redis_unavailable";
    /// Activation code invalid or expired
    pub const INVALID_CODE: &str = "invalid_code";
    /// User not found for activation
    pub const USER_NOT_FOUND: &str = "user_not_found";
    /// Database update for activation failed
    pub const ACTIVATION_FAILED: &str = "activation_failed";
    /// Redis cleanup of used activation code failed
    pub const CLEANUP_FAILED: &str = "cleanup_failed";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records a successful activation step.
///
/// # Arguments
///
/// * `step` - The activation step that succeeded
pub fn record_step_success(step: &str) {
    record_activation_operation(step, results::SUCCESS);
}

/// Records a failed activation step.
///
/// # Arguments
///
/// * `step` - The activation step that failed
pub fn record_step_failure(step: &str) {
    record_activation_operation(step, results::FAILURE);
}

/// Records both general step failure and specific error details.
///
/// # Arguments
///
/// * `step` - The activation step that failed
/// * `error_type` - The specific error type that occurred
pub fn record_step_failure_with_type(step: &str, error_type: &str) {
    record_activation_failure_detailed(step, error_type);
    record_step_failure(step); // Also record in general operations
}

// Complete flow helpers

/// Records a successful complete activation flow.
pub fn record_activation_success() {
    record_step_success(steps::COMPLETE_FLOW);
}

/// Records a failed complete activation flow.
pub fn record_activation_failure() {
    record_step_failure(steps::COMPLETE_FLOW);
}

/// Creates a timer for measuring the complete activation flow duration.
///
/// # Returns
///
/// A histogram timer that will automatically record the duration when dropped.
pub fn time_complete_activation_flow() -> HistogramTimer {
    time_activation_step(steps::COMPLETE_FLOW)
}

// Step-specific helpers (matching activation_logic.rs)

/// Records a successful Redis check.
pub fn record_redis_check_success() {
    record_step_success(steps::REDIS_CHECK);
}

/// Records a failed Redis check with error details.
pub fn record_redis_check_failure(error_type: &str) {
    record_step_failure_with_type(steps::REDIS_CHECK, error_type);
}

/// Records a successful activation code validation.
pub fn record_code_validation_success() {
    record_step_success(steps::CODE_VALIDATION);
}

/// Records a failed activation code validation with error details.
pub fn record_code_validation_failure(error_type: &str) {
    record_step_failure_with_type(steps::CODE_VALIDATION, error_type);
}

/// Records a successful user lookup.
pub fn record_user_lookup_success() {
    record_step_success(steps::USER_LOOKUP);
}

/// Records a failed user lookup with error details.
pub fn record_user_lookup_failure(error_type: &str) {
    record_step_failure_with_type(steps::USER_LOOKUP, error_type);
}

/// Records a successful account activation in the database.
pub fn record_account_activation_success() {
    record_step_success(steps::ACCOUNT_ACTIVATION);
}

/// Records a failed account activation with error details.
pub fn record_account_activation_failure(error_type: &str) {
    record_step_failure_with_type(steps::ACCOUNT_ACTIVATION, error_type);
}

/// Records a successful activation code cleanup.
pub fn record_code_cleanup_success() {
    record_step_success(steps::CODE_CLEANUP);
}

/// Records a failed activation code cleanup with error details.
pub fn record_code_cleanup_failure(error_type: &str) {
    record_step_failure_with_type(steps::CODE_CLEANUP, error_type);
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activation_metrics_initialization() {
        init_activation_metrics();

        // Test that all metrics are properly initialized
        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
                .get(),
            0.0
        );
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::CODE_VALIDATION, error_types::INVALID_CODE])
                .get(),
            0.0
        );
        assert_eq!(
            ACTIVATION_DURATION
                .with_label_values(&[steps::COMPLETE_FLOW])
                .get_sample_count(),
            0
        );
        assert_eq!(
            ACTIVATION_HTTP_REQUESTS
                .with_label_values(&[http::GET, "200"])
                .get(),
            0.0
        );
        assert_eq!(
            ACTIVATION_HTTP_DURATION
                .with_label_values(&[http::GET, "200"])
                .get_sample_count(),
            0
        );
    }

    #[test]
    fn test_complete_activation_flow() {
        init_activation_metrics();

        let before_count = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let before_duration = ACTIVATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        // Test complete flow success
        let timer = time_complete_activation_flow();
        record_activation_success();
        drop(timer);

        let after_count = ACTIVATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let after_duration = ACTIVATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();

        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_step_specific_helpers() {
        init_activation_metrics();

        // Test all step helpers
        record_redis_check_success();
        record_redis_check_failure(error_types::REDIS_UNAVAILABLE);

        record_code_validation_success();
        record_code_validation_failure(error_types::INVALID_CODE);

        record_user_lookup_success();
        record_user_lookup_failure(error_types::USER_NOT_FOUND);

        record_account_activation_success();
        record_account_activation_failure(error_types::ACTIVATION_FAILED);

        record_code_cleanup_success();
        record_code_cleanup_failure(error_types::CLEANUP_FAILED);

        // Verify operations were recorded
        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::CODE_VALIDATION, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::CODE_VALIDATION, results::FAILURE])
                .get(),
            1.0
        );

        // Verify detailed failures were recorded
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
                .get(),
            1.0
        );
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::CODE_VALIDATION, error_types::INVALID_CODE])
                .get(),
            1.0
        );
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
                .get(),
            1.0
        );
    }

    #[test]
    fn test_http_metrics_integration() {
        init_activation_metrics();

        // Test HTTP request tracking
        let initial_success = ACTIVATION_HTTP_REQUESTS
            .with_label_values(&[http::GET, "200"])
            .get();
        let initial_error = ACTIVATION_HTTP_REQUESTS
            .with_label_values(&[http::GET, "400"])
            .get();

        // Record requests
        record_http_request(http::GET, http::OK);
        record_http_request(http::GET, http::BAD_REQUEST);

        // Verify counts
        let final_success = ACTIVATION_HTTP_REQUESTS
            .with_label_values(&[http::GET, "200"])
            .get();
        let final_error = ACTIVATION_HTTP_REQUESTS
            .with_label_values(&[http::GET, "400"])
            .get();

        assert_eq!(final_success, initial_success + 1.0);
        assert_eq!(final_error, initial_error + 1.0);
    }

    #[test]
    fn test_production_activation_patterns() {
        init_activation_metrics();

        // Simulate realistic production patterns

        // 8 successful activations
        for _ in 0..8 {
            record_redis_check_success();
            record_code_validation_success();
            record_user_lookup_success();
            record_account_activation_success();
            record_code_cleanup_success();
            record_activation_success();
        }

        // Some failures at different steps
        record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
        record_code_validation_failure(error_types::INVALID_CODE);
        record_user_lookup_failure(error_types::USER_NOT_FOUND);
        record_account_activation_failure(error_types::ACTIVATION_FAILED);
        record_code_cleanup_failure(error_types::CLEANUP_FAILED);

        // Verify realistic metric patterns
        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
                .get(),
            8.0
        );
        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE])
                .get(),
            0.0
        ); // No complete failures in sim

        // Specific failure types
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
                .get(),
            1.0
        );
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::CODE_VALIDATION, error_types::INVALID_CODE])
                .get(),
            1.0
        );
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
                .get(),
            1.0
        );

        // Successful steps
        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::ACCOUNT_ACTIVATION, results::SUCCESS])
                .get(),
            8.0
        );
    }

    #[test]
    fn test_type_safety_constants() {
        init_activation_metrics();

        // Verify all constants are valid and type-safe
        assert_eq!(steps::REDIS_CHECK, "redis_check");
        assert_eq!(steps::CODE_VALIDATION, "code_validation");
        assert_eq!(steps::USER_LOOKUP, "user_lookup");
        assert_eq!(steps::ACCOUNT_ACTIVATION, "account_activation");
        assert_eq!(steps::CODE_CLEANUP, "code_cleanup");
        assert_eq!(steps::COMPLETE_FLOW, "complete_flow");

        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");

        assert_eq!(error_types::REDIS_UNAVAILABLE, "redis_unavailable");
        assert_eq!(error_types::INVALID_CODE, "invalid_code");
        assert_eq!(error_types::USER_NOT_FOUND, "user_not_found");
        assert_eq!(error_types::ACTIVATION_FAILED, "activation_failed");
        assert_eq!(error_types::CLEANUP_FAILED, "cleanup_failed");

        // Use constants in actual operations
        record_activation_operation(steps::CODE_CLEANUP, results::SUCCESS);
        record_activation_failure_detailed(steps::CODE_VALIDATION, error_types::INVALID_CODE);

        assert_eq!(
            ACTIVATION_OPERATIONS
                .with_label_values(&[steps::CODE_CLEANUP, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            ACTIVATION_FAILURES
                .with_label_values(&[steps::CODE_VALIDATION, error_types::INVALID_CODE])
                .get(),
            1.0
        );
    }
}
