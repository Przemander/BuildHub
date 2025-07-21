//! # Logout Metrics - Production-Grade Logout Flow Monitoring
//!
//! Essential logout flow monitoring for complete authentication session termination observability.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **End-to-End Flow Tracking**: Monitor complete logout journey
//! - **Step-by-Step Observability**: Track each logout phase separately
//! - **Business Intelligence**: Logout success rates and failure analysis
//! - **Performance Monitoring**: Logout flow latency and bottlenecks
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (5 Essential)
//! - `logout_operations_total`: Logout operations by step and result
//! - `logout_failures_total`: Logout failures by specific step and error type
//! - `logout_duration_seconds`: Logout flow duration for performance monitoring
//! - `logout_http_requests_total`: HTTP requests by method and status code
//! - `logout_http_duration_seconds`: HTTP request duration for API performance
//!
//! ## Production Alerts
//! - High logout failure rates (authentication issues)
//! - Logout flow bottlenecks (user experience)
//! - Infrastructure failures during logout (system health)
//! - HTTP API health and performance monitoring

use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec, HistogramTimer};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::log_info;

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_FAST, // Logout is fast (JWT check + Redis set)
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Logout operations by step and result
    ///
    /// Essential for monitoring logout flow completion and identifying
    /// bottlenecks in the session termination process.
    ///
    /// # Labels
    /// * `step`: Logout flow step
    ///   - `"redis_check"`: Redis client availability check
    ///   - `"token_validation"`: Optional token validation
    ///   - `"token_revocation"`: Token addition to blocklist
    ///   - `"complete_flow"`: End-to-end logout process
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Step completed successfully
    ///   - `"failure"`: Step failed for any reason
    ///
    /// # Business Impact
    /// - **User Security**: Failed revocations may allow continued access
    /// - **Session Management**: Logout success rate affects user trust
    /// - **Compliance**: Proper revocation needed for audit trails
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High logout failure rate
    /// - alert: HighLogoutFailureRate
    ///   expr: rate(logout_operations_total{step="complete_flow", result="failure"}[5m]) / rate(logout_operations_total{step="complete_flow"}[5m]) > 0.05
    ///   severity: critical
    ///   annotations:
    ///     summary: "Logout failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: Revocation failures
    /// - alert: TokenRevocationFailures
    ///   expr: rate(logout_operations_total{step="token_revocation", result="failure"}[5m]) > 1
    ///   severity: warning
    /// ```
    pub static ref LOGOUT_OPERATIONS: CounterVec = create_counter_vec(
        "logout_operations_total",
        "Logout operations by step and result",
        &["step", "result"]
    ).expect("Failed to create LOGOUT_OPERATIONS metric");

    /// **Failure Analysis Metric**: Logout failures by specific step and error type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and
    /// security compliance monitoring.
    ///
    /// # Labels
    /// * `step`: Logout step that failed
    /// * `error_type`: Specific type of failure
    ///   - `"redis_unavailable"`: Redis not available for revocation
    ///   - `"invalid_token"`: Token validation failed
    ///   - `"revocation_failed"`: Failed to add token to blocklist
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Redis unavailable during logout
    /// - alert: LogoutRedisUnavailable
    ///   expr: rate(logout_failures_total{error_type="redis_unavailable"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: High invalid token rate
    /// - alert: HighInvalidLogoutTokens
    ///   expr: rate(logout_failures_total{step="token_validation", error_type="invalid_token"}[5m]) > 5
    ///   severity: warning
    /// ```
    pub static ref LOGOUT_FAILURES: CounterVec = create_counter_vec(
        "logout_failures_total",
        "Logout failures by step and error type",
        &["step", "error_type"]
    ).expect("Failed to create LOGOUT_FAILURES metric");

    /// **Performance Metric**: Logout flow duration for SLA monitoring
    ///
    /// Tracks logout processing latency to ensure responsive session termination
    /// and identify performance bottlenecks in the logout pipeline.
    ///
    /// # Labels
    /// * `step`: Logout step for performance analysis
    ///
    /// # Performance Targets
    /// - **Complete Flow**: p95 < 50ms, p99 < 100ms (Redis set operation)
    /// - **Token Validation**: p95 < 5ms, p99 < 10ms (JWT check)
    /// - **Token Revocation**: p95 < 10ms, p99 < 25ms (Redis set)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow logout flow
    /// - alert: SlowLogoutFlow
    ///   expr: histogram_quantile(0.95, rate(logout_duration_seconds_bucket{step="complete_flow"}[5m])) > 0.05
    ///   severity: warning
    ///
    /// # Critical: Very slow logout
    /// - alert: VerySlowLogoutFlow
    ///   expr: histogram_quantile(0.95, rate(logout_duration_seconds_bucket{step="complete_flow"}[5m])) > 0.1
    ///   severity: critical
    /// ```
    pub static ref LOGOUT_DURATION: HistogramVec = create_histogram_vec(
        "logout_duration_seconds",
        "Logout step duration for performance monitoring",
        &["step"],
        LATENCY_BUCKETS_FAST  // Fast token operations
    ).expect("Failed to create LOGOUT_DURATION metric");

    /// **HTTP API Metric**: Logout endpoint requests by method and status
    ///
    /// Tracks HTTP-level logout API usage and success rates for complete
    /// end-to-end monitoring from HTTP request to business logic completion.
    ///
    /// # Labels
    /// * `method`: HTTP method (should always be "POST" for logout)
    /// * `status_code`: HTTP response status code
    ///   - `"200"`: OK - successful logout
    ///   - `"400"`: Bad Request - validation errors
    ///   - `"401"`: Unauthorized - invalid token
    ///   - `"500"`: Internal Server Error - system failures
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High HTTP error rate
    /// - alert: HighLogoutHTTPErrorRate
    ///   expr: rate(logout_http_requests_total{status_code=~"5.."}[5m]) / rate(logout_http_requests_total[5m]) > 0.01
    ///   severity: critical
    ///
    /// # Warning: High unauthorized rate
    /// - alert: HighLogoutUnauthorizedRate
    ///   expr: rate(logout_http_requests_total{status_code="401"}[5m]) / rate(logout_http_requests_total[5m]) > 0.1
    ///   severity: warning
    /// ```
    pub static ref LOGOUT_HTTP_REQUESTS: CounterVec = create_counter_vec(
        "logout_http_requests_total",
        "HTTP requests to logout endpoint by method and status",
        &["method", "status_code"]
    ).expect("Failed to create LOGOUT_HTTP_REQUESTS metric");

    /// **HTTP Performance Metric**: Logout endpoint response duration
    ///
    /// Tracks HTTP request-response latency for the logout API endpoint
    /// to ensure responsive session termination at the API level.
    ///
    /// # Performance Targets
    /// - **Success (200)**: p95 < 50ms, p99 < 100ms (includes Redis set)
    /// - **Auth Errors (401)**: p95 < 20ms, p99 < 50ms (fast validation failures)
    /// - **Server Errors (500)**: p95 < 20ms, p99 < 50ms (fast failure detection)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow logout API
    /// - alert: SlowLogoutAPI
    ///   expr: histogram_quantile(0.95, rate(logout_http_duration_seconds_bucket{status_code="200"}[5m])) > 0.05
    ///   severity: warning
    ///
    /// # Critical: Very slow logout API
    /// - alert: VerySlowLogoutAPI
    ///   expr: histogram_quantile(0.95, rate(logout_http_duration_seconds_bucket{status_code="200"}[5m])) > 0.1
    ///   severity: critical
    /// ```
    pub static ref LOGOUT_HTTP_DURATION: HistogramVec = create_histogram_vec(
        "logout_http_duration_seconds",
        "HTTP request duration for logout endpoint",
        &["method", "status_code"],
        LATENCY_BUCKETS_FAST  // Fast operations
    ).expect("Failed to create LOGOUT_HTTP_DURATION metric");
}

static LOGOUT_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_logout_metrics() {
    if LOGOUT_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&LOGOUT_OPERATIONS);
    lazy_static::initialize(&LOGOUT_FAILURES);
    lazy_static::initialize(&LOGOUT_DURATION);
    lazy_static::initialize(&LOGOUT_HTTP_REQUESTS);
    lazy_static::initialize(&LOGOUT_HTTP_DURATION);

    log_info!("Metrics", "Logout metrics initialized (production-ready with HTTP tracking)", "logout_metrics_init");
}

// =============================================================================
// CORE API (Fully standardized - consistent with other modules)
// =============================================================================

/// Records logout operation result (standardized approach)
pub fn record_logout_operation(step: &str, result: &str) {
    observe_counter_vec(
        &LOGOUT_OPERATIONS,
        "logout_operations_total",
        &[step, result]
    );
}

/// Records specific logout failure (standardized approach)
pub fn record_logout_failure_detailed(step: &str, error_type: &str) {
    observe_counter_vec(
        &LOGOUT_FAILURES,
        "logout_failures_total",
        &[step, error_type]
    );
}

/// Times logout step with standard prometheus timer
pub fn time_logout_step(step: &str) -> HistogramTimer {
    LOGOUT_DURATION
        .with_label_values(&[step])
        .start_timer()
}

// =============================================================================
// HTTP API HELPERS
// =============================================================================

/// Records HTTP logout request with method and status code
pub fn record_http_request(method: &str, status_code: u16) {
    observe_counter_vec(
        &LOGOUT_HTTP_REQUESTS,
        "logout_http_requests_total",
        &[method, &status_code.to_string()]
    );
}

/// Constants for HTTP methods and status codes
pub mod http {
    pub const POST: &str = "POST";
    
    // Status codes
    pub const OK: u16 = 200;
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHORIZED: u16 = 401;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
}

// =============================================================================
// CONSTANTS (Type-safe logout step classification)
// =============================================================================

/// Logout step constants for type safety
pub mod steps {
    pub const REDIS_CHECK: &str = "redis_check";
    pub const TOKEN_VALIDATION: &str = "token_validation";
    pub const TOKEN_REVOCATION: &str = "token_revocation";
    pub const COMPLETE_FLOW: &str = "complete_flow";
}

/// Result constants for consistent labeling
pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization
pub mod error_types {
    pub const REDIS_UNAVAILABLE: &str = "redis_unavailable";
    pub const INVALID_TOKEN: &str = "invalid_token";
    pub const REVOCATION_FAILED: &str = "revocation_failed";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful logout step
pub fn record_step_success(step: &str) {
    record_logout_operation(step, results::SUCCESS);
}

/// Records failed logout step
pub fn record_step_failure(step: &str) {
    record_logout_operation(step, results::FAILURE);
}

/// Records logout step failure with specific error type
pub fn record_step_failure_with_type(step: &str, error_type: &str) {
    record_logout_failure_detailed(step, error_type);
    record_step_failure(step); // Also record in general operations
}

// Complete flow helpers
pub fn record_logout_success() {
    record_step_success(steps::COMPLETE_FLOW);
}

pub fn record_logout_failure() {
    record_step_failure(steps::COMPLETE_FLOW);
}

pub fn time_complete_logout_flow() -> HistogramTimer {
    time_logout_step(steps::COMPLETE_FLOW)
}

// Step-specific helpers (matching logout_logic.rs)
pub fn record_redis_check_success() {
    record_step_success(steps::REDIS_CHECK);
}

pub fn record_redis_check_failure(error_type: &str) {
    record_step_failure_with_type(steps::REDIS_CHECK, error_type);
}

pub fn record_token_validation_success() {
    record_step_success(steps::TOKEN_VALIDATION);
}

pub fn record_token_validation_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_VALIDATION, error_type);
}

pub fn record_token_revocation_success() {
    record_step_success(steps::TOKEN_REVOCATION);
}

pub fn record_token_revocation_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_REVOCATION, error_type);
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logout_metrics_initialization() {
        init_logout_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 0.0);
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED]).get(), 0.0);
        assert_eq!(LOGOUT_DURATION.with_label_values(&[steps::COMPLETE_FLOW]).get_sample_count(), 0);
        assert_eq!(LOGOUT_HTTP_REQUESTS.with_label_values(&[http::POST, "200"]).get(), 0.0);
        assert_eq!(LOGOUT_HTTP_DURATION.with_label_values(&[http::POST, "200"]).get_sample_count(), 0);
    }

    #[test]
    fn test_complete_logout_flow() {
        init_logout_metrics();
        
        let before_count = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let before_duration = LOGOUT_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        // Test complete flow success
        let timer = time_complete_logout_flow();
        record_logout_success();
        drop(timer);
        
        let after_count = LOGOUT_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let after_duration = LOGOUT_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_step_specific_helpers() {
        init_logout_metrics();
        
        // Test all step helpers
        record_redis_check_success();
        record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
        
        record_token_validation_success();
        record_token_validation_failure(error_types::INVALID_TOKEN);
        
        record_token_revocation_success();
        record_token_revocation_failure(error_types::REVOCATION_FAILED);
        
        // Verify operations were recorded
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::REDIS_CHECK, results::SUCCESS]).get(), 1.0);
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::REDIS_CHECK, results::FAILURE]).get(), 1.0);
        
        // Verify detailed failures were recorded
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE]).get(), 1.0);
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN]).get(), 1.0);
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED]).get(), 1.0);
    }

    #[test]
    fn test_http_metrics_integration() {
        init_logout_metrics();
        
        // Test HTTP request tracking
        let initial_success = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let initial_error = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        
        // Record requests
        record_http_request(http::POST, http::OK);
        record_http_request(http::POST, http::BAD_REQUEST);
        
        // Verify counts
        let final_success = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let final_error = LOGOUT_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        
        assert_eq!(final_success, initial_success + 1.0);
        assert_eq!(final_error, initial_error + 1.0);
    }

    #[test]
    fn test_production_logout_patterns() {
        init_logout_metrics();
        
        // Simulate realistic production patterns
        
        // 10 successful logouts
        for _ in 0..10 {
            record_redis_check_success();
            record_token_validation_success();
            record_token_revocation_success();
            record_logout_success();
        }
        
        // Some failures at different steps
        record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
        record_token_validation_failure(error_types::INVALID_TOKEN);
        record_token_revocation_failure(error_types::REVOCATION_FAILED);
        
        // Verify realistic metric patterns
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 10.0);
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE]).get(), 0.0); // No complete failures in sim
        
        // Specific failure types
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE]).get(), 1.0);
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN]).get(), 1.0);
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED]).get(), 1.0);
        
        // Successful steps
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::TOKEN_REVOCATION, results::SUCCESS]).get(), 10.0);
    }

    #[test]
    fn test_type_safety_constants() {
        init_logout_metrics();
        
        // Verify all constants are valid and type-safe
        assert_eq!(steps::REDIS_CHECK, "redis_check");
        assert_eq!(steps::TOKEN_VALIDATION, "token_validation");
        assert_eq!(steps::TOKEN_REVOCATION, "token_revocation");
        assert_eq!(steps::COMPLETE_FLOW, "complete_flow");
        
        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");
        
        assert_eq!(error_types::REDIS_UNAVAILABLE, "redis_unavailable");
        assert_eq!(error_types::INVALID_TOKEN, "invalid_token");
        assert_eq!(error_types::REVOCATION_FAILED, "revocation_failed");
        
        // Use constants in actual operations
        record_logout_operation(steps::TOKEN_REVOCATION, results::SUCCESS);
        record_logout_failure_detailed(steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE);
        
        assert_eq!(LOGOUT_OPERATIONS.with_label_values(&[steps::TOKEN_REVOCATION, results::SUCCESS]).get(), 1.0);
        assert_eq!(LOGOUT_FAILURES.with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE]).get(), 1.0);
    }
}