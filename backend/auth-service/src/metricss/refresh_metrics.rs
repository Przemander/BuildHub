//! # Refresh Metrics - Production-Grade Token Refresh Flow Monitoring
//!
//! Essential token refresh flow monitoring for complete authentication session observability.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **End-to-End Flow Tracking**: Monitor complete token refresh journey
//! - **Step-by-Step Observability**: Track each refresh phase separately
//! - **Business Intelligence**: Refresh success rates and failure analysis
//! - **Performance Monitoring**: Refresh flow latency and bottlenecks
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (3 Essential)
//! - `refresh_operations_total`: Refresh operations by step and result
//! - `refresh_failures_total`: Refresh failures by specific step and error type
//! - `refresh_duration_seconds`: Refresh flow duration for performance monitoring
//!
//! ## Production Alerts
//! - High refresh failure rates (authentication issues)
//! - Refresh flow bottlenecks (user experience)
//! - Infrastructure failures during refresh (system health)
//! - Unusual failure patterns (security monitoring)

use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec, HistogramTimer};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::log_info;

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_FAST, // Token operations are fast (JWT + Redis)
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Refresh operations by step and result
    ///
    /// Essential for monitoring token refresh flow completion and identifying
    /// bottlenecks in the authentication session management process.
    ///
    /// # Labels
    /// * `step`: Refresh flow step
    ///   - `"token_validation"`: JWT validation and revocation check
    ///   - `"token_type_check"`: Token type enforcement (refresh only)
    ///   - `"token_revocation"`: Old refresh token revocation
    ///   - `"access_token_generation"`: New access token creation
    ///   - `"refresh_token_generation"`: New refresh token creation
    ///   - `"complete_flow"`: End-to-end refresh process
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Step completed successfully
    ///   - `"failure"`: Step failed for any reason
    ///
    /// # Business Impact
    /// - **User Experience**: Failed steps cause session interruptions
    /// - **Security Compliance**: Proper revocation prevents replay attacks
    /// - **Session Management**: Refresh success rate affects user retention
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High refresh failure rate
    /// - alert: HighRefreshFailureRate
    ///   expr: rate(refresh_operations_total{step="complete_flow", result="failure"}[5m]) / rate(refresh_operations_total{step="complete_flow"}[5m]) > 0.05
    ///   severity: critical
    ///   annotations:
    ///     summary: "Token refresh failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: Revocation failures
    /// - alert: TokenRevocationFailures
    ///   expr: rate(refresh_operations_total{step="token_revocation", result="failure"}[5m]) > 1
    ///   severity: warning
    /// ```
    pub static ref REFRESH_OPERATIONS: CounterVec = create_counter_vec(
        "refresh_operations_total",
        "Refresh operations by step and result",
        &["step", "result"]
    ).expect("Failed to create REFRESH_OPERATIONS metric");

    /// **Failure Analysis Metric**: Refresh failures by specific step and error type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and
    /// security compliance monitoring.
    ///
    /// # Labels
    /// * `step`: Refresh step that failed
    /// * `error_type`: Specific type of failure
    ///   - Token Validation: `"invalid_signature"`, `"token_expired"`, `"token_revoked"`
    ///   - Token Type Check: `"wrong_token_type"`
    ///   - Token Revocation: `"revocation_failed"`
    ///   - Token Generation: `"generation_error"`
    ///   - General: `"redis_unavailable"`
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Redis unavailable during refresh
    /// - alert: RefreshRedisUnavailable
    ///   expr: rate(refresh_failures_total{error_type="redis_unavailable"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: High expired token rate
    /// - alert: HighExpiredRefreshTokens
    ///   expr: rate(refresh_failures_total{step="token_validation", error_type="token_expired"}[5m]) > 5
    ///   severity: warning
    /// ```
    pub static ref REFRESH_FAILURES: CounterVec = create_counter_vec(
        "refresh_failures_total",
        "Refresh failures by step and error type",
        &["step", "error_type"]
    ).expect("Failed to create REFRESH_FAILURES metric");

    /// **Performance Metric**: Refresh flow duration for SLA monitoring
    ///
    /// Tracks token refresh processing latency to ensure responsive authentication
    /// and identify performance bottlenecks in the refresh pipeline.
    ///
    /// # Labels
    /// * `step`: Refresh step for performance analysis
    ///
    /// # Performance Targets
    /// - **Complete Flow**: p95 < 100ms, p99 < 250ms (full refresh process)
    /// - **Token Validation**: p95 < 5ms, p99 < 10ms (JWT + Redis check)
    /// - **Token Generation**: p95 < 5ms, p99 < 10ms (JWT signing)
    /// - **Token Revocation**: p95 < 10ms, p99 < 25ms (Redis set)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow refresh flow
    /// - alert: SlowRefreshFlow
    ///   expr: histogram_quantile(0.95, rate(refresh_duration_seconds_bucket{step="complete_flow"}[5m])) > 0.1
    ///   severity: warning
    ///
    /// # Critical: Very slow refresh
    /// - alert: VerySlowRefreshFlow
    ///   expr: histogram_quantile(0.95, rate(refresh_duration_seconds_bucket{step="complete_flow"}[5m])) > 0.25
    ///   severity: critical
    /// ```
    pub static ref REFRESH_DURATION: HistogramVec = create_histogram_vec(
        "refresh_duration_seconds",
        "Refresh step duration for performance monitoring",
        &["step"],
        LATENCY_BUCKETS_FAST  // Fast token operations
    ).expect("Failed to create REFRESH_DURATION metric");
}

static REFRESH_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_refresh_metrics() {
    if REFRESH_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&REFRESH_OPERATIONS);
    lazy_static::initialize(&REFRESH_FAILURES);
    lazy_static::initialize(&REFRESH_DURATION);

    log_info!("Metrics", "Refresh metrics initialized (production-ready with full standardization)", "refresh_metrics_init");
}

// =============================================================================
// CORE API (Fully standardized - consistent with validation/register pattern)
// =============================================================================

/// Records refresh operation result (standardized approach)
pub fn record_refresh_operation(step: &str, result: &str) {
    observe_counter_vec(
        &REFRESH_OPERATIONS,
        "refresh_operations_total",
        &[step, result]
    );
}

/// Records specific refresh failure (standardized approach)
pub fn record_refresh_failure_detailed(step: &str, error_type: &str) {
    observe_counter_vec(
        &REFRESH_FAILURES,
        "refresh_failures_total",
        &[step, error_type]
    );
}

/// Times refresh step with standard prometheus timer
pub fn time_refresh_step(step: &str) -> HistogramTimer {
    REFRESH_DURATION
        .with_label_values(&[step])
        .start_timer()
}

// =============================================================================
// CONSTANTS (Type-safe refresh step classification)
// =============================================================================

/// Refresh step constants for type safety
pub mod steps {
    pub const TOKEN_VALIDATION: &str = "token_validation";
    pub const TOKEN_TYPE_CHECK: &str = "token_type_check";
    pub const TOKEN_REVOCATION: &str = "token_revocation";
    pub const ACCESS_TOKEN_GENERATION: &str = "access_token_generation";
    pub const REFRESH_TOKEN_GENERATION: &str = "refresh_token_generation";
    pub const COMPLETE_FLOW: &str = "complete_flow";
}

/// Result constants for consistent labeling
pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization
pub mod error_types {
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    pub const TOKEN_EXPIRED: &str = "token_expired";
    pub const TOKEN_REVOKED: &str = "token_revoked";
    pub const WRONG_TOKEN_TYPE: &str = "wrong_token_type";
    pub const REVOCATION_FAILED: &str = "revocation_failed";
    pub const GENERATION_ERROR: &str = "generation_error";
    pub const REDIS_UNAVAILABLE: &str = "redis_unavailable";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful refresh step
pub fn record_step_success(step: &str) {
    record_refresh_operation(step, results::SUCCESS);
}

/// Records failed refresh step
pub fn record_step_failure(step: &str) {
    record_refresh_operation(step, results::FAILURE);
}

/// Records refresh step failure with specific error type
pub fn record_step_failure_with_type(step: &str, error_type: &str) {
    record_refresh_failure_detailed(step, error_type);
    record_step_failure(step); // Also record in general operations
}

// Complete flow helpers
pub fn record_refresh_success() {
    record_step_success(steps::COMPLETE_FLOW);
}

pub fn record_refresh_failure() {
    record_step_failure(steps::COMPLETE_FLOW);
}

pub fn time_complete_refresh_flow() -> HistogramTimer {
    time_refresh_step(steps::COMPLETE_FLOW)
}

// Step-specific helpers (matching refresh_logic.rs)
pub fn record_token_validation_success() {
    record_step_success(steps::TOKEN_VALIDATION);
}

pub fn record_token_validation_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_VALIDATION, error_type);
}

pub fn record_token_type_check_success() {
    record_step_success(steps::TOKEN_TYPE_CHECK);
}

pub fn record_token_type_check_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_TYPE_CHECK, error_type);
}

pub fn record_token_revocation_success() {
    record_step_success(steps::TOKEN_REVOCATION);
}

pub fn record_token_revocation_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_REVOCATION, error_type);
}

pub fn record_access_token_generation_success() {
    record_step_success(steps::ACCESS_TOKEN_GENERATION);
}

pub fn record_access_token_generation_failure(error_type: &str) {
    record_step_failure_with_type(steps::ACCESS_TOKEN_GENERATION, error_type);
}

pub fn record_refresh_token_generation_success() {
    record_step_success(steps::REFRESH_TOKEN_GENERATION);
}

pub fn record_refresh_token_generation_failure(error_type: &str) {
    record_step_failure_with_type(steps::REFRESH_TOKEN_GENERATION, error_type);
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_metrics_initialization() {
        init_refresh_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(REFRESH_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 0.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_SIGNATURE]).get(), 0.0);
        assert_eq!(REFRESH_DURATION.with_label_values(&[steps::COMPLETE_FLOW]).get_sample_count(), 0);
    }

    #[test]
    fn test_complete_refresh_flow() {
        init_refresh_metrics();
        
        let before_count = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let before_duration = REFRESH_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        // Test complete flow success
        let timer = time_complete_refresh_flow();
        record_refresh_success();
        drop(timer);
        
        let after_count = REFRESH_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let after_duration = REFRESH_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_step_specific_helpers() {
        init_refresh_metrics();
        
        // Test all step helpers
        record_token_validation_success();
        record_token_validation_failure(error_types::TOKEN_EXPIRED);
        
        record_token_type_check_success();
        record_token_type_check_failure(error_types::WRONG_TOKEN_TYPE);
        
        record_token_revocation_success();
        record_token_revocation_failure(error_types::REVOCATION_FAILED);
        
        record_access_token_generation_success();
        record_access_token_generation_failure(error_types::GENERATION_ERROR);
        
        record_refresh_token_generation_success();
        record_refresh_token_generation_failure(error_types::GENERATION_ERROR);
        
        // Verify operations were recorded
        assert_eq!(REFRESH_OPERATIONS.with_label_values(&[steps::TOKEN_VALIDATION, results::SUCCESS]).get(), 1.0);
        assert_eq!(REFRESH_OPERATIONS.with_label_values(&[steps::TOKEN_VALIDATION, results::FAILURE]).get(), 1.0);
        
        // Verify detailed failures were recorded
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_VALIDATION, error_types::TOKEN_EXPIRED]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_TYPE_CHECK, error_types::WRONG_TOKEN_TYPE]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::ACCESS_TOKEN_GENERATION, error_types::GENERATION_ERROR]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::REFRESH_TOKEN_GENERATION, error_types::GENERATION_ERROR]).get(), 1.0);
    }

    #[test]
    fn test_production_refresh_patterns() {
        init_refresh_metrics();
        
        // Simulate realistic production patterns
        
        // 5 successful refreshes
        for _ in 0..5 {
            record_token_validation_success();
            record_token_type_check_success();
            record_access_token_generation_success();
            record_token_revocation_success();
            record_refresh_token_generation_success();
            record_refresh_success();
        }
        
        // Some failures at different steps
        record_token_validation_failure(error_types::INVALID_SIGNATURE);
        record_token_type_check_failure(error_types::WRONG_TOKEN_TYPE);
        record_token_revocation_failure(error_types::REVOCATION_FAILED);
        record_access_token_generation_failure(error_types::GENERATION_ERROR);
        record_refresh_token_generation_failure(error_types::GENERATION_ERROR);
        
        // Verify realistic metric patterns
        assert_eq!(REFRESH_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 5.0);
        assert_eq!(REFRESH_OPERATIONS.with_label_values(&[steps::TOKEN_VALIDATION, results::FAILURE]).get(), 1.0);
        
        // Specific failure types
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_SIGNATURE]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_TYPE_CHECK, error_types::WRONG_TOKEN_TYPE]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED]).get(), 1.0);
    }

    #[test]
    fn test_type_safety_constants() {
        init_refresh_metrics();
        
        // Verify all constants are valid and type-safe
        assert_eq!(steps::TOKEN_VALIDATION, "token_validation");
        assert_eq!(steps::TOKEN_TYPE_CHECK, "token_type_check");
        assert_eq!(steps::TOKEN_REVOCATION, "token_revocation");
        assert_eq!(steps::ACCESS_TOKEN_GENERATION, "access_token_generation");
        assert_eq!(steps::REFRESH_TOKEN_GENERATION, "refresh_token_generation");
        assert_eq!(steps::COMPLETE_FLOW, "complete_flow");
        
        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");
        
        assert_eq!(error_types::INVALID_SIGNATURE, "invalid_signature");
        assert_eq!(error_types::TOKEN_EXPIRED, "token_expired");
        assert_eq!(error_types::TOKEN_REVOKED, "token_revoked");
        assert_eq!(error_types::WRONG_TOKEN_TYPE, "wrong_token_type");
        assert_eq!(error_types::REVOCATION_FAILED, "revocation_failed");
        assert_eq!(error_types::GENERATION_ERROR, "generation_error");
        assert_eq!(error_types::REDIS_UNAVAILABLE, "redis_unavailable");
        
        // Use constants in actual operations
        record_refresh_operation(steps::TOKEN_VALIDATION, results::SUCCESS);
        record_refresh_failure_detailed(steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED);
        
        assert_eq!(REFRESH_OPERATIONS.with_label_values(&[steps::TOKEN_VALIDATION, results::SUCCESS]).get(), 1.0);
        assert_eq!(REFRESH_FAILURES.with_label_values(&[steps::TOKEN_REVOCATION, error_types::REVOCATION_FAILED]).get(), 1.0);
    }
}