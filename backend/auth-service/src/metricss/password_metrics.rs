//! # Password Reset Metrics - Production-Grade Password Reset Flow Monitoring
//!
//! Essential password reset flow monitoring for complete authentication recovery observability.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **End-to-End Flow Tracking**: Monitor complete password reset journey
//! - **Step-by-Step Observability**: Track each reset phase separately
//! - **Business Intelligence**: Reset success rates and failure analysis
//! - **Performance Monitoring**: Reset flow latency and bottlenecks
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (3 Essential)
//! - `password_reset_operations_total`: Reset operations by step and result
//! - `password_reset_failures_total`: Reset failures by specific step and error type
//! - `password_reset_duration_seconds`: Reset flow duration for performance monitoring
//!
//! ## Production Alerts
//! - High reset failure rates (user recovery issues)
//! - Reset flow bottlenecks (user experience)
//! - Infrastructure failures during reset (system health)
//! - Unusual failure patterns (security monitoring)

use crate::log_info;
use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramTimer, HistogramVec};
use std::sync::atomic::{AtomicBool, Ordering};

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_MEDIUM, // Involves DB, Redis, and potentially email
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Password reset operations by step and result
    ///
    /// Essential for monitoring password reset flow completion and identifying
    /// bottlenecks in the user recovery process.
    ///
    /// # Labels
    /// * `step`: Reset flow step
    ///   - `"redis_check"`: Redis client availability check
    ///   - `"user_lookup"`: User existence verification
    ///   - `"token_generation"`: Secure token creation
    ///   - `"redis_store"`: Token storage in Redis
    ///   - `"email_send"`: Reset email delivery
    ///   - `"token_validation"`: Token verification for confirm
    ///   - `"password_validation"`: New password strength check
    ///   - `"password_update"`: Database password update
    ///   - `"token_invalidation"`: Token cleanup after use
    ///   - `"complete_request"`: End-to-end request process
    ///   - `"complete_confirm"`: End-to-end confirm process
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Step completed successfully
    ///   - `"failure"`: Step failed for any reason
    ///
    /// # Business Impact
    /// - **User Recovery**: Failed steps prevent password resets
    /// - **Security Compliance**: Proper token handling ensures security
    /// - **Support Load**: High failures increase support tickets
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High reset failure rate
    /// - alert: HighPasswordResetFailureRate
    ///   expr: rate(password_reset_operations_total{step="complete_confirm", result="failure"}[5m]) / rate(password_reset_operations_total{step="complete_confirm"}[5m]) > 0.05
    ///   severity: critical
    ///   annotations:
    ///     summary: "Password reset failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: Email send failures
    /// - alert: PasswordResetEmailFailures
    ///   expr: rate(password_reset_operations_total{step="email_send", result="failure"}[5m]) > 1
    ///   severity: warning
    /// ```
    pub static ref PASSWORD_RESET_OPERATIONS: CounterVec = create_counter_vec(
        "password_reset_operations_total",
        "Password reset operations by step and result",
        &["step", "result"]
    ).expect("Failed to create PASSWORD_RESET_OPERATIONS metric");

    /// **Failure Analysis Metric**: Password reset failures by specific step and error type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and
    /// security compliance monitoring.
    ///
    /// # Labels
    /// * `step`: Reset step that failed
    /// * `error_type`: Specific type of failure
    ///   - General: `"redis_unavailable"`, `"db_connection_failed"`
    ///   - Request: `"user_not_found"`, `"token_generation_failed"`, `"redis_store_failed"`, `"email_send_failed"`
    ///   - Confirm: `"invalid_token"`, `"expired_token"`, `"weak_password"`, `"password_update_failed"`, `"token_invalidation_failed"`
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Redis unavailable during reset
    /// - alert: PasswordResetRedisUnavailable
    ///   expr: rate(password_reset_failures_total{error_type="redis_unavailable"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: High invalid token rate
    /// - alert: HighInvalidResetTokens
    ///   expr: rate(password_reset_failures_total{step="token_validation", error_type="invalid_token"}[5m]) > 5
    ///   severity: warning
    /// ```
    pub static ref PASSWORD_RESET_FAILURES: CounterVec = create_counter_vec(
        "password_reset_failures_total",
        "Password reset failures by step and error type",
        &["step", "error_type"]
    ).expect("Failed to create PASSWORD_RESET_FAILURES metric");

    /// **Performance Metric**: Password reset flow duration for SLA monitoring
    ///
    /// Tracks password reset processing latency to ensure responsive user recovery
    /// and identify performance bottlenecks in the reset pipeline.
    ///
    /// # Labels
    /// * `step`: Reset step for performance analysis
    ///
    /// # Performance Targets
    /// - **Complete Request**: p95 < 500ms, p99 < 1s (includes email send)
    /// - **Complete Confirm**: p95 < 200ms, p99 < 500ms (DB update)
    /// - **Token Generation**: p95 < 5ms, p99 < 10ms (crypto ops)
    /// - **Redis Operations**: p95 < 10ms, p99 < 25ms (store/validate)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow reset request flow
    /// - alert: SlowPasswordResetRequest
    ///   expr: histogram_quantile(0.95, rate(password_reset_duration_seconds_bucket{step="complete_request"}[5m])) > 0.5
    ///   severity: warning
    ///
    /// # Critical: Very slow reset confirm
    /// - alert: VerySlowPasswordResetConfirm
    ///   expr: histogram_quantile(0.95, rate(password_reset_duration_seconds_bucket{step="complete_confirm"}[5m])) > 0.5
    ///   severity: critical
    /// ```
    pub static ref PASSWORD_RESET_DURATION: HistogramVec = create_histogram_vec(
        "password_reset_duration_seconds",
        "Password reset step duration for performance monitoring",
        &["step"],
        LATENCY_BUCKETS_MEDIUM  // Involves DB, Redis, email
    ).expect("Failed to create PASSWORD_RESET_DURATION metric");
}

static PASSWORD_RESET_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_password_reset_metrics() {
    if PASSWORD_RESET_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&PASSWORD_RESET_OPERATIONS);
    lazy_static::initialize(&PASSWORD_RESET_FAILURES);
    lazy_static::initialize(&PASSWORD_RESET_DURATION);

    log_info!(
        "Metrics",
        "Password reset metrics initialized (production-ready with full standardization)",
        "password_reset_metrics_init"
    );
}

// =============================================================================
// CORE API (Fully standardized - consistent with other modules)
// =============================================================================

/// Records password reset operation result (standardized approach)
pub fn record_password_reset_operation(step: &str, result: &str) {
    observe_counter_vec(
        &PASSWORD_RESET_OPERATIONS,
        "password_reset_operations_total",
        &[step, result],
    );
}

/// Records specific password reset failure (standardized approach)
pub fn record_password_reset_failure_detailed(step: &str, error_type: &str) {
    observe_counter_vec(
        &PASSWORD_RESET_FAILURES,
        "password_reset_failures_total",
        &[step, error_type],
    );
}

/// Times password reset step with standard prometheus timer
pub fn time_password_reset_step(step: &str) -> HistogramTimer {
    PASSWORD_RESET_DURATION
        .with_label_values(&[step])
        .start_timer()
}

// =============================================================================
// CONSTANTS (Type-safe password reset step classification)
// =============================================================================

/// Password reset step constants for type safety
pub mod steps {
    pub const REDIS_CHECK: &str = "redis_check";
    pub const USER_LOOKUP: &str = "user_lookup";
    pub const TOKEN_GENERATION: &str = "token_generation";
    pub const REDIS_STORE: &str = "redis_store";
    pub const EMAIL_SEND: &str = "email_send";
    pub const TOKEN_VALIDATION: &str = "token_validation";
    pub const PASSWORD_VALIDATION: &str = "password_validation";
    pub const PASSWORD_UPDATE: &str = "password_update";
    pub const TOKEN_INVALIDATION: &str = "token_invalidation";
    pub const COMPLETE_REQUEST: &str = "complete_request";
    pub const COMPLETE_CONFIRM: &str = "complete_confirm";
}

/// Result constants for consistent labeling
pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization
pub mod error_types {
    pub const REDIS_UNAVAILABLE: &str = "redis_unavailable";
    pub const USER_NOT_FOUND: &str = "user_not_found";
    pub const REDIS_STORE_FAILED: &str = "redis_store_failed";
    pub const EMAIL_SEND_FAILED: &str = "email_send_failed";
    pub const INVALID_TOKEN: &str = "invalid_token";
    pub const WEAK_PASSWORD: &str = "weak_password";
    pub const PASSWORD_UPDATE_FAILED: &str = "password_update_failed";
    pub const TOKEN_INVALIDATION_FAILED: &str = "token_invalidation_failed";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful password reset step
pub fn record_step_success(step: &str) {
    record_password_reset_operation(step, results::SUCCESS);
}

/// Records failed password reset step
pub fn record_step_failure(step: &str) {
    record_password_reset_operation(step, results::FAILURE);
}

/// Records password reset step failure with specific error type
pub fn record_step_failure_with_type(step: &str, error_type: &str) {
    record_password_reset_failure_detailed(step, error_type);
    record_step_failure(step); // Also record in general operations
}

// Complete flow helpers
pub fn record_request_success() {
    record_step_success(steps::COMPLETE_REQUEST);
}

pub fn record_request_failure() {
    record_step_failure(steps::COMPLETE_REQUEST);
}

pub fn time_complete_request_flow() -> HistogramTimer {
    time_password_reset_step(steps::COMPLETE_REQUEST)
}

pub fn record_confirm_success() {
    record_step_success(steps::COMPLETE_CONFIRM);
}

pub fn record_confirm_failure() {
    record_step_failure(steps::COMPLETE_CONFIRM);
}

pub fn time_complete_confirm_flow() -> HistogramTimer {
    time_password_reset_step(steps::COMPLETE_CONFIRM)
}

// Step-specific helpers (matching password_reset_logic.rs)
pub fn record_redis_check_success() {
    record_step_success(steps::REDIS_CHECK);
}

pub fn record_redis_check_failure(error_type: &str) {
    record_step_failure_with_type(steps::REDIS_CHECK, error_type);
}

pub fn record_user_lookup_success() {
    record_step_success(steps::USER_LOOKUP);
}

pub fn record_user_lookup_failure(error_type: &str) {
    record_step_failure_with_type(steps::USER_LOOKUP, error_type);
}

pub fn record_token_generation_success() {
    record_step_success(steps::TOKEN_GENERATION);
}

pub fn record_redis_store_success() {
    record_step_success(steps::REDIS_STORE);
}

pub fn record_redis_store_failure(error_type: &str) {
    record_step_failure_with_type(steps::REDIS_STORE, error_type);
}

pub fn record_email_send_success() {
    record_step_success(steps::EMAIL_SEND);
}

pub fn record_email_send_failure(error_type: &str) {
    record_step_failure_with_type(steps::EMAIL_SEND, error_type);
}

pub fn record_token_validation_success() {
    record_step_success(steps::TOKEN_VALIDATION);
}

pub fn record_token_validation_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_VALIDATION, error_type);
}

pub fn record_password_validation_success() {
    record_step_success(steps::PASSWORD_VALIDATION);
}

pub fn record_password_validation_failure(error_type: &str) {
    record_step_failure_with_type(steps::PASSWORD_VALIDATION, error_type);
}

pub fn record_password_update_success() {
    record_step_success(steps::PASSWORD_UPDATE);
}

pub fn record_password_update_failure(error_type: &str) {
    record_step_failure_with_type(steps::PASSWORD_UPDATE, error_type);
}

pub fn record_token_invalidation_success() {
    record_step_success(steps::TOKEN_INVALIDATION);
}

pub fn record_token_invalidation_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_INVALIDATION, error_type);
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_reset_metrics_initialization() {
        init_password_reset_metrics();

        // Test that all metrics are properly initialized
        assert_eq!(
            PASSWORD_RESET_OPERATIONS
                .with_label_values(&[steps::COMPLETE_REQUEST, results::SUCCESS])
                .get(),
            0.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
                .get(),
            0.0
        );
        assert_eq!(
            PASSWORD_RESET_DURATION
                .with_label_values(&[steps::COMPLETE_CONFIRM])
                .get_sample_count(),
            0
        );
    }

    #[test]
    fn test_complete_request_flow() {
        init_password_reset_metrics();

        let before_count = PASSWORD_RESET_OPERATIONS
            .with_label_values(&[steps::COMPLETE_REQUEST, results::SUCCESS])
            .get();
        let before_duration = PASSWORD_RESET_DURATION
            .with_label_values(&[steps::COMPLETE_REQUEST])
            .get_sample_count();

        // Test complete request success
        let timer = time_complete_request_flow();
        record_request_success();
        drop(timer);

        let after_count = PASSWORD_RESET_OPERATIONS
            .with_label_values(&[steps::COMPLETE_REQUEST, results::SUCCESS])
            .get();
        let after_duration = PASSWORD_RESET_DURATION
            .with_label_values(&[steps::COMPLETE_REQUEST])
            .get_sample_count();

        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_complete_confirm_flow() {
        init_password_reset_metrics();

        let before_count = PASSWORD_RESET_OPERATIONS
            .with_label_values(&[steps::COMPLETE_CONFIRM, results::SUCCESS])
            .get();
        let before_duration = PASSWORD_RESET_DURATION
            .with_label_values(&[steps::COMPLETE_CONFIRM])
            .get_sample_count();

        // Test complete confirm success
        let timer = time_complete_confirm_flow();
        record_confirm_success();
        drop(timer);

        let after_count = PASSWORD_RESET_OPERATIONS
            .with_label_values(&[steps::COMPLETE_CONFIRM, results::SUCCESS])
            .get();
        let after_duration = PASSWORD_RESET_DURATION
            .with_label_values(&[steps::COMPLETE_CONFIRM])
            .get_sample_count();

        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_step_specific_helpers() {
        init_password_reset_metrics();

        // Test request step helpers
        record_redis_check_success();
        record_redis_check_failure(error_types::REDIS_UNAVAILABLE);

        record_user_lookup_success();
        record_user_lookup_failure(error_types::USER_NOT_FOUND);

        record_token_generation_success();

        record_redis_store_success();
        record_redis_store_failure(error_types::REDIS_STORE_FAILED);

        record_email_send_success();
        record_email_send_failure(error_types::EMAIL_SEND_FAILED);

        // Test confirm step helpers
        record_token_validation_success();
        record_token_validation_failure(error_types::INVALID_TOKEN);

        record_password_validation_success();
        record_password_validation_failure(error_types::WEAK_PASSWORD);

        record_password_update_success();
        record_password_update_failure(error_types::PASSWORD_UPDATE_FAILED);

        record_token_invalidation_success();
        record_token_invalidation_failure(error_types::TOKEN_INVALIDATION_FAILED);

        // Verify operations were recorded
        assert_eq!(
            PASSWORD_RESET_OPERATIONS
                .with_label_values(&[steps::REDIS_CHECK, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_OPERATIONS
                .with_label_values(&[steps::REDIS_CHECK, results::FAILURE])
                .get(),
            1.0
        );

        // Verify detailed failures were recorded
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::PASSWORD_VALIDATION, error_types::WEAK_PASSWORD])
                .get(),
            1.0
        );
    }

    #[test]
    fn test_production_reset_patterns() {
        init_password_reset_metrics();

        // Simulate realistic production patterns

        // 5 successful request flows
        for _ in 0..5 {
            record_redis_check_success();
            record_user_lookup_success();
            record_token_generation_success();
            record_redis_store_success();
            record_email_send_success();
            record_request_success();
        }

        // 3 successful confirm flows
        for _ in 0..3 {
            record_redis_check_success();
            record_token_validation_success();
            record_password_validation_success();
            record_password_update_success();
            record_token_invalidation_success();
            record_confirm_success();
        }

        // Some failures at different steps
        record_redis_check_failure(error_types::REDIS_UNAVAILABLE);
        record_user_lookup_failure(error_types::USER_NOT_FOUND);
        record_email_send_failure(error_types::EMAIL_SEND_FAILED);
        record_token_validation_failure(error_types::INVALID_TOKEN);
        record_password_validation_failure(error_types::WEAK_PASSWORD);
        record_password_update_failure(error_types::PASSWORD_UPDATE_FAILED);
        record_token_invalidation_failure(error_types::TOKEN_INVALIDATION_FAILED);

        // Verify realistic metric patterns
        assert_eq!(
            PASSWORD_RESET_OPERATIONS
                .with_label_values(&[steps::COMPLETE_REQUEST, results::SUCCESS])
                .get(),
            5.0
        );
        assert_eq!(
            PASSWORD_RESET_OPERATIONS
                .with_label_values(&[steps::COMPLETE_CONFIRM, results::SUCCESS])
                .get(),
            3.0
        );

        // Specific failure types
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::REDIS_CHECK, error_types::REDIS_UNAVAILABLE])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::EMAIL_SEND, error_types::EMAIL_SEND_FAILED])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
                .get(),
            1.0
        );
    }

    #[test]
    fn test_type_safety_constants() {
        init_password_reset_metrics();

        // Verify all constants are valid and type-safe
        assert_eq!(steps::REDIS_CHECK, "redis_check");
        assert_eq!(steps::USER_LOOKUP, "user_lookup");
        assert_eq!(steps::TOKEN_GENERATION, "token_generation");
        assert_eq!(steps::REDIS_STORE, "redis_store");
        assert_eq!(steps::EMAIL_SEND, "email_send");
        assert_eq!(steps::TOKEN_VALIDATION, "token_validation");
        assert_eq!(steps::PASSWORD_VALIDATION, "password_validation");
        assert_eq!(steps::PASSWORD_UPDATE, "password_update");
        assert_eq!(steps::TOKEN_INVALIDATION, "token_invalidation");
        assert_eq!(steps::COMPLETE_REQUEST, "complete_request");
        assert_eq!(steps::COMPLETE_CONFIRM, "complete_confirm");

        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");

        assert_eq!(error_types::REDIS_UNAVAILABLE, "redis_unavailable");
        assert_eq!(error_types::USER_NOT_FOUND, "user_not_found");
        assert_eq!(error_types::EMAIL_SEND_FAILED, "email_send_failed");
        assert_eq!(error_types::INVALID_TOKEN, "invalid_token");
        assert_eq!(error_types::WEAK_PASSWORD, "weak_password");
        assert_eq!(
            error_types::PASSWORD_UPDATE_FAILED,
            "password_update_failed"
        );

        // Use constants in actual operations
        record_password_reset_operation(steps::EMAIL_SEND, results::SUCCESS);
        record_password_reset_failure_detailed(steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN);

        assert_eq!(
            PASSWORD_RESET_OPERATIONS
                .with_label_values(&[steps::EMAIL_SEND, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            PASSWORD_RESET_FAILURES
                .with_label_values(&[steps::TOKEN_VALIDATION, error_types::INVALID_TOKEN])
                .get(),
            1.0
        );
    }
}
