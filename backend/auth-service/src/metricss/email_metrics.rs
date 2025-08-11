//! # Email Metrics - Production-Grade Email Service Monitoring
//!
//! Essential email delivery monitoring for registration and password recovery flows.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **Business-Critical Tracking**: Monitor email delivery success/failure rates
//! - **Performance Monitoring**: Track email processing latency for SLA compliance
//! - **Failure Analysis**: Detailed failure categorization for troubleshooting
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Low Cardinality**: Controlled label values to prevent metric explosion
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (3 Essential)
//! - `email_operations_total`: Email operations by type and result
//! - `email_failures_total`: Email delivery failures by specific failure type
//! - `email_duration_seconds`: Email processing duration for performance monitoring
//!
//! ## Production Alerts
//! - High email failure rates (delivery issues)
//! - SMTP connection failures (infrastructure problems)
//! - Slow email processing (performance degradation)

use crate::log_info;
use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramTimer, HistogramVec};
use std::sync::atomic::{AtomicBool, Ordering};

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_SLOW, // Use standardized buckets for email operations
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Email operations by type and result
    ///
    /// Essential for monitoring email delivery success rates and business flow completion.
    /// Tracks the fundamental email operations critical to user registration and password recovery.
    ///
    /// # Labels
    /// * `email_type`: Type of email being sent
    ///   - `"activation"`: Account activation emails for new user registration
    ///   - `"password_reset"`: Password reset emails for account recovery
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Email successfully sent and accepted by SMTP server
    ///   - `"failure"`: Email sending failed for any reason
    ///
    /// # Business Impact
    /// - **Registration Flow**: Failed activation emails prevent user onboarding
    /// - **Account Recovery**: Failed password reset emails block user access
    /// - **SLA Compliance**: Email delivery success rate directly affects user experience
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High email failure rate
    /// - alert: HighEmailFailureRate
    ///   expr: rate(email_operations_total{result="failure"}[5m]) / rate(email_operations_total[5m]) > 0.05
    ///   severity: critical
    ///   annotations:
    ///     summary: "Email failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: Activation email failures
    /// - alert: ActivationEmailFailures
    ///   expr: rate(email_operations_total{email_type="activation", result="failure"}[5m]) > 1
    ///   severity: warning
    /// ```
    ///
    /// # Business Dashboards
    /// ```promql
    /// # Overall email success rate
    /// rate(email_operations_total{result="success"}[5m]) / rate(email_operations_total[5m])
    ///
    /// # Email volume by type
    /// sum by (email_type) (rate(email_operations_total[5m]))
    /// ```
    pub static ref EMAIL_OPERATIONS: CounterVec = create_counter_vec(
        "email_operations_total",
        "Email operations by type and result",
        &["email_type", "result"]
    ).expect("Failed to create EMAIL_OPERATIONS metric");

    /// **Failure Analysis Metric**: Email delivery failures by specific failure type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and infrastructure monitoring.
    /// Essential for distinguishing between transient issues and systematic problems.
    ///
    /// # Labels
    /// * `failure_type`: Specific type of failure for targeted resolution
    ///   - `"smtp_connection"`: SMTP server connection failures (infrastructure)
    ///   - `"smtp_auth"`: SMTP authentication failures (configuration)
    ///   - `"smtp_timeout"`: SMTP operation timeouts (performance/network)
    ///   - `"invalid_address"`: Invalid email address format (validation)
    ///   - `"token_storage"`: Token generation/storage failures (internal)
    ///   - `"configuration"`: Email service configuration errors (setup)
    /// * `email_type`: Type of email that failed (for impact analysis)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: SMTP infrastructure down
    /// - alert: SMTPConnectionFailures
    ///   expr: rate(email_failures_total{failure_type="smtp_connection"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: SMTP authentication issues
    /// - alert: SMTPAuthFailures
    ///   expr: rate(email_failures_total{failure_type="smtp_auth"}[5m]) > 0
    ///   severity: warning
    /// ```
    ///
    /// # Troubleshooting Dashboards
    /// ```promql
    /// # Failure breakdown by type
    /// sum by (failure_type) (rate(email_failures_total[5m]))
    ///
    /// # Infrastructure vs application failures
    /// rate(email_failures_total{failure_type=~"smtp_.*"}[5m])
    /// ```
    pub static ref EMAIL_FAILURES: CounterVec = create_counter_vec(
        "email_failures_total",
        "Email delivery failures by specific failure type",
        &["failure_type", "email_type"]
    ).expect("Failed to create EMAIL_FAILURES metric");

    /// **Performance Metric**: Email processing duration for SLA monitoring
    ///
    /// Tracks email processing latency to ensure responsive user experience and detect performance issues.
    /// Critical for maintaining SLA compliance and identifying bottlenecks in the email pipeline.
    ///
    /// # Labels
    /// * `email_type`: Type of email for performance comparison
    ///
    /// # Performance Targets
    /// - **p95 < 2s**: 95% of emails processed within 2 seconds
    /// - **p99 < 5s**: 99% of emails processed within 5 seconds
    /// - **Mean < 1s**: Average processing time under 1 second
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow email processing
    /// - alert: SlowEmailProcessing
    ///   expr: histogram_quantile(0.95, rate(email_duration_seconds_bucket[5m])) > 2.0
    ///   severity: warning
    ///   annotations:
    ///     summary: "Email p95 latency: {{ $value }}s"
    ///
    /// # Critical: Very slow email processing
    /// - alert: VerySlowEmailProcessing
    ///   expr: histogram_quantile(0.95, rate(email_duration_seconds_bucket[5m])) > 5.0
    ///   severity: critical
    /// ```
    ///
    /// # Performance Dashboards
    /// ```promql
    /// # p95 latency by email type
    /// histogram_quantile(0.95, sum by (email_type, le) (rate(email_duration_seconds_bucket[5m])))
    ///
    /// # Average processing time
    /// rate(email_duration_seconds_sum[5m]) / rate(email_duration_seconds_count[5m])
    /// ```
    pub static ref EMAIL_DURATION: HistogramVec = create_histogram_vec(
        "email_duration_seconds",
        "Email processing duration for performance monitoring",
        &["email_type"],
        LATENCY_BUCKETS_SLOW  // Use standardized buckets for email operations
    ).expect("Failed to create EMAIL_DURATION metric");
}

/// Thread-safe initialization guard to ensure metrics are initialized only once
static EMAIL_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize all email metrics in a thread-safe manner
///
/// This function ensures metrics are registered exactly once, regardless of concurrent calls.
/// Safe to call from multiple threads during application startup.
pub fn init_email_metrics() {
    if EMAIL_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // Already initialized
    }

    // Force initialization of all metrics
    lazy_static::initialize(&EMAIL_OPERATIONS);
    lazy_static::initialize(&EMAIL_FAILURES);
    lazy_static::initialize(&EMAIL_DURATION);

    log_info!(
        "Metrics",
        "Email metrics initialized (production-ready with full standardization)",
        "email_metrics_init"
    );
}

// =============================================================================
// CORE API (Fully standardized - consistent with jwt_metrics.rs pattern)
// =============================================================================

/// Records email operation result (standardized approach)
///
/// # Arguments
/// * `email_type` - Type of email being processed (use `email_types` constants)
/// * `result` - Result of the operation (use `results` constants)
///
/// # Example
/// ```
/// // Record a successful activation email
/// record_email_operation(email_types::ACTIVATION, results::SUCCESS);
/// ```
pub fn record_email_operation(email_type: &str, result: &str) {
    observe_counter_vec(
        &EMAIL_OPERATIONS,
        "email_operations_total",
        &[email_type, result],
    );
}

/// Records specific email failure (standardized approach)
///
/// # Arguments
/// * `failure_type` - Specific type of failure (use `failure_types` constants)
/// * `email_type` - Type of email being processed (use `email_types` constants)
///
/// # Example
/// ```
/// // Record a connection failure for activation email
/// record_email_failure(failure_types::SMTP_CONNECTION, email_types::ACTIVATION);
/// ```
pub fn record_email_failure(failure_type: &str, email_type: &str) {
    observe_counter_vec(
        &EMAIL_FAILURES,
        "email_failures_total",
        &[failure_type, email_type],
    );
}

/// Times email processing with standard prometheus timer (clean approach like JWT module)
///
/// # Arguments
/// * `email_type` - Type of email being processed (use `email_types` constants)
///
/// # Returns
/// A histogram timer that will automatically record the duration when dropped
///
/// # Example
/// ```
/// let timer = time_email_processing(email_types::ACTIVATION);
/// // Send email...
/// // Timer automatically records duration when it goes out of scope
/// ```
pub fn time_email_processing(email_type: &str) -> HistogramTimer {
    EMAIL_DURATION
        .with_label_values(&[email_type])
        .start_timer()
}

// =============================================================================
// CONSTANTS (Type-safe email classification)
// =============================================================================

/// Email type constants for type safety
pub mod email_types {
    /// Account activation email
    pub const ACTIVATION: &str = "activation";
    /// Password reset email
    pub const PASSWORD_RESET: &str = "password_reset";
}

/// Result constants for consistent labeling
pub mod results {
    /// Operation succeeded
    pub const SUCCESS: &str = "success";
    /// Operation failed
    pub const FAILURE: &str = "failure";
}

/// Failure type constants for detailed error categorization
pub mod failure_types {
    /// Invalid email address format (validation)
    pub const INVALID_ADDRESS: &str = "invalid_address";
    /// Token generation/storage failures (internal)
    pub const TOKEN_STORAGE: &str = "token_storage";
    /// Email service configuration errors (setup)
    pub const CONFIGURATION: &str = "configuration";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful activation email
///
/// Convenience function for recording successful activation email operations.
pub fn record_activation_success() {
    record_email_operation(email_types::ACTIVATION, results::SUCCESS);
}

/// Records failed activation email
///
/// Convenience function for recording failed activation email operations.
pub fn record_activation_failure() {
    record_email_operation(email_types::ACTIVATION, results::FAILURE);
}

/// Records successful password reset email
///
/// Convenience function for recording successful password reset email operations.
pub fn record_password_reset_success() {
    record_email_operation(email_types::PASSWORD_RESET, results::SUCCESS);
}

/// Records failed password reset email
///
/// Convenience function for recording failed password reset email operations.
pub fn record_password_reset_failure() {
    record_email_operation(email_types::PASSWORD_RESET, results::FAILURE);
}

/// Records activation email failure with specific failure type
///
/// Convenience function for recording detailed activation email failures.
///
/// # Arguments
/// * `failure_type` - Specific type of failure (use `failure_types` constants)
pub fn record_activation_failure_detailed(failure_type: &str) {
    record_email_failure(failure_type, email_types::ACTIVATION);
    record_activation_failure(); // Also record in general operations
}

/// Records password reset email failure with specific failure type
///
/// Convenience function for recording detailed password reset email failures.
///
/// # Arguments
/// * `failure_type` - Specific type of failure (use `failure_types` constants)
pub fn record_password_reset_failure_detailed(failure_type: &str) {
    record_email_failure(failure_type, email_types::PASSWORD_RESET);
    record_password_reset_failure(); // Also record in general operations
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_metrics_initialization() {
        init_email_metrics();

        // Test that all metrics are properly initialized
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
                .get(),
            0.0
        );
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::ACTIVATION])
                .get(),
            0.0
        );
        assert_eq!(
            EMAIL_DURATION
                .with_label_values(&[email_types::ACTIVATION])
                .get_sample_count(),
            0
        );
    }

    #[test]
    fn test_standardized_counter_operations() {
        init_email_metrics();

        let before = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
            .get();

        record_activation_success();

        let after = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
            .get();

        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_standardized_failure_tracking() {
        init_email_metrics();

        let before = EMAIL_FAILURES
            .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::ACTIVATION])
            .get();

        record_email_failure(failure_types::INVALID_ADDRESS, email_types::ACTIVATION);

        let after = EMAIL_FAILURES
            .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::ACTIVATION])
            .get();

        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_standardized_timer_approach() {
        init_email_metrics();

        let before_count = EMAIL_DURATION
            .with_label_values(&[email_types::ACTIVATION])
            .get_sample_count();

        let timer = time_email_processing(email_types::ACTIVATION);
        drop(timer); // Complete the timing

        let after_count = EMAIL_DURATION
            .with_label_values(&[email_types::ACTIVATION])
            .get_sample_count();

        // Clean assertion - timer should always work with standardized approach
        assert_eq!(after_count, before_count + 1);
    }

    #[test]
    fn test_business_helper_consistency() {
        init_email_metrics();

        // Test all business helpers
        record_activation_success();
        record_activation_failure();
        record_password_reset_success();
        record_password_reset_failure();

        // Test detailed failure helpers
        record_activation_failure_detailed(failure_types::INVALID_ADDRESS);
        record_password_reset_failure_detailed(failure_types::INVALID_ADDRESS);

        // Verify operations were recorded
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::FAILURE])
                .get(),
            2.0
        ); // General + detailed
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::PASSWORD_RESET, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::PASSWORD_RESET, results::FAILURE])
                .get(),
            2.0
        ); // General + detailed

        // Verify detailed failures were recorded
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::ACTIVATION])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::PASSWORD_RESET])
                .get(),
            1.0
        );
    }

    #[test]
    fn test_comprehensive_email_types_and_failures() {
        init_email_metrics();

        // Test all email types and results
        record_email_operation(email_types::ACTIVATION, results::SUCCESS);
        record_email_operation(email_types::ACTIVATION, results::FAILURE);
        record_email_operation(email_types::PASSWORD_RESET, results::SUCCESS);
        record_email_operation(email_types::PASSWORD_RESET, results::FAILURE);

        // Test all failure types
        record_email_failure(failure_types::INVALID_ADDRESS, email_types::ACTIVATION);
        record_email_failure(failure_types::TOKEN_STORAGE, email_types::ACTIVATION);
        record_email_failure(failure_types::CONFIGURATION, email_types::PASSWORD_RESET);

        // Verify all constants work correctly
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::PASSWORD_RESET, results::FAILURE])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::TOKEN_STORAGE, email_types::ACTIVATION])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::CONFIGURATION, email_types::PASSWORD_RESET])
                .get(),
            1.0
        );
    }

    #[test]
    fn test_production_email_patterns() {
        init_email_metrics();

        // Simulate realistic production patterns

        // Normal successful flow (majority of operations)
        for _ in 0..10 {
            record_activation_success();
        }
        for _ in 0..5 {
            record_password_reset_success();
        }

        // Some failures with specific causes
        record_activation_failure_detailed(failure_types::TOKEN_STORAGE);
        record_password_reset_failure_detailed(failure_types::INVALID_ADDRESS);
        record_activation_failure_detailed(failure_types::TOKEN_STORAGE);

        // Performance tracking with timer
        {
            let _timer = time_email_processing(email_types::ACTIVATION);
            // Simulate work
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        {
            let _timer = time_email_processing(email_types::PASSWORD_RESET);
            // Simulate work
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Verify realistic ratios
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
                .get(),
            10.0
        );
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::PASSWORD_RESET, results::SUCCESS])
                .get(),
            5.0
        );
        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::FAILURE])
                .get(),
            2.0
        ); // 2 detailed failures

        // Verify failure categorization
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::TOKEN_STORAGE, email_types::ACTIVATION])
                .get(),
            2.0
        );
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::PASSWORD_RESET])
                .get(),
            1.0
        );

        // Verify duration tracking
        assert_eq!(
            EMAIL_DURATION
                .with_label_values(&[email_types::ACTIVATION])
                .get_sample_count(),
            1
        );
        assert_eq!(
            EMAIL_DURATION
                .with_label_values(&[email_types::PASSWORD_RESET])
                .get_sample_count(),
            1
        );
    }

    #[test]
    fn test_edge_cases_and_validation() {
        init_email_metrics();

        // Test edge cases that should be handled gracefully by core infrastructure
        record_email_operation("", ""); // Empty strings
        record_email_failure("", "");
        let _timer = time_email_processing(""); // Empty string timer

        // These should not panic due to core infrastructure protection
        // Just verify we can continue operating
        record_activation_success();
        assert!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
                .get()
                >= 1.0
        );
    }

    #[test]
    fn test_type_safety_constants() {
        init_email_metrics();

        // Verify all constants are valid and type-safe
        assert_eq!(email_types::ACTIVATION, "activation");
        assert_eq!(email_types::PASSWORD_RESET, "password_reset");

        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");

        assert_eq!(failure_types::INVALID_ADDRESS, "invalid_address");
        assert_eq!(failure_types::TOKEN_STORAGE, "token_storage");
        assert_eq!(failure_types::CONFIGURATION, "configuration");

        // Use constants in actual operations to verify they work
        record_email_operation(email_types::ACTIVATION, results::SUCCESS);
        record_email_failure(failure_types::INVALID_ADDRESS, email_types::PASSWORD_RESET);

        assert_eq!(
            EMAIL_OPERATIONS
                .with_label_values(&[email_types::ACTIVATION, results::SUCCESS])
                .get(),
            1.0
        );
        assert_eq!(
            EMAIL_FAILURES
                .with_label_values(&[failure_types::INVALID_ADDRESS, email_types::PASSWORD_RESET])
                .get(),
            1.0
        );
    }
}
