//! # Validation Metrics - Production-Grade Input Validation Monitoring
//!
//! Essential validation monitoring for user input processing and security compliance.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **Performance Monitoring**: Track validation latency for responsive user experience
//! - **Error Analysis**: Categorize validation failures for targeted improvements
//! - **Business Intelligence**: Monitor field-specific validation patterns
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Low Cardinality**: Controlled label values to prevent metric explosion
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (3 Essential)
//! - `validation_operations_total`: Validation operations by field and result
//! - `validation_failures_total`: Validation failures by specific error type
//! - `validation_duration_seconds`: Validation processing duration for performance monitoring
//!
//! ## Production Alerts
//! - High validation failure rates (user experience issues)
//! - Slow validation processing (performance degradation)
//! - Password weakness patterns (security compliance)

use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec, HistogramTimer};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::utils::error_new::{AuthServiceError, ValidationError};
use crate::log_info;

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_FAST, // Use standardized buckets for fast validation operations
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Validation operations by field and result
    ///
    /// Essential for monitoring user input validation success rates and identifying
    /// problematic fields or user experience issues in the registration flow.
    ///
    /// # Labels
    /// * `field`: Type of field being validated
    ///   - `"username"`: Username validation for uniqueness and format
    ///   - `"email"`: Email address validation for format and deliverability
    ///   - `"password"`: Password validation for strength and security requirements
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Validation passed all requirements
    ///   - `"failure"`: Validation failed for any reason
    ///
    /// # Business Impact
    /// - **User Experience**: High failure rates indicate overly strict validation
    /// - **Security Compliance**: Password validation ensures security standards
    /// - **Registration Flow**: Failed validations block user onboarding
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: High validation failure rate
    /// - alert: HighValidationFailureRate
    ///   expr: rate(validation_operations_total{result="failure"}[5m]) / rate(validation_operations_total[5m]) > 0.1
    ///   severity: warning
    ///   annotations:
    ///     summary: "Validation failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Critical: Password validation issues
    /// - alert: PasswordValidationIssues
    ///   expr: rate(validation_operations_total{field="password", result="failure"}[5m]) > 5
    ///   severity: critical
    /// ```
    ///
    /// # Business Dashboards
    /// ```promql
    /// # Overall validation success rate
    /// rate(validation_operations_total{result="success"}[5m]) / rate(validation_operations_total[5m])
    ///
    /// # Validation volume by field
    /// sum by (field) (rate(validation_operations_total[5m]))
    /// ```
    pub static ref VALIDATION_OPERATIONS: CounterVec = create_counter_vec(
        "validation_operations_total",
        "Validation operations by field and result",
        &["field", "result"]
    ).expect("Failed to create VALIDATION_OPERATIONS metric");

    /// **Failure Analysis Metric**: Validation failures by specific error type
    ///
    /// Provides detailed failure categorization for targeted user experience improvements
    /// and security compliance monitoring.
    ///
    /// # Labels
    /// * `field`: Type of field that failed validation (for impact analysis)
    /// * `error_type`: Specific type of validation failure
    ///   - `"missing"`: Required field was not provided
    ///   - `"too_long"`: Field exceeds maximum length requirements
    ///   - `"invalid_format"`: Field format doesn't match requirements (email, username)
    ///   - `"weak_password"`: Password doesn't meet security requirements
    ///   - `"hash_error"`: Password hashing operation failed
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: High password weakness rate
    /// - alert: WeakPasswordAttempts
    ///   expr: rate(validation_failures_total{field="password", error_type="weak_password"}[5m]) > 2
    ///   severity: warning
    ///
    /// # Critical: Format validation issues
    /// - alert: FormatValidationFailures
    ///   expr: rate(validation_failures_total{error_type="invalid_format"}[5m]) > 1
    ///   severity: critical
    /// ```
    ///
    /// # Error Analysis Dashboards
    /// ```promql
    /// # Top validation error types
    /// topk(5, rate(validation_failures_total[5m]))
    ///
    /// # Password weakness trends
    /// rate(validation_failures_total{field="password", error_type="weak_password"}[5m])
    /// ```
    pub static ref VALIDATION_FAILURES: CounterVec = create_counter_vec(
        "validation_failures_total",
        "Validation failures by field and error type",
        &["field", "error_type"]
    ).expect("Failed to create VALIDATION_FAILURES metric");

    /// **Performance Metric**: Validation processing duration for user experience monitoring
    ///
    /// Tracks validation latency to ensure responsive user interfaces and detect performance issues.
    /// Critical for maintaining smooth registration and login experiences.
    ///
    /// # Labels
    /// * `field`: Type of field for performance comparison
    ///
    /// # Performance Targets
    /// - **p95 < 10ms**: 95% of validations completed within 10 milliseconds
    /// - **p99 < 50ms**: 99% of validations completed within 50 milliseconds
    /// - **Mean < 5ms**: Average validation time under 5 milliseconds
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow validation processing
    /// - alert: SlowValidationProcessing
    ///   expr: histogram_quantile(0.95, rate(validation_duration_seconds_bucket[5m])) > 0.01
    ///   severity: warning
    ///   annotations:
    ///     summary: "Validation p95 latency: {{ $value }}ms"
    ///
    /// # Critical: Very slow validation processing
    /// - alert: VerySlowValidationProcessing
    ///   expr: histogram_quantile(0.95, rate(validation_duration_seconds_bucket[5m])) > 0.05
    ///   severity: critical
    /// ```
    ///
    /// # Performance Dashboards
    /// ```promql
    /// # p95 latency by field type
    /// histogram_quantile(0.95, sum by (field, le) (rate(validation_duration_seconds_bucket[5m])))
    ///
    /// # Average validation time
    /// rate(validation_duration_seconds_sum[5m]) / rate(validation_duration_seconds_count[5m])
    /// ```
    pub static ref VALIDATION_DURATION: HistogramVec = create_histogram_vec(
        "validation_duration_seconds",
        "Validation operation duration for performance monitoring",
        &["field"],
        LATENCY_BUCKETS_FAST  // ✅ Use standardized buckets for fast validation operations
    ).expect("Failed to create VALIDATION_DURATION metric");
}

static VALIDATION_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn init_validation_metrics() {
    if VALIDATION_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&VALIDATION_OPERATIONS);
    lazy_static::initialize(&VALIDATION_FAILURES);
    lazy_static::initialize(&VALIDATION_DURATION);

    log_info!("Metrics", "Validation metrics initialized (production-ready with full standardization)", "validation_metrics_init");
}

// =============================================================================
// CORE API (Fully standardized - consistent with email_metrics.rs pattern)
// =============================================================================

/// Records validation operation result (standardized approach)
pub fn record_validation_operation(field: &str, result: &str) {
    observe_counter_vec(
        &VALIDATION_OPERATIONS,
        "validation_operations_total",
        &[field, result]
    );
}

/// Records specific validation failure (standardized approach)
pub fn record_validation_failure_detailed(field: &str, error_type: &str) {
    observe_counter_vec(
        &VALIDATION_FAILURES,
        "validation_failures_total",
        &[field, error_type]
    );
}

/// Times validation processing with standard prometheus timer (clean approach like email module)
pub fn time_validation(field: &str) -> HistogramTimer {
    VALIDATION_DURATION
        .with_label_values(&[field])
        .start_timer()
}

// =============================================================================
// CONSTANTS (Type-safe validation classification)
// =============================================================================

/// Field type constants for type safety
pub mod field_types {
    pub const USERNAME: &str = "username";
    pub const EMAIL: &str = "email";
    pub const PASSWORD: &str = "password";
}

/// Result constants for consistent labeling
pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization
pub mod error_types {
    pub const MISSING: &str = "missing";
    pub const TOO_LONG: &str = "too_long";
    pub const INVALID_FORMAT: &str = "invalid_format";
    pub const WEAK_PASSWORD: &str = "weak_password";
    pub const HASH_ERROR: &str = "hash_error";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful validation
pub fn record_validation_success(field: &str) {
    record_validation_operation(field, results::SUCCESS);
}

/// Records failed validation
pub fn record_validation_failure(field: &str) {
    record_validation_operation(field, results::FAILURE);
}

/// Records validation failure with specific error type
pub fn record_validation_failure_with_type(field: &str, error_type: &str) {
    record_validation_failure_detailed(field, error_type);
    record_validation_failure(field); // Also record in general operations
}

// Field-specific helpers for common validation scenarios (only used ones)
pub fn record_username_success() {
    record_validation_success(field_types::USERNAME);
}

pub fn record_username_failure(error_type: &str) {
    record_validation_failure_with_type(field_types::USERNAME, error_type);
}

// =============================================================================
// HIGH-LEVEL API (For complex validation flows)
// =============================================================================

/// Instruments a validation operation with complete metrics tracking (standardized approach)
/// 
/// This is the high-level API that combines timing, success/failure tracking, and error categorization.
/// Perfect for wrapping existing validation functions without changing their logic.
///
/// # Example
/// ```rust
/// let result = instrument_validation("username", || {
///     validate_username(&input_username)
/// })?;
/// ```
pub fn instrument_validation<F>(field: &str, validation_fn: F) -> Result<(), AuthServiceError>
where
    F: FnOnce() -> Result<(), ValidationError>,
{
    // ✅ PERFECT: Clean timer using standardized approach - no Option<>, no custom error handling
    let _timer = time_validation(field);
    
    match validation_fn() {
        Ok(()) => {
            // ✅ PERFECT: Clean success tracking using business helper
            record_validation_success(field);
            Ok(())
        }
        Err(validation_err) => {
            // ✅ PERFECT: Clean failure tracking with error categorization
            let error_type = categorize_error(&validation_err);
            record_validation_failure_with_type(field, error_type);
            
            // Pass the error up the chain
            Err(AuthServiceError::from(validation_err))
        }
    }
}

// =============================================================================
// ERROR CATEGORIZATION (Simple and reliable)
// =============================================================================

/// Categorizes validation errors for metrics (simple, no security theater)
fn categorize_error(err: &ValidationError) -> &'static str {
    match err {
        ValidationError::MissingField { .. } => error_types::MISSING,
        ValidationError::TooLong { .. } => error_types::TOO_LONG,
        ValidationError::InvalidValue { field, .. } => {
            match field.as_str() {
                "password" => error_types::WEAK_PASSWORD,
                _ => error_types::INVALID_FORMAT,
            }
        }
        ValidationError::PasswordHash { .. } => error_types::HASH_ERROR,
    }
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_error::SpanTrace;

    #[test]
    fn test_validation_metrics_initialization() {
        init_validation_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::SUCCESS]).get(), 0.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::USERNAME, error_types::MISSING]).get(), 0.0);
        assert_eq!(VALIDATION_DURATION.with_label_values(&[field_types::USERNAME]).get_sample_count(), 0);
    }

    #[test]
    fn test_standardized_counter_operations() {
        init_validation_metrics();
        
        let before = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::USERNAME, results::SUCCESS])
            .get();
        
        record_username_success();
        
        let after = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::USERNAME, results::SUCCESS])
            .get();
        
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_standardized_failure_tracking() {
        init_validation_metrics();
        
        let before_general = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::EMAIL, results::FAILURE])
            .get();
        let before_detailed = VALIDATION_FAILURES
            .with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT])
            .get();
        
        record_validation_failure_with_type(field_types::EMAIL, error_types::INVALID_FORMAT);
        
        let after_general = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::EMAIL, results::FAILURE])
            .get();
        let after_detailed = VALIDATION_FAILURES
            .with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT])
            .get();
        
        assert_eq!(after_general, before_general + 1.0);
        assert_eq!(after_detailed, before_detailed + 1.0);
    }

    #[test]
    fn test_standardized_timer_approach() {
        init_validation_metrics();
        
        let before_count = VALIDATION_DURATION
            .with_label_values(&[field_types::PASSWORD])
            .get_sample_count();
        
        let timer = time_validation(field_types::PASSWORD);
        drop(timer); // Complete the timing
        
        let after_count = VALIDATION_DURATION
            .with_label_values(&[field_types::PASSWORD])
            .get_sample_count();
        
        // ✅ Clean assertion - timer should always work with standardized approach
        assert_eq!(after_count, before_count + 1);
    }

    #[test]
    fn test_high_level_instrument_validation_success() {
        init_validation_metrics();
        
        let before_count = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::USERNAME, results::SUCCESS])
            .get();
        let before_duration = VALIDATION_DURATION
            .with_label_values(&[field_types::USERNAME])
            .get_sample_count();
        
        let result = instrument_validation(field_types::USERNAME, || Ok(()));
        
        assert!(result.is_ok());
        
        let after_count = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::USERNAME, results::SUCCESS])
            .get();
        let after_duration = VALIDATION_DURATION
            .with_label_values(&[field_types::USERNAME])
            .get_sample_count();
        
        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_high_level_instrument_validation_failure() {
        init_validation_metrics();
        
        let before_general = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::EMAIL, results::FAILURE])
            .get();
        let before_detailed = VALIDATION_FAILURES
            .with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT])
            .get();
        let before_duration = VALIDATION_DURATION
            .with_label_values(&[field_types::EMAIL])
            .get_sample_count();
        
        let result = instrument_validation(field_types::EMAIL, || {
            Err(ValidationError::InvalidValue {
                field: field_types::EMAIL.to_string(),
                message: "Invalid email format".to_string(),
                span: SpanTrace::capture(),
            })
        });
        
        assert!(result.is_err());
        
        let after_general = VALIDATION_OPERATIONS
            .with_label_values(&[field_types::EMAIL, results::FAILURE])
            .get();
        let after_detailed = VALIDATION_FAILURES
            .with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT])
            .get();
        let after_duration = VALIDATION_DURATION
            .with_label_values(&[field_types::EMAIL])
            .get_sample_count();
        
        assert_eq!(after_general, before_general + 1.0);
        assert_eq!(after_detailed, before_detailed + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_error_categorization() {
        assert_eq!(
            categorize_error(&ValidationError::MissingField {
                field: field_types::USERNAME.to_string(),
                span: SpanTrace::capture(),
            }),
            error_types::MISSING
        );
        
        assert_eq!(
            categorize_error(&ValidationError::TooLong {
                field: field_types::EMAIL.to_string(),
                max_length: 254,
                span: SpanTrace::capture(),
            }),
            error_types::TOO_LONG
        );
        
        assert_eq!(
            categorize_error(&ValidationError::InvalidValue {
                field: field_types::PASSWORD.to_string(), // ✅ FIXED: Added missing dot
                message: "Too weak".to_string(),
                span: SpanTrace::capture(),
            }),
            error_types::WEAK_PASSWORD
        );
        
        assert_eq!(
            categorize_error(&ValidationError::InvalidValue {
                field: field_types::EMAIL.to_string(),
                message: "Bad format".to_string(),
                span: SpanTrace::capture(),
            }),
            error_types::INVALID_FORMAT
        );
        
        assert_eq!(
            categorize_error(&ValidationError::PasswordHash {
                message: "Hash failed".to_string(),
                span: SpanTrace::capture(),
            }),
            error_types::HASH_ERROR
        );
    }

    #[test]
    fn test_business_helper_consistency() {
        init_validation_metrics();
        
        // Test used field-specific business helpers
        record_username_success();
        record_username_failure(error_types::TOO_LONG);
        
        // Test direct calls with other field types  
        record_validation_success(field_types::EMAIL);
        record_validation_failure_with_type(field_types::EMAIL, error_types::INVALID_FORMAT);
        record_validation_success(field_types::PASSWORD);
        record_validation_failure_with_type(field_types::PASSWORD, error_types::WEAK_PASSWORD);
        
        // Verify operations were recorded
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::SUCCESS]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::FAILURE]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::EMAIL, results::SUCCESS]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::EMAIL, results::FAILURE]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::PASSWORD, results::SUCCESS]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::PASSWORD, results::FAILURE]).get(), 1.0);
        
        // Verify detailed failures were recorded
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::USERNAME, error_types::TOO_LONG]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::PASSWORD, error_types::WEAK_PASSWORD]).get(), 1.0);
    }

    #[test]
    fn test_comprehensive_validation_patterns() {
        init_validation_metrics();
        
        // Test all field types and error types
        record_validation_operation(field_types::USERNAME, results::SUCCESS);
        record_validation_operation(field_types::EMAIL, results::SUCCESS);
        record_validation_operation(field_types::PASSWORD, results::SUCCESS);
        
        record_validation_failure_with_type(field_types::USERNAME, error_types::MISSING);
        record_validation_failure_with_type(field_types::USERNAME, error_types::TOO_LONG);
        record_validation_failure_with_type(field_types::EMAIL, error_types::INVALID_FORMAT);
        record_validation_failure_with_type(field_types::PASSWORD, error_types::WEAK_PASSWORD);
        record_validation_failure_with_type(field_types::PASSWORD, error_types::HASH_ERROR);
        
        // Verify all constants work correctly
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::SUCCESS]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::EMAIL, results::SUCCESS]).get(), 1.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::PASSWORD, results::SUCCESS]).get(), 1.0);
        
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::USERNAME, error_types::MISSING]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::USERNAME, error_types::TOO_LONG]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::PASSWORD, error_types::WEAK_PASSWORD]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::PASSWORD, error_types::HASH_ERROR]).get(), 1.0);
    }

    #[test]
    fn test_production_validation_patterns() {
        init_validation_metrics();
        
        // Simulate realistic production patterns
        
        // Normal successful validations (majority of operations)
        for _ in 0..20 {
            record_username_success();
        }
        for _ in 0..15 {
            record_validation_success(field_types::EMAIL);
        }
        for _ in 0..10 {
            record_validation_success(field_types::PASSWORD);
        }
        
        // Some failures with specific causes
        record_username_failure(error_types::TOO_LONG);
        record_validation_failure_with_type(field_types::EMAIL, error_types::INVALID_FORMAT);
        record_validation_failure_with_type(field_types::PASSWORD, error_types::WEAK_PASSWORD);
        record_validation_failure_with_type(field_types::PASSWORD, error_types::WEAK_PASSWORD); // Common issue
        
        // Verify realistic ratios
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::SUCCESS]).get(), 20.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::EMAIL, results::SUCCESS]).get(), 15.0);
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::PASSWORD, results::SUCCESS]).get(), 10.0);
        
        // Verify failure patterns
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::USERNAME, error_types::TOO_LONG]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::EMAIL, error_types::INVALID_FORMAT]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::PASSWORD, error_types::WEAK_PASSWORD]).get(), 2.0);
    }

    #[test]
    fn test_edge_cases_and_validation() {
        init_validation_metrics();
        
        // Test edge cases that should be handled gracefully by core infrastructure
        record_validation_operation("", ""); // Empty strings
        record_validation_failure_detailed("", "");
        
        // These should not panic due to core infrastructure protection
        // Just verify we can continue operating
        record_username_success();
        assert!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::SUCCESS]).get() >= 1.0);
    }

    #[test]
    fn test_type_safety_constants() {
        init_validation_metrics();
        
        // Verify all constants are valid and type-safe
        assert_eq!(field_types::USERNAME, "username");
        assert_eq!(field_types::EMAIL, "email");
        assert_eq!(field_types::PASSWORD, "password");
        
        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");
        
        assert_eq!(error_types::MISSING, "missing");
        assert_eq!(error_types::TOO_LONG, "too_long");
        assert_eq!(error_types::INVALID_FORMAT, "invalid_format");
        assert_eq!(error_types::WEAK_PASSWORD, "weak_password");
        assert_eq!(error_types::HASH_ERROR, "hash_error");
        
        // Use constants in actual operations to verify they work
        record_validation_operation(field_types::USERNAME, results::SUCCESS);
        record_validation_failure_detailed(field_types::PASSWORD, error_types::WEAK_PASSWORD);
        
        assert_eq!(VALIDATION_OPERATIONS.with_label_values(&[field_types::USERNAME, results::SUCCESS]).get(), 1.0);
        assert_eq!(VALIDATION_FAILURES.with_label_values(&[field_types::PASSWORD, error_types::WEAK_PASSWORD]).get(), 1.0);
    }
}