//! Next-generation metrics system for BuildHub authentication service.
//!
//! This module implements a focused, hierarchical metrics system designed for:
//! - **Business value** - metrics that answer important questions
//! - **Security insights** - detection of attack patterns
//! - **Operational clarity** - clear signal vs noise separation
//! - **Performance monitoring** - actionable performance data
//!
//! # Design Philosophy
//!
//! Unlike traditional metrics that track every possible event, this system focuses on:
//! 1. **High-level success/failure rates** - business metrics
//! 2. **Categorized failures** - actionable failure analysis  
//! 3. **Security event detection** - attack pattern recognition
//! 4. **Performance timing** - latency and throughput insights
//!
//! # Validation Metrics Strategy
//!
//! ## Core Questions Answered:
//! - How often do validations succeed overall?
//! - Which fields cause most validation problems?
//! - Are we seeing attack patterns (DoS, injection)?
//! - Is validation performance acceptable?
//!
//! ## Metric Hierarchy:
//! ```
//! validation_attempts_total{field}                    <- All attempts
//! validation_failures_total{field, category}         <- Categorized failures
//! validation_duration_seconds{field}                 <- Performance timing
//! validation_attacks_total{field, attack_type}       <- Security events
//! ```
//!
//! ## Usage Example:
//! ```rust
//! use crate::utils::metrics_new::*;
//!
//! // Initialize early in main()
//! metrics_new::init();
//!
//! // In validation functions - use instrumentation wrapper
//! fn validate_email(email: &str) -> Result<(), AuthServiceError> {
//!     instrument_validation("email", || {
//!         // Your validation logic here
//!         if email.is_empty() {
//!             return Err(ValidationError::MissingField { ... });
//!         }
//!         // ... rest of validation
//!         Ok(())
//!     })
//! }
//! ```

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, Encoder, HistogramVec, TextEncoder,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tracing_error::SpanTrace;

use crate::utils::error_new::{AuthServiceError, ValidationError};
use crate::{log_debug, log_error, log_info, log_warn};

// =============================================================================
// DURATION BUCKETS
// =============================================================================

/// Fine-grained duration buckets for validation operations (in seconds).
///
/// Covers microsecond to millisecond operations, suitable for high-performance
/// validation operations that should complete very quickly.
const VALIDATION_DURATION_BUCKETS: &[f64] = &[
    0.0001, // 0.1ms - very fast validation
    0.0005, // 0.5ms - fast validation  
    0.001,  // 1ms - normal validation
    0.005,  // 5ms - slow validation
    0.01,   // 10ms - very slow validation
    0.05,   // 50ms - problematic validation
    0.1,    // 100ms - unacceptable validation
    0.5,    // 500ms - potential DoS
    1.0,    // 1s - definite problem
];

// =============================================================================
// VALIDATION METRICS
// =============================================================================

lazy_static! {
    /// Total validation attempts by field type.
    ///
    /// **Business Value:** Baseline metric for validation volume and success rates.
    ///
    /// # Labels
    /// * `field` - Field being validated ("username", "email", "password")
    ///
    /// # Queries
    /// ```promql
    /// # Validation volume per minute
    /// rate(validation_attempts_total[1m])
    ///
    /// # Success rate (attempts - failures)
    /// (rate(validation_attempts_total[5m]) - rate(validation_failures_total[5m])) 
    ///   / rate(validation_attempts_total[5m])
    /// ```
    pub static ref VALIDATION_ATTEMPTS: CounterVec = register_counter_vec!(
        "validation_attempts_total",
        "Total number of validation attempts by field type",
        &["field"]
    ).expect("Failed to register VALIDATION_ATTEMPTS");

    /// Validation failures categorized by field and failure type.
    ///
    /// **Business Value:** Identifies specific validation issues affecting users.
    ///
    /// # Labels
    /// * `field` - Field being validated ("username", "email", "password")
    /// * `category` - Failure category ("missing", "format", "length", "complexity")
    ///
    /// # Categories
    /// * `missing` - Required field not provided
    /// * `format` - Invalid format (regex mismatch, structure issues)
    /// * `length` - Length constraints violated (too short/long)
    /// * `complexity` - Complexity requirements not met (password strength)
    ///
    /// # Queries
    /// ```promql
    /// # Top failure categories
    /// topk(5, rate(validation_failures_total[1h]))
    ///
    /// # Field-specific failure rates
    /// rate(validation_failures_total{field="email"}[5m])
    ///
    /// # Failure rate by category
    /// sum(rate(validation_failures_total[5m])) by (category)
    /// ```
    pub static ref VALIDATION_FAILURES: CounterVec = register_counter_vec!(
        "validation_failures_total",
        "Validation failures categorized by field and failure type",
        &["field", "category"]
    ).expect("Failed to register VALIDATION_FAILURES");

    /// Time spent on validation operations by field type.
    ///
    /// **Performance Value:** Identifies validation bottlenecks and performance issues.
    ///
    /// # Labels
    /// * `field` - Field being validated ("username", "email", "password")
    ///
    /// # Queries
    /// ```promql
    /// # 95th percentile validation time
    /// histogram_quantile(0.95, rate(validation_duration_seconds_bucket[5m]))
    ///
    /// # Slow validations (>10ms)
    /// increase(validation_duration_seconds_bucket{le="0.01"}[5m])
    ///
    /// # Average validation time by field
    /// rate(validation_duration_seconds_sum[5m]) / rate(validation_duration_seconds_count[5m])
    /// ```
    pub static ref VALIDATION_DURATION: HistogramVec = register_histogram_vec!(
        "validation_duration_seconds",
        "Time spent on validation operations in seconds by field type",
        &["field"],
        VALIDATION_DURATION_BUCKETS.to_vec()
    ).expect("Failed to register VALIDATION_DURATION");

    /// Security events detected during validation.
    ///
    /// **Security Value:** Early detection of potential attacks and abuse patterns.
    ///
    /// # Labels
    /// * `field` - Field where attack was detected ("username", "email", "password")
    /// * `attack_type` - Type of potential attack ("dos_attempt", "injection_attempt", "malformed_input")
    ///
    /// # Attack Types
    /// * `dos_attempt` - Unusually long inputs that might cause DoS
    /// * `injection_attempt` - Inputs with suspicious characters (SQL, XSS, etc.)
    /// * `malformed_input` - Deliberately malformed data to test boundaries
    ///
    /// # Queries
    /// ```promql
    /// # Attack detection rate
    /// rate(validation_attacks_total[5m])
    ///
    /// # Top attack types
    /// topk(3, rate(validation_attacks_total[1h]))
    ///
    /// # Field-specific attack patterns
    /// sum(rate(validation_attacks_total{field="username"}[1h])) by (attack_type)
    /// ```
    pub static ref VALIDATION_ATTACKS: CounterVec = register_counter_vec!(
        "validation_attacks_total",
        "Potential attack patterns detected during validation",
        &["field", "attack_type"]
    ).expect("Failed to register VALIDATION_ATTACKS");
}

// =============================================================================
// VALIDATION INSTRUMENTATION
// =============================================================================

/// Instrumentation wrapper for validation operations.
///
/// Provides automatic metrics collection, timing, error categorization,
/// and security event detection for validation functions.
///
/// # Design
/// - **Zero-overhead success path** - minimal impact when validation succeeds
/// - **Automatic categorization** - errors are categorized without manual work
/// - **Security detection** - potential attacks are automatically flagged
/// - **Comprehensive logging** - appropriate log levels for different outcomes
///
/// # Arguments
/// * `field` - Name of the field being validated (e.g., "email", "username")
/// * `validation_fn` - Closure containing the validation logic
///
/// # Returns
/// Result from the validation function, with all metrics automatically recorded.
///
/// # Example
/// ```rust
/// pub fn validate_email(email: &str) -> Result<(), AuthServiceError> {
///     instrument_validation("email", || {
///         if email.is_empty() {
///             return Err(ValidationError::MissingField {
///                 field: "email".to_string(),
///                 span: SpanTrace::capture(),
///             });
///         }
///         
///         if !EMAIL_REGEX.is_match(email) {
///             return Err(ValidationError::InvalidValue {
///                 field: "email".to_string(),
///                 message: "Invalid email format".to_string(),
///                 span: SpanTrace::capture(),
///             });
///         }
///         
///         Ok(())
///     })
/// }
/// ```
pub fn instrument_validation<F>(field: &str, validation_fn: F) -> Result<(), AuthServiceError>
where
    F: FnOnce() -> Result<(), ValidationError>,
{
    // 📊 METRIC: Count validation attempt
    VALIDATION_ATTEMPTS.with_label_values(&[field]).inc();

    // 🕐 Start timing
    let timer = VALIDATION_DURATION.with_label_values(&[field]).start_timer();
    let start_time = Instant::now();

    // 🔍 DEBUG: Log validation start (low noise)
    log_debug!(
        "Validation",
        &format!("Starting {} validation", field),
        "validation_start"
    );

    // Execute validation and convert to AuthServiceError
    let result = validation_fn().map_err(AuthServiceError::from);

    // ⏱️ Record timing regardless of outcome
    let duration = start_time.elapsed();
    timer.observe_duration();

    // 📊 Handle result with appropriate metrics and logging
    match &result {
        Ok(_) => {
            // ✅ SUCCESS: Log with performance info (minimal)
            log_info!(
                "Validation",
                &format!(
                    "{} validation succeeded in {:.2}ms",
                    field,
                    duration.as_millis()
                ),
                "validation_success"
            );
            // No failure metrics to record - success is measured by absence of failures
        }

        Err(AuthServiceError::Validation(validation_err)) => {
            // ❌ FAILURE: Categorize and record detailed metrics
            let (category, attack_type) = categorize_validation_error(validation_err);

            // 📊 METRIC: Record categorized failure
            VALIDATION_FAILURES
                .with_label_values(&[field, category])
                .inc();

            // 🚨 SECURITY: Record potential attacks
            if let Some(attack) = attack_type {
                VALIDATION_ATTACKS
                    .with_label_values(&[field, attack])
                    .inc();

                // 🚨 ERROR: Log security events for immediate attention
                log_error!(
                    "Security",
                    &format!(
                        "Potential {} attack detected in {} validation: {} (duration: {:.2}ms)",
                        attack, field, validation_err, duration.as_millis()
                    ),
                    "security_event"
                );
            } else {
                // ⚠️ WARN: Log normal validation failures
                log_warn!(
                    "Validation",
                    &format!(
                        "{} validation failed ({}): {} (duration: {:.2}ms)",
                        field, category, validation_err, duration.as_millis()
                    ),
                    "validation_failed"
                );
            }
        }

        Err(other_err) => {
            // 🔥 ERROR: Unexpected error type in validation
            log_error!(
                "Validation",
                &format!(
                    "Unexpected error type in {} validation: {} (duration: {:.2}ms)",
                    field, other_err, duration.as_millis()
                ),
                "validation_error"
            );
        }
    }

    result
}

/// Categorizes validation errors for metrics and security detection.
///
/// Analyzes validation errors to determine:
/// 1. **Category** - For failure metrics (business intelligence)
/// 2. **Attack Type** - For security metrics (threat detection)
///
/// # Arguments
/// * `err` - The validation error to categorize
///
/// # Returns
/// * `(category, attack_type)` - Category for metrics, optional attack type for security
///
/// # Categories
/// * `missing` - Required data not provided (normal user error)
/// * `format` - Invalid format or structure (normal user error)
/// * `length` - Length constraints violated (might be attack)
/// * `complexity` - Complexity requirements not met (normal for passwords)
///
/// # Attack Types
/// * `dos_attempt` - Unusually long inputs (potential DoS)
/// * `injection_attempt` - Suspicious characters (potential injection)
/// * `malformed_input` - Deliberately broken format (testing boundaries)
fn categorize_validation_error(err: &ValidationError) -> (&'static str, Option<&'static str>) {
    match err {
        ValidationError::MissingField { .. } => {
            // Missing fields are normal user errors
            ("missing", None)
        }

        ValidationError::TooLong { field, max_length, .. } => {
            // Long inputs are categorized as length issues, but might be DoS attacks
            if *max_length > 0 && *max_length < 1000 {
                // Reasonable length limits - likely legitimate user error
                ("length", None)
            } else {
                // Very long inputs might be DoS attempts
                ("length", Some("dos_attempt"))
            }
        }

        ValidationError::InvalidValue { field, message, .. } => {
            // Analyze the specific validation failure for attack patterns
            match field.as_str() {
                "username" => {
                    if message.contains("characters") || message.contains("invalid") {
                        // Username with weird characters might be injection attempt
                        if message.contains("special") || message.contains("symbol") {
                            ("format", Some("injection_attempt"))
                        } else {
                            ("format", None)
                        }
                    } else {
                        ("format", None)
                    }
                }

                "email" => {
                    if message.contains("@") || message.contains("domain") || message.contains("TLD") {
                        // Normal email format issues
                        ("format", None)
                    } else if message.contains("symbol") || message.contains("exactly one") {
                        // Weird malformed email structure might be testing boundaries
                        ("format", Some("malformed_input"))
                    } else {
                        ("format", None)
                    }
                }

                "password" => {
                    if message.contains("special") || message.contains("letter") || message.contains("number") {
                        // Normal password complexity failures
                        ("complexity", None)
                    } else if message.contains("length") {
                        // Password length issues
                        ("length", None)
                    } else {
                        // Unexpected password validation failure
                        ("format", Some("malformed_input"))
                    }
                }

                _ => {
                    // Unknown field - treat as format issue, potentially suspicious
                    ("format", Some("malformed_input"))
                }
            }
        }
    }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/// Track if metrics have been initialized.
static METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the new metrics system.
///
/// This function is idempotent and thread-safe. It should be called early
/// in application startup to ensure all metrics are properly registered.
///
/// # Thread Safety
/// Multiple calls are safe and will only initialize metrics once.
///
/// # Example
/// ```rust
/// fn main() {
///     // Initialize new metrics system
///     metrics_new::init();
///     
///     // Start application...
/// }
/// ```
pub fn init() {
    // Only initialize once using atomic compare-and-swap
    if METRICS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Touch all lazy_static metrics to ensure they're registered
    let _ = &VALIDATION_ATTEMPTS;
    let _ = &VALIDATION_FAILURES;
    let _ = &VALIDATION_DURATION;
    let _ = &VALIDATION_ATTACKS;

    log_info!(
        "Metrics",
        "New metrics system initialized - validation metrics ready",
        "metrics_init"
    );
}

/// Gather validation metrics in Prometheus text format.
///
/// Returns only the validation-related metrics from the new system.
/// This can be used for debugging or specialized monitoring endpoints.
///
/// # Returns
/// String containing validation metrics in Prometheus text format.
pub fn gather_validation_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::with_capacity(1024);

    // Filter for validation metrics only
    let validation_families: Vec<_> = metric_families
        .into_iter()
        .filter(|family| {
            family.get_name().starts_with("validation_")
        })
        .collect();

    // Encode filtered metrics
    if let Err(e) = encoder.encode(&validation_families, &mut buffer) {
        log_error!("Metrics", &format!("Error encoding validation metrics: {}", e), "metrics_error");
        return String::from("Error encoding validation metrics");
    }

    // Convert to string
    match String::from_utf8(buffer) {
        Ok(output) => output,
        Err(e) => {
            log_error!("Metrics", &format!("Error converting validation metrics to UTF-8: {}", e), "metrics_error");
            String::from("Error gathering validation metrics")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        // Reset for this test
        METRICS_INITIALIZED.store(false, Ordering::SeqCst);
        
        // Initialize should work
        init();
        
        // Should be marked as initialized
        assert!(METRICS_INITIALIZED.load(Ordering::SeqCst));
        
        // Multiple calls should be safe
        init();
        init();
    }

    #[test]
    fn test_validation_instrumentation_success() {
        init();
        
        let initial_attempts = VALIDATION_ATTEMPTS.with_label_values(&["test_field"]).get();
        let initial_failures = VALIDATION_FAILURES.with_label_values(&["test_field", "format"]).get();
        
        // Successful validation
        let result = instrument_validation("test_field", || Ok(()));
        
        assert!(result.is_ok());
        assert_eq!(
            VALIDATION_ATTEMPTS.with_label_values(&["test_field"]).get(),
            initial_attempts + 1.0
        );
        // Failures should not increment on success
        assert_eq!(
            VALIDATION_FAILURES.with_label_values(&["test_field", "format"]).get(),
            initial_failures
        );
    }

    #[test]
    fn test_validation_instrumentation_failure() {
        init();
        
        let initial_attempts = VALIDATION_ATTEMPTS.with_label_values(&["test_field"]).get();
        let initial_failures = VALIDATION_FAILURES.with_label_values(&["test_field", "missing"]).get();
        
        // Failed validation
        let result = instrument_validation("test_field", || {
            Err(ValidationError::MissingField {
                field: "test_field".to_string(),
                span: SpanTrace::capture(),
            })
        });
        
        assert!(result.is_err());
        assert_eq!(
            VALIDATION_ATTEMPTS.with_label_values(&["test_field"]).get(),
            initial_attempts + 1.0
        );
        assert_eq!(
            VALIDATION_FAILURES.with_label_values(&["test_field", "missing"]).get(),
            initial_failures + 1.0
        );
    }

    #[test]
    fn test_error_categorization() {
        // Test missing field categorization
        let missing_err = ValidationError::MissingField {
            field: "email".to_string(),
            span: SpanTrace::capture(),
        };
        let (category, attack) = categorize_validation_error(&missing_err);
        assert_eq!(category, "missing");
        assert_eq!(attack, None);

        // Test potential DoS attempt
        let dos_err = ValidationError::TooLong {
            field: "username".to_string(),
            max_length: 50000, // Unreasonably large
            span: SpanTrace::capture(),
        };
        let (category, attack) = categorize_validation_error(&dos_err);
        assert_eq!(category, "length");
        assert_eq!(attack, Some("dos_attempt"));

        // Test normal length violation
        let normal_length_err = ValidationError::TooLong {
            field: "username".to_string(),
            max_length: 50, // Reasonable limit
            span: SpanTrace::capture(),
        };
        let (category, attack) = categorize_validation_error(&normal_length_err);
        assert_eq!(category, "length");
        assert_eq!(attack, None);
    }

    #[test]
    fn test_attack_detection() {
        init();
        
        let initial_attacks = VALIDATION_ATTACKS.with_label_values(&["username", "injection_attempt"]).get();
        
        // Simulate potential injection attempt
        let result = instrument_validation("username", || {
            Err(ValidationError::InvalidValue {
                field: "username".to_string(),
                message: "Invalid special characters detected".to_string(),
                span: SpanTrace::capture(),
            })
        });
        
        assert!(result.is_err());
        assert_eq!(
            VALIDATION_ATTACKS.with_label_values(&["username", "injection_attempt"]).get(),
            initial_attacks + 1.0
        );
    }

    #[test]
    fn test_gather_validation_metrics() {
        init();
        
        // Generate some metrics
        let _ = instrument_validation("test", || Ok(()));
        
        let output = gather_validation_metrics();
        
        assert!(!output.is_empty());
        assert!(output.contains("validation_attempts_total"));
        assert!(output.contains("validation_duration_seconds"));
    }
}