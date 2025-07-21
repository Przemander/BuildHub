//! # JWT Metrics - Production-Grade Authentication Monitoring
//!
//! Essential JWT metrics focused on real production monitoring needs with full
//! integration to the standardized core metrics infrastructure.
//!
//! ## Design Philosophy
//! - **Alert-Driven**: Only metrics that trigger actual production alerts
//! - **Business Focused**: Metrics that help understand system health and user behavior
//! - **Security Conscious**: Detection of attacks and abuse patterns
//! - **Performance SLA**: Clear latency targets for authentication operations
//! - **Low Cardinality**: Controlled label values to prevent metric explosion
//! - **Core Integration**: Uses standardized infrastructure for consistency
//!
//! ## Core Metrics (3 Essential)
//! - `jwt_operations_total`: Core business operations with success/failure tracking
//! - `jwt_validation_failures_total`: Security-focused detailed failure tracking
//! - `jwt_operation_duration_seconds`: Performance SLA monitoring
//!
//! ## Production Alerts
//! - Auth system down (high failure rates)
//! - Security events (invalid signatures, revoked token usage)
//! - Performance SLA breaches (latency targets)
//! - Unusual activity patterns (login storms, attack patterns)

use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::log_info;

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec, create_histogram_vec,
    observe_counter_vec,
    LATENCY_BUCKETS_FAST,
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: JWT operations with success/failure tracking
    ///
    /// Essential for monitoring authentication system health and detecting outages.
    /// Covers the complete JWT lifecycle with simple, actionable labels.
    ///
    /// # Labels
    /// * `operation`: Core JWT operations
    ///   - `"generate"`: Token creation (login, token refresh)
    ///   - `"validate"`: Token verification (API authentication)  
    ///   - `"revoke"`: Token invalidation (logout, security revocation)
    /// * `result`: Simple binary outcome
    ///   - `"success"`: Operation completed successfully
    ///   - `"failure"`: Operation failed (any reason)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Auth system down
    /// - alert: AuthSystemDown
    ///   expr: rate(jwt_operations_total{result="failure"}[5m]) / rate(jwt_operations_total[5m]) > 0.1
    ///   severity: critical
    ///
    /// # Warning: High failure rate
    /// - alert: AuthHighFailureRate  
    ///   expr: rate(jwt_operations_total{result="failure"}[5m]) > 5
    ///   severity: warning
    ///
    /// # Info: Login storm detection
    /// - alert: LoginStorm
    ///   expr: rate(jwt_operations_total{operation="generate",result="success"}[5m]) > 100
    ///   severity: info
    /// ```
    ///
    /// # Business Dashboards
    /// ```promql
    /// # Daily active users (approximate)
    /// sum(increase(jwt_operations_total{operation="generate",result="success"}[24h]))
    ///
    /// # Authentication rate
    /// sum(rate(jwt_operations_total{operation="validate",result="success"}[5m]))
    ///
    /// # System health (success rate)
    /// rate(jwt_operations_total{result="success"}[5m]) / rate(jwt_operations_total[5m])
    /// ```
    pub static ref JWT_OPERATIONS: CounterVec = create_counter_vec(
        "jwt_operations_total",
        "JWT operations by type and result",
        &["operation", "result"]
    ).expect("Failed to create JWT_OPERATIONS metric");

    /// **Security Metric**: Detailed validation failure tracking
    ///
    /// Security-focused metric for detecting attacks, abuse patterns, and debugging
    /// authentication issues. Provides granular failure reasons for incident response.
    ///
    /// # Labels  
    /// * `failure_type`: Specific failure reason for security analysis
    ///   - `"expired"`: Token past expiration (normal user behavior)
    ///   - `"invalid_signature"`: Signature verification failed (potential attack)
    ///   - `"invalid_format"`: Malformed token structure (client issues)
    ///   - `"revoked"`: Token in blacklist (security incident or logout)
    ///   - `"invalid_iat"`: Future-dated token (clock skew or tampering)
    ///   - `"redis_failure"`: Revocation check failed (infrastructure issue)
    ///
    /// # Security Alerts
    /// ```yaml
    /// # Critical: Attack detected
    /// - alert: JWTAttackDetected
    ///   expr: rate(jwt_validation_failures_total{failure_type="invalid_signature"}[5m]) > 10
    ///   severity: critical
    ///   annotations:
    ///     summary: "JWT signature attack: {{ $value }} failures/sec"
    ///
    /// # Warning: Compromised tokens in circulation  
    /// - alert: RevokedTokenUsage
    ///   expr: rate(jwt_validation_failures_total{failure_type="revoked"}[5m]) > 1
    ///   severity: warning
    ///   annotations:
    ///     summary: "{{ $value }} revoked tokens used/sec"
    ///
    /// # Warning: Clock skew or tampering
    /// - alert: ClockSkewDetected
    ///   expr: rate(jwt_validation_failures_total{failure_type="invalid_iat"}[5m]) > 0.1
    ///   severity: warning
    ///
    /// # Info: Infrastructure issue
    /// - alert: RedisConnectivityIssue
    ///   expr: rate(jwt_validation_failures_total{failure_type="redis_failure"}[5m]) > 1
    ///   severity: info
    /// ```
    ///
    /// # Security Dashboards
    /// ```promql
    /// # Security events rate
    /// sum by (failure_type) (rate(jwt_validation_failures_total{failure_type=~"invalid_signature|revoked|invalid_iat"}[5m]))
    ///
    /// # Normal vs abnormal failures
    /// rate(jwt_validation_failures_total{failure_type="expired"}[5m]) vs 
    /// rate(jwt_validation_failures_total{failure_type!="expired"}[5m])
    /// ```
    pub static ref JWT_VALIDATION_FAILURES: CounterVec = create_counter_vec(
        "jwt_validation_failures_total",
        "JWT validation failures by failure type",
        &["failure_type"]
    ).expect("Failed to create JWT_VALIDATION_FAILURES metric");

    /// **Performance Metric**: JWT operation latency for SLA monitoring
    ///
    /// Performance monitoring for authentication SLA compliance and capacity planning.
    /// Essential for detecting performance regressions and infrastructure issues.
    ///
    /// # Labels
    /// * `operation`: Operation being timed
    ///   - `"generate"`: Token creation (cryptographic signing)
    ///   - `"validate"`: Token validation (crypto + Redis lookup)
    ///   - `"revoke"`: Token revocation (Redis write)
    ///
    /// # SLA Targets (Production)
    /// - **Generation**: p95 < 5ms, p99 < 10ms (pure cryptographic operation)
    /// - **Validation**: p95 < 25ms, p99 < 50ms (crypto + Redis roundtrip)
    /// - **Revocation**: p95 < 15ms, p99 < 25ms (Redis write operation)
    ///
    /// # Performance Alerts
    /// ```yaml
    /// # Critical: SLA breach
    /// - alert: JWTLatencyHigh
    ///   expr: histogram_quantile(0.95, rate(jwt_operation_duration_seconds_bucket[5m])) > 0.050
    ///   severity: critical
    ///   annotations:
    ///     summary: "JWT p95 latency: {{ $value }}s (SLA: <50ms)"
    ///
    /// # Warning: Performance degradation
    /// - alert: JWTLatencyWarning
    ///   expr: histogram_quantile(0.95, rate(jwt_operation_duration_seconds_bucket[5m])) > 0.025
    ///   severity: warning
    ///
    /// # Critical: Very slow operations
    /// - alert: JWTVerySlowOperations
    ///   expr: histogram_quantile(0.99, rate(jwt_operation_duration_seconds_bucket[5m])) > 0.100
    ///   severity: critical
    /// ```
    ///
    /// # Performance Dashboards
    /// ```promql
    /// # Latency percentiles by operation
    /// histogram_quantile(0.95, sum(rate(jwt_operation_duration_seconds_bucket[5m])) by (le, operation))
    ///
    /// # Throughput vs latency correlation
    /// rate(jwt_operation_duration_seconds_count[5m]) vs 
    /// histogram_quantile(0.95, rate(jwt_operation_duration_seconds_bucket[5m]))
    ///
    /// # Week-over-week performance comparison
    /// histogram_quantile(0.95, rate(jwt_operation_duration_seconds_bucket[5m])) vs
    /// histogram_quantile(0.95, rate(jwt_operation_duration_seconds_bucket[5m] offset 7d))
    /// ```
    pub static ref JWT_OPERATION_DURATION: HistogramVec = create_histogram_vec(
        "jwt_operation_duration_seconds",
        "JWT operation duration by operation type",
        &["operation"],
        LATENCY_BUCKETS_FAST // Using standardized buckets for crypto operations
    ).expect("Failed to create JWT_OPERATION_DURATION metric");
}

static JWT_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn init_jwt_metrics() {
    if JWT_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&JWT_OPERATIONS);
    lazy_static::initialize(&JWT_VALIDATION_FAILURES);
    lazy_static::initialize(&JWT_OPERATION_DURATION);

    log_info!("Metrics", "JWT metrics initialized (enhanced production version with core integration)", "jwt_metrics_init");
}

// =============================================================================
// CORE API (Using standardized observation functions)
// =============================================================================

/// Records a successful JWT operation with enhanced error handling
pub fn record_operation_success(operation: &str) {
    observe_counter_vec(
        &JWT_OPERATIONS,
        "jwt_operations_total",
        &[operation, "success"]
    );
}

/// Records a failed JWT operation with enhanced error handling
pub fn record_operation_failure(operation: &str) {
    observe_counter_vec(
        &JWT_OPERATIONS,
        "jwt_operations_total",
        &[operation, "failure"]
    );
}

/// Records a specific validation failure for security monitoring with enhanced error handling
pub fn record_validation_failure(failure_type: &str) {
    observe_counter_vec(
        &JWT_VALIDATION_FAILURES,
        "jwt_validation_failures_total",
        &[failure_type]
    );
}

/// Creates a timer for measuring JWT operation duration
pub fn time_operation(operation: &str) -> prometheus::HistogramTimer {
    // Note: Timers are automatically observed when dropped
    JWT_OPERATION_DURATION
        .with_label_values(&[operation])
        .start_timer()
}

// =============================================================================
// CONSTANTS (Type-safe values for consistent labeling)
// =============================================================================

pub mod operations {
    pub const GENERATE: &str = "generate";
    pub const VALIDATE: &str = "validate";
    pub const REVOKE: &str = "revoke";
}

pub mod failure_types {
    pub const EXPIRED: &str = "expired";
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    pub const INVALID_FORMAT: &str = "invalid_format";
    pub const REVOKED: &str = "revoked";
    pub const INVALID_IAT: &str = "invalid_iat";
    pub const REDIS_FAILURE: &str = "redis_failure";
}

// =============================================================================
// HELPER MODULES (Enhanced with comprehensive tracking)
// =============================================================================

/// Generation operation helpers
pub mod generate {
    use super::*;
    
    pub fn record_success() {
        record_operation_success(operations::GENERATE);
    }
    
    pub fn record_failure() {
        record_operation_failure(operations::GENERATE);
    }
    
    pub fn time() -> prometheus::HistogramTimer {
        time_operation(operations::GENERATE)
    }
}

/// Validation operation helpers
pub mod validate {
    use super::*;
    
    pub fn record_success() {
        record_operation_success(operations::VALIDATE);
    }
    
    pub fn record_failure() {
        record_operation_failure(operations::VALIDATE);
    }
    
    pub fn time() -> prometheus::HistogramTimer {
        time_operation(operations::VALIDATE)
    }
    
    /// Record specific validation failures
    pub fn record_expired() {
        record_validation_failure(failure_types::EXPIRED);
        record_failure();
    }
    
    pub fn record_invalid_signature() {
        record_validation_failure(failure_types::INVALID_SIGNATURE);
        record_failure();
    }
    
    pub fn record_invalid_format() {
        record_validation_failure(failure_types::INVALID_FORMAT);
        record_failure();
    }
    
    pub fn record_revoked() {
        record_validation_failure(failure_types::REVOKED);
        record_failure();
    }
    
    pub fn record_invalid_iat() {
        record_validation_failure(failure_types::INVALID_IAT);
        record_failure();
    }
    
    pub fn record_redis_failure() {
        record_validation_failure(failure_types::REDIS_FAILURE);
        record_failure();
    }
}

/// Revocation operation helpers
pub mod revoke {
    use super::*;
    
    pub fn record_success() {
        record_operation_success(operations::REVOKE);
    }
    
    pub fn record_failure() {
        record_operation_failure(operations::REVOKE);
    }
    
    pub fn time() -> prometheus::HistogramTimer {
        time_operation(operations::REVOKE)
    }
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_jwt_metrics_initialization() {
        init_jwt_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(JWT_OPERATIONS.with_label_values(&[operations::GENERATE, "success"]).get(), 0.0);
        assert_eq!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::EXPIRED]).get(), 0.0);
        assert_eq!(JWT_OPERATION_DURATION.with_label_values(&[operations::VALIDATE]).get_sample_count(), 0);
    }

    #[test]
    fn test_core_operations_with_standardized_functions() {
        init_jwt_metrics();
        
        // Test core operations with enhanced error handling
        let initial_ops = JWT_OPERATIONS.with_label_values(&[operations::GENERATE, "success"]).get();
        record_operation_success(operations::GENERATE);
        let after_ops = JWT_OPERATIONS.with_label_values(&[operations::GENERATE, "success"]).get();
        
        assert_eq!(after_ops, initial_ops + 1.0);
    }

    #[test]
    fn test_validation_failure_tracking_with_enhanced_error_handling() {
        init_jwt_metrics();
        
        let initial_failures = JWT_VALIDATION_FAILURES
            .with_label_values(&[failure_types::INVALID_SIGNATURE])
            .get();
        
        record_validation_failure(failure_types::INVALID_SIGNATURE);
        
        assert_eq!(
            JWT_VALIDATION_FAILURES
                .with_label_values(&[failure_types::INVALID_SIGNATURE])
                .get(),
            initial_failures + 1.0
        );
    }

    #[test]
    fn test_operation_timing_with_fast_buckets() {
        init_jwt_metrics();
        
        let initial_count = JWT_OPERATION_DURATION
            .with_label_values(&[operations::VALIDATE])
            .get_sample_count();
        
        // Test timing with auto-drop
        let timer = time_operation(operations::VALIDATE);
        std::thread::sleep(Duration::from_millis(1));
        drop(timer); // Timer automatically observed when dropped
        
        assert_eq!(
            JWT_OPERATION_DURATION
                .with_label_values(&[operations::VALIDATE])
                .get_sample_count(),
            initial_count + 1
        );
    }

    #[test]
    fn test_helper_modules() {
        init_jwt_metrics();
        
        // Test generate helpers
        generate::record_success();
        assert!(JWT_OPERATIONS.with_label_values(&[operations::GENERATE, "success"]).get() >= 1.0);
        
        // Test validate helpers with specific failures
        validate::record_expired();
        assert!(JWT_OPERATIONS.with_label_values(&[operations::VALIDATE, "failure"]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::EXPIRED]).get() >= 1.0);
        
        validate::record_invalid_signature();
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::INVALID_SIGNATURE]).get() >= 1.0);
        
        // Test revoke helpers
        revoke::record_success();
        assert!(JWT_OPERATIONS.with_label_values(&[operations::REVOKE, "success"]).get() >= 1.0);
    }

    #[test]
    fn test_timer_helpers() {
        init_jwt_metrics();
        
        // Test helper timer functions
        let gen_timer = generate::time();
        drop(gen_timer);
        
        let val_timer = validate::time();
        drop(val_timer);
        
        let rev_timer = revoke::time();
        drop(rev_timer);
        
        // Verify timers were recorded
        assert!(JWT_OPERATION_DURATION.with_label_values(&[operations::GENERATE]).get_sample_count() >= 1);
        assert!(JWT_OPERATION_DURATION.with_label_values(&[operations::VALIDATE]).get_sample_count() >= 1);
        assert!(JWT_OPERATION_DURATION.with_label_values(&[operations::REVOKE]).get_sample_count() >= 1);
    }

    #[test]
    fn test_comprehensive_validation_failures() {
        init_jwt_metrics();
        
        // Test all validation failure types
        validate::record_expired();
        validate::record_invalid_signature();
        validate::record_invalid_format();
        validate::record_revoked();
        validate::record_invalid_iat();
        validate::record_redis_failure();
        
        // Verify all failure types are recorded
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::EXPIRED]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::INVALID_SIGNATURE]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::INVALID_FORMAT]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::REVOKED]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::INVALID_IAT]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::REDIS_FAILURE]).get() >= 1.0);
        
        // Verify that each validation failure also records general operation failure
        assert!(JWT_OPERATIONS.with_label_values(&[operations::VALIDATE, "failure"]).get() >= 6.0);
    }

    #[test]
    fn test_production_usage_pattern() {
        init_jwt_metrics();
        
        // Test the actual pattern used in production code
        let timer = validate::time();
        
        // Simulate validation process
        std::thread::sleep(Duration::from_millis(1));
        
        // Different outcomes
        validate::record_success();
        drop(timer);
        
        // Test failure case
        let timer2 = validate::time();
        validate::record_expired();
        drop(timer2);
        
        // Verify both success and failure paths work
        assert!(JWT_OPERATIONS.with_label_values(&[operations::VALIDATE, "success"]).get() >= 1.0);
        assert!(JWT_OPERATIONS.with_label_values(&[operations::VALIDATE, "failure"]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::EXPIRED]).get() >= 1.0);
        assert!(JWT_OPERATION_DURATION.with_label_values(&[operations::VALIDATE]).get_sample_count() >= 2);
    }

    #[test]
    fn test_constants_usage() {
        init_jwt_metrics();
        
        // Test using constants for type safety
        record_operation_success(operations::GENERATE);
        record_operation_failure(operations::VALIDATE);
        record_validation_failure(failure_types::INVALID_SIGNATURE);
        
        assert!(JWT_OPERATIONS.with_label_values(&[operations::GENERATE, "success"]).get() >= 1.0);
        assert!(JWT_OPERATIONS.with_label_values(&[operations::VALIDATE, "failure"]).get() >= 1.0);
        assert!(JWT_VALIDATION_FAILURES.with_label_values(&[failure_types::INVALID_SIGNATURE]).get() >= 1.0);
    }

    #[test]
    fn test_metric_error_handling() {
        init_jwt_metrics();
        
        // Test that invalid/long label values are handled gracefully
        // (These would be sanitized by the core infrastructure)
        record_operation_success("very_long_operation_name_that_might_cause_issues");
        record_validation_failure("some_invalid_failure_type!");
        
        // These should not panic due to the enhanced error handling in core.rs
        // The metrics should either be recorded with sanitized labels or ignored safely
    }
}