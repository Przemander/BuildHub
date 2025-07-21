//! # Registration Metrics - Production-Grade User Registration Flow Monitoring
//!
//! Essential registration flow monitoring for complete user onboarding observability.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **End-to-End Flow Tracking**: Monitor complete registration journey
//! - **Step-by-Step Observability**: Track each registration phase separately
//! - **Business Intelligence**: Registration success rates and drop-off analysis
//! - **Performance Monitoring**: Registration flow latency and bottlenecks
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (5 Essential)
//! - `registration_operations_total`: Registration operations by step and result
//! - `registration_failures_total`: Registration failures by specific step and error type
//! - `registration_duration_seconds`: Registration flow duration for performance monitoring
//! - `registration_http_requests_total`: HTTP requests by method and status code
//! - `registration_http_duration_seconds`: HTTP request duration for API performance
//!
//! ## Production Alerts
//! - High registration failure rates (business impact)
//! - Registration flow bottlenecks (user experience)
//! - Infrastructure failures during registration (system health)
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
    LATENCY_BUCKETS_MEDIUM, // Registration involves DB + Redis + Email
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Registration operations by step and result
    ///
    /// Essential for monitoring user registration flow completion and identifying
    /// bottlenecks in the onboarding process. Tracks each critical step.
    ///
    /// # Labels
    /// * `step`: Registration flow step
    ///   - `"validation"`: Input validation (username, email, password)
    ///   - `"uniqueness_check"`: Email/username uniqueness verification
    ///   - `"user_creation"`: Database user record creation
    ///   - `"activation_setup"`: Activation code generation and storage
    ///   - `"email_delivery"`: Activation email sending
    ///   - `"complete_flow"`: End-to-end registration process
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Step completed successfully
    ///   - `"failure"`: Step failed for any reason
    ///
    /// # Business Impact
    /// - **User Onboarding**: Failed steps prevent new user acquisition
    /// - **Conversion Rates**: Registration success rate affects business growth
    /// - **User Experience**: Slow steps impact user satisfaction
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High registration failure rate
    /// - alert: HighRegistrationFailureRate
    ///   expr: rate(registration_operations_total{step="complete_flow", result="failure"}[5m]) / rate(registration_operations_total{step="complete_flow"}[5m]) > 0.05
    ///   severity: critical
    ///   annotations:
    ///     summary: "Registration failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: User creation failures
    /// - alert: UserCreationFailures
    ///   expr: rate(registration_operations_total{step="user_creation", result="failure"}[5m]) > 1
    ///   severity: warning
    /// ```
    pub static ref REGISTRATION_OPERATIONS: CounterVec = create_counter_vec(
        "registration_operations_total",
        "Registration operations by step and result",
        &["step", "result"]
    ).expect("Failed to create REGISTRATION_OPERATIONS metric");

    /// **Failure Analysis Metric**: Registration failures by specific step and error type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and
    /// business flow optimization.
    ///
    /// # Labels
    /// * `step`: Registration step that failed
    /// * `error_type`: Specific type of failure
    ///   - Validation: `"invalid_username"`, `"invalid_email"`, `"weak_password"`
    ///   - Uniqueness: `"email_taken"`, `"username_taken"`
    ///   - User Creation: `"database_error"`
    ///   - Activation Setup: `"redis_error"`
    ///   - Email Delivery: `"smtp_error"`, `"configuration_error"`
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Database issues during registration
    /// - alert: RegistrationDatabaseErrors
    ///   expr: rate(registration_failures_total{step="user_creation", error_type="database_error"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: Email delivery failures
    /// - alert: RegistrationEmailFailures
    ///   expr: rate(registration_failures_total{step="email_delivery", error_type="smtp_error"}[5m]) > 1
    ///   severity: warning
    /// ```
    pub static ref REGISTRATION_FAILURES: CounterVec = create_counter_vec(
        "registration_failures_total",
        "Registration failures by step and error type",
        &["step", "error_type"]
    ).expect("Failed to create REGISTRATION_FAILURES metric");

    /// **Performance Metric**: Registration flow duration for SLA monitoring
    ///
    /// Tracks registration processing latency to ensure responsive user experience
    /// and identify performance bottlenecks in the registration pipeline.
    ///
    /// # Labels
    /// * `step`: Registration step for performance analysis
    ///
    /// # Performance Targets
    /// - **Complete Flow**: p95 < 3s, p99 < 5s (full registration process)
    /// - **Validation**: p95 < 50ms, p99 < 100ms (input validation)
    /// - **User Creation**: p95 < 200ms, p99 < 500ms (database operations)
    /// - **Email Delivery**: p95 < 2s, p99 < 4s (SMTP operations)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow registration flow
    /// - alert: SlowRegistrationFlow
    ///   expr: histogram_quantile(0.95, rate(registration_duration_seconds_bucket{step="complete_flow"}[5m])) > 3.0
    ///   severity: warning
    ///
    /// # Critical: Very slow registration
    /// - alert: VerySlowRegistrationFlow
    ///   expr: histogram_quantile(0.95, rate(registration_duration_seconds_bucket{step="complete_flow"}[5m])) > 5.0
    ///   severity: critical
    /// ```
    pub static ref REGISTRATION_DURATION: HistogramVec = create_histogram_vec(
        "registration_duration_seconds",
        "Registration step duration for performance monitoring",
        &["step"],
        LATENCY_BUCKETS_MEDIUM  // Registration involves multiple systems
    ).expect("Failed to create REGISTRATION_DURATION metric");

    /// **HTTP API Metric**: Registration endpoint requests by method and status
    ///
    /// Tracks HTTP-level registration API usage and success rates for complete
    /// end-to-end monitoring from HTTP request to business logic completion.
    ///
    /// # Labels
    /// * `method`: HTTP method (should always be "POST" for registration)
    /// * `status_code`: HTTP response status code
    ///   - `"201"`: Created - successful registration
    ///   - `"400"`: Bad Request - validation errors
    ///   - `"500"`: Internal Server Error - system failures
    ///
    /// # Business Impact
    /// - **API Health**: HTTP-level success rate monitoring
    /// - **Client Experience**: Track HTTP response codes for debugging
    /// - **Load Monitoring**: Track registration API volume
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High HTTP error rate
    /// - alert: HighRegistrationHTTPErrorRate
    ///   expr: rate(registration_http_requests_total{status_code=~"5.."}[5m]) / rate(registration_http_requests_total[5m]) > 0.01
    ///   severity: critical
    ///   annotations:
    ///     summary: "Registration API HTTP error rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: High client error rate
    /// - alert: HighRegistrationClientErrorRate
    ///   expr: rate(registration_http_requests_total{status_code=~"4.."}[5m]) / rate(registration_http_requests_total[5m]) > 0.2
    ///   severity: warning
    /// ```
    pub static ref REGISTRATION_HTTP_REQUESTS: CounterVec = create_counter_vec(
        "registration_http_requests_total",
        "HTTP requests to registration endpoint by method and status",
        &["method", "status_code"]
    ).expect("Failed to create REGISTRATION_HTTP_REQUESTS metric");

    /// **HTTP Performance Metric**: Registration endpoint response duration
    ///
    /// Tracks HTTP request-response latency for the registration API endpoint
    /// to ensure responsive user experience at the API level.
    ///
    /// # Labels
    /// * `method`: HTTP method
    /// * `status_code`: HTTP response status for performance analysis by outcome
    ///
    /// # Performance Targets
    /// - **Success (2xx)**: p95 < 3s, p99 < 5s (includes full registration flow)
    /// - **Client Errors (4xx)**: p95 < 100ms, p99 < 200ms (fast validation failures)
    /// - **Server Errors (5xx)**: p95 < 200ms, p99 < 500ms (fast failure detection)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow registration API
    /// - alert: SlowRegistrationAPI
    ///   expr: histogram_quantile(0.95, rate(registration_http_duration_seconds_bucket{status_code="201"}[5m])) > 3.0
    ///   severity: warning
    ///
    /// # Critical: Very slow registration API
    /// - alert: VerySlowRegistrationAPI
    ///   expr: histogram_quantile(0.95, rate(registration_http_duration_seconds_bucket{status_code="201"}[5m])) > 5.0
    ///   severity: critical
    /// ```
    pub static ref REGISTRATION_HTTP_DURATION: HistogramVec = create_histogram_vec(
        "registration_http_duration_seconds",
        "HTTP request duration for registration endpoint",
        &["method", "status_code"],
        LATENCY_BUCKETS_MEDIUM  // HTTP includes full registration flow
    ).expect("Failed to create REGISTRATION_HTTP_DURATION metric");
}

static REGISTRATION_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn init_registration_metrics() {
    if REGISTRATION_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&REGISTRATION_OPERATIONS);
    lazy_static::initialize(&REGISTRATION_FAILURES);
    lazy_static::initialize(&REGISTRATION_DURATION);
    lazy_static::initialize(&REGISTRATION_HTTP_REQUESTS);
    lazy_static::initialize(&REGISTRATION_HTTP_DURATION);

    log_info!("Metrics", "Registration metrics initialized (production-ready with HTTP tracking)", "registration_metrics_init");
}

// =============================================================================
// CORE API (Fully standardized)
// =============================================================================

/// Records registration operation result (standardized approach)
pub fn record_registration_operation(step: &str, result: &str) {
    observe_counter_vec(
        &REGISTRATION_OPERATIONS,
        "registration_operations_total",
        &[step, result]
    );
}

/// Records specific registration failure (standardized approach)
pub fn record_registration_failure_detailed(step: &str, error_type: &str) {
    observe_counter_vec(
        &REGISTRATION_FAILURES,
        "registration_failures_total",
        &[step, error_type]
    );
}

/// Times registration step with standard prometheus timer
pub fn time_registration_step(step: &str) -> HistogramTimer {
    REGISTRATION_DURATION
        .with_label_values(&[step])
        .start_timer()
}

// =============================================================================
// HTTP API HELPERS (Only used functions)
// =============================================================================

/// Records HTTP registration request with method and status code
pub fn record_http_request(method: &str, status_code: u16) {
    observe_counter_vec(
        &REGISTRATION_HTTP_REQUESTS,
        "registration_http_requests_total",
        &[method, &status_code.to_string()]
    );
}

/// Constants for HTTP methods and status codes (only used ones)
pub mod http {
    pub const POST: &str = "POST";
    
    // Status codes (only used ones)
    pub const CREATED: u16 = 201;
    pub const BAD_REQUEST: u16 = 400;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
}

// =============================================================================
// CONSTANTS (Type-safe registration step classification)
// =============================================================================

/// Registration step constants for type safety
pub mod steps {
    pub const VALIDATION: &str = "validation";
    pub const UNIQUENESS_CHECK: &str = "uniqueness_check";
    pub const USER_CREATION: &str = "user_creation";
    pub const ACTIVATION_SETUP: &str = "activation_setup";
    pub const EMAIL_DELIVERY: &str = "email_delivery";
    pub const COMPLETE_FLOW: &str = "complete_flow";
}

/// Result constants for consistent labeling
pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization (only used ones)
pub mod error_types {
    // Validation errors
    pub const INVALID_USERNAME: &str = "invalid_username";
    pub const INVALID_EMAIL: &str = "invalid_email";
    pub const WEAK_PASSWORD: &str = "weak_password";
    
    // Uniqueness check errors
    pub const EMAIL_TAKEN: &str = "email_taken";
    pub const USERNAME_TAKEN: &str = "username_taken";
    
    // User creation errors
    pub const DATABASE_ERROR: &str = "database_error";
    
    // Activation setup errors
    pub const REDIS_ERROR: &str = "redis_error";
    
    // Email delivery errors
    pub const SMTP_ERROR: &str = "smtp_error";
    pub const CONFIGURATION_ERROR: &str = "configuration_error";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful registration step
pub fn record_step_success(step: &str) {
    record_registration_operation(step, results::SUCCESS);
}

/// Records failed registration step
pub fn record_step_failure(step: &str) {
    record_registration_operation(step, results::FAILURE);
}

/// Records registration step failure with specific error type
pub fn record_step_failure_with_type(step: &str, error_type: &str) {
    record_registration_failure_detailed(step, error_type);
    record_step_failure(step); // Also record in general operations
}

// Complete flow helpers
pub fn record_registration_success() {
    record_step_success(steps::COMPLETE_FLOW);
}

pub fn record_registration_failure() {
    record_step_failure(steps::COMPLETE_FLOW);
}

pub fn time_complete_registration_flow() -> HistogramTimer {
    time_registration_step(steps::COMPLETE_FLOW)
}

// Step-specific helpers
pub fn record_validation_success() {
    record_step_success(steps::VALIDATION);
}

pub fn record_validation_failure(error_type: &str) {
    record_step_failure_with_type(steps::VALIDATION, error_type);
}

pub fn record_uniqueness_check_success() {
    record_step_success(steps::UNIQUENESS_CHECK);
}

pub fn record_uniqueness_check_failure(error_type: &str) {
    record_step_failure_with_type(steps::UNIQUENESS_CHECK, error_type);
}

pub fn record_user_creation_success() {
    record_step_success(steps::USER_CREATION);
}

pub fn record_user_creation_failure(error_type: &str) {
    record_step_failure_with_type(steps::USER_CREATION, error_type);
}

pub fn record_activation_setup_success() {
    record_step_success(steps::ACTIVATION_SETUP);
}

pub fn record_activation_setup_failure(error_type: &str) {
    record_step_failure_with_type(steps::ACTIVATION_SETUP, error_type);
}

pub fn record_email_delivery_success() {
    record_step_success(steps::EMAIL_DELIVERY);
}

pub fn record_email_delivery_failure(error_type: &str) {
    record_step_failure_with_type(steps::EMAIL_DELIVERY, error_type);
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_metrics_initialization() {
        init_registration_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 0.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::VALIDATION, error_types::INVALID_EMAIL]).get(), 0.0);
        assert_eq!(REGISTRATION_DURATION.with_label_values(&[steps::COMPLETE_FLOW]).get_sample_count(), 0);
    }

    #[test]
    fn test_complete_registration_flow() {
        init_registration_metrics();
        
        let before_count = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let before_duration = REGISTRATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        // Test complete flow success
        let timer = time_complete_registration_flow();
        record_registration_success();
        drop(timer);
        
        let after_count = REGISTRATION_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let after_duration = REGISTRATION_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_step_specific_helpers() {
        init_registration_metrics();
        
        // Test all step helpers
        record_validation_success();
        record_validation_failure(error_types::WEAK_PASSWORD);
        
        record_uniqueness_check_success();
        record_uniqueness_check_failure(error_types::EMAIL_TAKEN);
        
        record_user_creation_success();
        record_user_creation_failure(error_types::DATABASE_ERROR);
        
        record_activation_setup_success();
        record_activation_setup_failure(error_types::REDIS_ERROR);
        
        record_email_delivery_success();
        record_email_delivery_failure(error_types::SMTP_ERROR);
        
        // Verify operations were recorded
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::VALIDATION, results::SUCCESS]).get(), 1.0);
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::VALIDATION, results::FAILURE]).get(), 1.0);
        
        // Verify detailed failures were recorded
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::VALIDATION, error_types::WEAK_PASSWORD]).get(), 1.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::UNIQUENESS_CHECK, error_types::EMAIL_TAKEN]).get(), 1.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::USER_CREATION, error_types::DATABASE_ERROR]).get(), 1.0);
    }

    #[test]
    fn test_production_registration_patterns() {
        init_registration_metrics();
        
        // Simulate realistic production registration flow
        
        // Most registrations succeed
        for _ in 0..10 {
            record_validation_success();
            record_uniqueness_check_success();
            record_user_creation_success();
            record_activation_setup_success();
            record_email_delivery_success();
            record_registration_success();
        }
        
        // Some fail at different steps
        record_validation_failure(error_types::WEAK_PASSWORD);
        record_uniqueness_check_failure(error_types::EMAIL_TAKEN);
        record_user_creation_failure(error_types::DATABASE_ERROR);
        record_email_delivery_failure(error_types::SMTP_ERROR);
        
        // Verify realistic success rates
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 10.0);
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::VALIDATION, results::SUCCESS]).get(), 10.0);
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::VALIDATION, results::FAILURE]).get(), 1.0);
        
        // Verify failure categorization
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::VALIDATION, error_types::WEAK_PASSWORD]).get(), 1.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::UNIQUENESS_CHECK, error_types::EMAIL_TAKEN]).get(), 1.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::USER_CREATION, error_types::DATABASE_ERROR]).get(), 1.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::EMAIL_DELIVERY, error_types::SMTP_ERROR]).get(), 1.0);
    }

    #[test]
    fn test_type_safety_constants() {
        init_registration_metrics();
        
        // Verify all constants are valid and type-safe
        assert_eq!(steps::VALIDATION, "validation");
        assert_eq!(steps::UNIQUENESS_CHECK, "uniqueness_check");
        assert_eq!(steps::USER_CREATION, "user_creation");
        assert_eq!(steps::ACTIVATION_SETUP, "activation_setup");
        assert_eq!(steps::EMAIL_DELIVERY, "email_delivery");
        assert_eq!(steps::COMPLETE_FLOW, "complete_flow");
        
        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");
        
        assert_eq!(error_types::INVALID_EMAIL, "invalid_email");
        assert_eq!(error_types::EMAIL_TAKEN, "email_taken");
        assert_eq!(error_types::DATABASE_ERROR, "database_error");
        assert_eq!(error_types::SMTP_ERROR, "smtp_error");
        
        // Use constants in actual operations
        record_registration_operation(steps::VALIDATION, results::SUCCESS);
        record_registration_failure_detailed(steps::USER_CREATION, error_types::DATABASE_ERROR);
        
        assert_eq!(REGISTRATION_OPERATIONS.with_label_values(&[steps::VALIDATION, results::SUCCESS]).get(), 1.0);
        assert_eq!(REGISTRATION_FAILURES.with_label_values(&[steps::USER_CREATION, error_types::DATABASE_ERROR]).get(), 1.0);
    }

    #[test]
    fn test_http_metrics_integration() {
        init_registration_metrics();
        
        // Test HTTP request tracking
        let initial_success = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "201"])
            .get();
        let initial_error = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        
        // Record requests
        record_http_request(http::POST, http::CREATED);
        record_http_request(http::POST, http::BAD_REQUEST);
        
        // Verify counts
        let final_success = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "201"])
            .get();
        let final_error = REGISTRATION_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        
        assert_eq!(final_success, initial_success + 1.0);
        assert_eq!(final_error, initial_error + 1.0);
    }
}