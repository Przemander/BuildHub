//! # Login Metrics - Production-Grade Login Flow Monitoring
//!
//! Essential login flow monitoring for complete authentication observability.
//! Fully integrated with the standardized core metrics infrastructure for maximum consistency.
//!
//! ## Design Philosophy
//! - **End-to-End Flow Tracking**: Monitor complete login journey
//! - **Step-by-Step Observability**: Track each login phase separately
//! - **Business Intelligence**: Login success rates and failure analysis
//! - **Performance Monitoring**: Login flow latency and bottlenecks
//! - **Complete Core Integration**: Uses standardized infrastructure exclusively
//! - **Production-Ready**: Zero custom error handling, consistent with other modules
//!
//! ## Core Metrics (5 Essential)
//! - `login_operations_total`: Login operations by step and result
//! - `login_failures_total`: Login failures by specific step and error type
//! - `login_duration_seconds`: Login flow duration for performance monitoring
//! - `login_http_requests_total`: HTTP requests by method and status code
//! - `login_http_duration_seconds`: HTTP request duration for API performance
//!
//! ## Production Alerts
//! - High login failure rates (authentication issues)
//! - Login flow bottlenecks (user experience)
//! - Infrastructure failures during login (system health)
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
    LATENCY_BUCKETS_MEDIUM, // Involves DB query and hash
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Login operations by step and result
    ///
    /// Essential for monitoring login flow completion and identifying
    /// bottlenecks in the authentication process.
    ///
    /// # Labels
    /// * `step`: Login flow step
    ///   - `"db_connection"`: Database connection acquisition
    ///   - `"user_lookup"`: User search by login/email
    ///   - `"password_verification"`: Password hash comparison
    ///   - `"account_check"`: Account status verification
    ///   - `"token_generation_access"`: Access token creation
    ///   - `"token_generation_refresh"`: Refresh token creation
    ///   - `"complete_flow"`: End-to-end login process
    /// * `result`: Operation outcome for success rate calculation
    ///   - `"success"`: Step completed successfully
    ///   - `"failure"`: Step failed for any reason
    ///
    /// # Business Impact
    /// - **User Experience**: Failed logins frustrate users
    /// - **Security Compliance**: Monitor invalid attempts
    /// - **Conversion Rates**: Login success affects engagement
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High login failure rate
    /// - alert: HighLoginFailureRate
    ///   expr: rate(login_operations_total{step="complete_flow", result="failure"}[5m]) / rate(login_operations_total{step="complete_flow"}[5m]) > 0.1
    ///   severity: critical
    ///   annotations:
    ///     summary: "Login failure rate: {{ $value | humanizePercentage }}"
    ///
    /// # Warning: Password verification failures
    /// - alert: PasswordVerificationFailures
    ///   expr: rate(login_operations_total{step="password_verification", result="failure"}[5m]) > 5
    ///   severity: warning
    /// ```
    pub static ref LOGIN_OPERATIONS: CounterVec = create_counter_vec(
        "login_operations_total",
        "Login operations by step and result",
        &["step", "result"]
    ).expect("Failed to create LOGIN_OPERATIONS metric");

    /// **Failure Analysis Metric**: Login failures by specific step and error type
    ///
    /// Provides detailed failure categorization for targeted troubleshooting and
    /// security compliance monitoring.
    ///
    /// # Labels
    /// * `step`: Login step that failed
    /// * `error_type`: Specific type of failure
    ///   - `"db_unavailable"`: Database connection issues
    ///   - `"user_not_found"`: Login identifier not found
    ///   - `"invalid_password"`: Password mismatch
    ///   - `"inactive_account"`: Account not active
    ///   - `"token_generation_failed"`: JWT creation error
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Database issues during login
    /// - alert: LoginDatabaseErrors
    ///   expr: rate(login_failures_total{step="db_connection", error_type="db_unavailable"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: High invalid password rate
    /// - alert: HighInvalidPasswords
    ///   expr: rate(login_failures_total{step="password_verification", error_type="invalid_password"}[5m]) > 10
    ///   severity: warning
    /// ```
    pub static ref LOGIN_FAILURES: CounterVec = create_counter_vec(
        "login_failures_total",
        "Login failures by step and error type",
        &["step", "error_type"]
    ).expect("Failed to create LOGIN_FAILURES metric");

    /// **Performance Metric**: Login flow duration for SLA monitoring
    ///
    /// Tracks login processing latency to ensure responsive authentication
    /// and identify performance bottlenecks in the login pipeline.
    ///
    /// # Labels
    /// * `step`: Login step for performance analysis
    ///
    /// # Performance Targets
    /// - **Complete Flow**: p95 < 200ms, p99 < 500ms (DB query + hash)
    /// - **User Lookup**: p95 < 50ms, p99 < 100ms (DB query)
    /// - **Password Verification**: p95 < 100ms, p99 < 200ms (hash time)
    /// - **Token Generation**: p95 < 10ms, p99 < 25ms (JWT signing)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow login flow
    /// - alert: SlowLoginFlow
    ///   expr: histogram_quantile(0.95, rate(login_duration_seconds_bucket{step="complete_flow"}[5m])) > 0.2
    ///   severity: warning
    ///
    /// # Critical: Very slow login
    /// - alert: VerySlowLoginFlow
    ///   expr: histogram_quantile(0.95, rate(login_duration_seconds_bucket{step="complete_flow"}[5m])) > 0.5
    ///   severity: critical
    /// ```
    pub static ref LOGIN_DURATION: HistogramVec = create_histogram_vec(
        "login_duration_seconds",
        "Login step duration for performance monitoring",
        &["step"],
        LATENCY_BUCKETS_MEDIUM  // Involves DB and crypto
    ).expect("Failed to create LOGIN_DURATION metric");

    /// **HTTP API Metric**: Login endpoint requests by method and status
    ///
    /// Tracks HTTP-level login API usage and success rates for complete
    /// end-to-end monitoring from HTTP request to business logic completion.
    ///
    /// # Labels
    /// * `method`: HTTP method (should always be "POST" for login)
    /// * `status_code`: HTTP response status code
    ///   - `"200"`: OK - successful login
    ///   - `"400"`: Bad Request - validation errors
    ///   - `"401"`: Unauthorized - invalid credentials
    ///   - `"500"`: Internal Server Error - system failures
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High HTTP error rate
    /// - alert: HighLoginHTTPErrorRate
    ///   expr: rate(login_http_requests_total{status_code=~"5.."}[5m]) / rate(login_http_requests_total[5m]) > 0.01
    ///   severity: critical
    ///
    /// # Warning: High unauthorized rate
    /// - alert: HighLoginUnauthorizedRate
    ///   expr: rate(login_http_requests_total{status_code="401"}[5m]) / rate(login_http_requests_total[5m]) > 0.1
    ///   severity: warning
    /// ```
    pub static ref LOGIN_HTTP_REQUESTS: CounterVec = create_counter_vec(
        "login_http_requests_total",
        "HTTP requests to login endpoint by method and status",
        &["method", "status_code"]
    ).expect("Failed to create LOGIN_HTTP_REQUESTS metric");

    /// **HTTP Performance Metric**: Login endpoint response duration
    ///
    /// Tracks HTTP request-response latency for the login API endpoint
    /// to ensure responsive authentication at the API level.
    ///
    /// # Performance Targets
    /// - **Success (200)**: p95 < 200ms, p99 < 500ms (includes DB and hash)
    /// - **Auth Errors (401)**: p95 < 100ms, p99 < 200ms (dummy hash delay)
    /// - **Server Errors (500)**: p95 < 50ms, p99 < 100ms (fast failure)
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Warning: Slow login API
    /// - alert: SlowLoginAPI
    ///   expr: histogram_quantile(0.95, rate(login_http_duration_seconds_bucket{status_code="200"}[5m])) > 0.2
    ///   severity: warning
    ///
    /// # Critical: Very slow login API
    /// - alert: VerySlowLoginAPI
    ///   expr: histogram_quantile(0.95, rate(login_http_duration_seconds_bucket{status_code="200"}[5m])) > 0.5
    ///   severity: critical
    /// ```
    pub static ref LOGIN_HTTP_DURATION: HistogramVec = create_histogram_vec(
        "login_http_duration_seconds",
        "HTTP request duration for login endpoint",
        &["method", "status_code"],
        LATENCY_BUCKETS_MEDIUM  // HTTP includes full login flow
    ).expect("Failed to create LOGIN_HTTP_DURATION metric");
}

static LOGIN_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_login_metrics() {
    if LOGIN_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&LOGIN_OPERATIONS);
    lazy_static::initialize(&LOGIN_FAILURES);
    lazy_static::initialize(&LOGIN_DURATION);
    lazy_static::initialize(&LOGIN_HTTP_REQUESTS);
    lazy_static::initialize(&LOGIN_HTTP_DURATION);

    log_info!("Metrics", "Login metrics initialized (production-ready with HTTP tracking)", "login_metrics_init");
}

// =============================================================================
// CORE API (Fully standardized - consistent with other modules)
// =============================================================================

/// Records login operation result (standardized approach)
pub fn record_login_operation(step: &str, result: &str) {
    observe_counter_vec(
        &LOGIN_OPERATIONS,
        "login_operations_total",
        &[step, result]
    );
}

/// Records specific login failure (standardized approach)
pub fn record_login_failure_detailed(step: &str, error_type: &str) {
    observe_counter_vec(
        &LOGIN_FAILURES,
        "login_failures_total",
        &[step, error_type]
    );
}

/// Times login step with standard prometheus timer
pub fn time_login_step(step: &str) -> HistogramTimer {
    LOGIN_DURATION
        .with_label_values(&[step])
        .start_timer()
}

// =============================================================================
// HTTP API HELPERS
// =============================================================================

/// Records HTTP login request with method and status code
pub fn record_http_request(method: &str, status_code: u16) {
    observe_counter_vec(
        &LOGIN_HTTP_REQUESTS,
        "login_http_requests_total",
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
// CONSTANTS (Type-safe login step classification)
// =============================================================================

/// Login step constants for type safety
pub mod steps {
    pub const DB_CONNECTION: &str = "db_connection";
    pub const USER_LOOKUP: &str = "user_lookup";
    pub const PASSWORD_VERIFICATION: &str = "password_verification";
    pub const ACCOUNT_CHECK: &str = "account_check";
    pub const TOKEN_GENERATION_ACCESS: &str = "token_generation_access";
    pub const TOKEN_GENERATION_REFRESH: &str = "token_generation_refresh";
    pub const COMPLETE_FLOW: &str = "complete_flow";
}

/// Result constants for consistent labeling
pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
}

/// Error type constants for detailed error categorization
pub mod error_types {
    pub const DB_UNAVAILABLE: &str = "db_unavailable";
    pub const USER_NOT_FOUND: &str = "user_not_found";
    pub const INVALID_PASSWORD: &str = "invalid_password";
    pub const INACTIVE_ACCOUNT: &str = "inactive_account";
    pub const TOKEN_GENERATION_FAILED: &str = "token_generation_failed";
}

// =============================================================================
// BUSINESS HELPERS (Semantic convenience functions)
// =============================================================================

/// Records successful login step
pub fn record_step_success(step: &str) {
    record_login_operation(step, results::SUCCESS);
}

/// Records failed login step
pub fn record_step_failure(step: &str) {
    record_login_operation(step, results::FAILURE);
}

/// Records login step failure with specific error type
pub fn record_step_failure_with_type(step: &str, error_type: &str) {
    record_login_failure_detailed(step, error_type);
    record_step_failure(step); // Also record in general operations
}

// Complete flow helpers
pub fn record_login_success() {
    record_step_success(steps::COMPLETE_FLOW);
}

pub fn record_login_failure() {
    record_step_failure(steps::COMPLETE_FLOW);
}

pub fn time_complete_login_flow() -> HistogramTimer {
    time_login_step(steps::COMPLETE_FLOW)
}

// Step-specific helpers (matching login_logic.rs)
pub fn record_db_connection_success() {
    record_step_success(steps::DB_CONNECTION);
}

pub fn record_db_connection_failure(error_type: &str) {
    record_step_failure_with_type(steps::DB_CONNECTION, error_type);
}

pub fn record_user_lookup_success() {
    record_step_success(steps::USER_LOOKUP);
}

pub fn record_user_lookup_failure(error_type: &str) {
    record_step_failure_with_type(steps::USER_LOOKUP, error_type);
}

pub fn record_password_verification_success() {
    record_step_success(steps::PASSWORD_VERIFICATION);
}

pub fn record_password_verification_failure(error_type: &str) {
    record_step_failure_with_type(steps::PASSWORD_VERIFICATION, error_type);
}

pub fn record_account_check_success() {
    record_step_success(steps::ACCOUNT_CHECK);
}

pub fn record_account_check_failure(error_type: &str) {
    record_step_failure_with_type(steps::ACCOUNT_CHECK, error_type);
}

pub fn record_token_generation_access_success() {
    record_step_success(steps::TOKEN_GENERATION_ACCESS);
}

pub fn record_token_generation_access_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_GENERATION_ACCESS, error_type);
}

pub fn record_token_generation_refresh_success() {
    record_step_success(steps::TOKEN_GENERATION_REFRESH);
}

pub fn record_token_generation_refresh_failure(error_type: &str) {
    record_step_failure_with_type(steps::TOKEN_GENERATION_REFRESH, error_type);
}

// =============================================================================
// COMPREHENSIVE TEST SUITE (Production-grade testing)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_metrics_initialization() {
        init_login_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 0.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND]).get(), 0.0);
        assert_eq!(LOGIN_DURATION.with_label_values(&[steps::COMPLETE_FLOW]).get_sample_count(), 0);
        assert_eq!(LOGIN_HTTP_REQUESTS.with_label_values(&[http::POST, "200"]).get(), 0.0);
        assert_eq!(LOGIN_HTTP_DURATION.with_label_values(&[http::POST, "200"]).get_sample_count(), 0);
    }

    #[test]
    fn test_complete_login_flow() {
        init_login_metrics();
        
        let before_count = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let before_duration = LOGIN_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        // Test complete flow success
        let timer = time_complete_login_flow();
        record_login_success();
        drop(timer);
        
        let after_count = LOGIN_OPERATIONS
            .with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS])
            .get();
        let after_duration = LOGIN_DURATION
            .with_label_values(&[steps::COMPLETE_FLOW])
            .get_sample_count();
        
        assert_eq!(after_count, before_count + 1.0);
        assert_eq!(after_duration, before_duration + 1);
    }

    #[test]
    fn test_step_specific_helpers() {
        init_login_metrics();
        
        // Test all step helpers
        record_db_connection_success();
        record_db_connection_failure(error_types::DB_UNAVAILABLE);
        
        record_user_lookup_success();
        record_user_lookup_failure(error_types::USER_NOT_FOUND);
        
        record_password_verification_success();
        record_password_verification_failure(error_types::INVALID_PASSWORD);
        
        record_account_check_success();
        record_account_check_failure(error_types::INACTIVE_ACCOUNT);
        
        record_token_generation_access_success();
        record_token_generation_access_failure(error_types::TOKEN_GENERATION_FAILED);
        
        record_token_generation_refresh_success();
        record_token_generation_refresh_failure(error_types::TOKEN_GENERATION_FAILED);
        
        // Verify operations were recorded
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::USER_LOOKUP, results::SUCCESS]).get(), 1.0);
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::USER_LOOKUP, results::FAILURE]).get(), 1.0);
        
        // Verify detailed failures were recorded
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::DB_CONNECTION, error_types::DB_UNAVAILABLE]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::PASSWORD_VERIFICATION, error_types::INVALID_PASSWORD]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::ACCOUNT_CHECK, error_types::INACTIVE_ACCOUNT]).get(), 1.0);
    }

    #[test]
    fn test_http_metrics_integration() {
        init_login_metrics();
        
        // Test HTTP request tracking
        let initial_success = LOGIN_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let initial_error = LOGIN_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        
        // Record requests
        record_http_request(http::POST, http::OK);
        record_http_request(http::POST, http::BAD_REQUEST);
        
        // Verify counts
        let final_success = LOGIN_HTTP_REQUESTS
            .with_label_values(&[http::POST, "200"])
            .get();
        let final_error = LOGIN_HTTP_REQUESTS
            .with_label_values(&[http::POST, "400"])
            .get();
        
        assert_eq!(final_success, initial_success + 1.0);
        assert_eq!(final_error, initial_error + 1.0);
    }

    #[test]
    fn test_production_login_patterns() {
        init_login_metrics();
        
        // Simulate realistic production patterns
        
        // 10 successful logins
        for _ in 0..10 {
            record_db_connection_success();
            record_user_lookup_success();
            record_password_verification_success();
            record_account_check_success();
            record_token_generation_access_success();
            record_token_generation_refresh_success();
            record_login_success();
        }
        
        // Some failures at different steps
        record_db_connection_failure(error_types::DB_UNAVAILABLE);
        record_user_lookup_failure(error_types::USER_NOT_FOUND);
        record_password_verification_failure(error_types::INVALID_PASSWORD);
        record_account_check_failure(error_types::INACTIVE_ACCOUNT);
        record_token_generation_access_failure(error_types::TOKEN_GENERATION_FAILED);
        record_token_generation_refresh_failure(error_types::TOKEN_GENERATION_FAILED);
        
        // Verify realistic metric patterns
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::SUCCESS]).get(), 10.0);
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::COMPLETE_FLOW, results::FAILURE]).get(), 0.0); // No complete failures in sim
        
        // Specific failure types
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::DB_CONNECTION, error_types::DB_UNAVAILABLE]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::PASSWORD_VERIFICATION, error_types::INVALID_PASSWORD]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::ACCOUNT_CHECK, error_types::INACTIVE_ACCOUNT]).get(), 1.0);
        
        // Successful steps
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::PASSWORD_VERIFICATION, results::SUCCESS]).get(), 10.0);
    }

    #[test]
    fn test_type_safety_constants() {
        init_login_metrics();
        
        // Verify all constants are valid and type-safe
        assert_eq!(steps::DB_CONNECTION, "db_connection");
        assert_eq!(steps::USER_LOOKUP, "user_lookup");
        assert_eq!(steps::PASSWORD_VERIFICATION, "password_verification");
        assert_eq!(steps::ACCOUNT_CHECK, "account_check");
        assert_eq!(steps::TOKEN_GENERATION_ACCESS, "token_generation_access");
        assert_eq!(steps::TOKEN_GENERATION_REFRESH, "token_generation_refresh");
        assert_eq!(steps::COMPLETE_FLOW, "complete_flow");
        
        assert_eq!(results::SUCCESS, "success");
        assert_eq!(results::FAILURE, "failure");
        
        assert_eq!(error_types::DB_UNAVAILABLE, "db_unavailable");
        assert_eq!(error_types::USER_NOT_FOUND, "user_not_found");
        assert_eq!(error_types::INVALID_PASSWORD, "invalid_password");
        assert_eq!(error_types::INACTIVE_ACCOUNT, "inactive_account");
        assert_eq!(error_types::TOKEN_GENERATION_FAILED, "token_generation_failed");
        
        // Use constants in actual operations
        record_login_operation(steps::PASSWORD_VERIFICATION, results::SUCCESS);
        record_login_failure_detailed(steps::USER_LOOKUP, error_types::USER_NOT_FOUND);
        
        assert_eq!(LOGIN_OPERATIONS.with_label_values(&[steps::PASSWORD_VERIFICATION, results::SUCCESS]).get(), 1.0);
        assert_eq!(LOGIN_FAILURES.with_label_values(&[steps::USER_LOOKUP, error_types::USER_NOT_FOUND]).get(), 1.0);
    }
}