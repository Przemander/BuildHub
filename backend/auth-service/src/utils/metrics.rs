//! Minimal, production-ready metrics for auth service.
//!
//! Clean, simple, and effective - no over-engineering.

use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder,
};

lazy_static! {
    // =============================================================================
    // HTTP METRICS
    // =============================================================================
    
    /// HTTP requests by endpoint, method, and status
    static ref HTTP_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "http_requests_total",
        "HTTP requests by endpoint, method and status",
        &["endpoint", "method", "status"]
    ).unwrap();
    
    /// HTTP request duration
    static ref HTTP_DURATION: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration",
        &["endpoint"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).unwrap();

    // =============================================================================
    // BUSINESS METRICS
    // =============================================================================
    
    /// Core auth operations
    static ref AUTH_OPERATIONS: IntCounterVec = register_int_counter_vec!(
        "auth_operations_total",
        "Authentication operations by type and result",
        &["operation", "result"]
    ).unwrap();
    
    /// Database operations
    static ref DB_OPERATIONS: IntCounterVec = register_int_counter_vec!(
        "db_operations_total",
        "Database operations by type and result",
        &["operation", "result"]
    ).unwrap();
    
    /// External service calls (Redis, Email)
    static ref EXTERNAL_CALLS: IntCounterVec = register_int_counter_vec!(
        "external_calls_total",
        "External service calls by service and result",
        &["service", "operation", "result"]
    ).unwrap();

    /// Security events (rate limiting, login attempts)
    static ref SECURITY_EVENTS: IntCounterVec = register_int_counter_vec!(
        "security_events_total",
        "Security events by type",
        &["event"]
    ).unwrap();

    /// Error counts by type
    static ref ERROR_COUNTS: IntCounterVec = register_int_counter_vec!(
        "errors_total",
        "Errors by type",
        &["error_type"]
    ).unwrap();

    /// Database pool state
    static ref DB_POOL_SIZE: IntGaugeVec = register_int_gauge_vec!(
        "db_pool_size",
        "Database connection pool size",
        &["state"]
    ).unwrap();
}

// =============================================================================
// PUBLIC API
// =============================================================================

/// Initialize metrics (call once at startup)
pub fn init() {
    // Force lazy_static initialization
    lazy_static::initialize(&HTTP_REQUESTS);
    lazy_static::initialize(&HTTP_DURATION);
    lazy_static::initialize(&AUTH_OPERATIONS);
    lazy_static::initialize(&DB_OPERATIONS);
    lazy_static::initialize(&EXTERNAL_CALLS);
    lazy_static::initialize(&SECURITY_EVENTS);
    lazy_static::initialize(&ERROR_COUNTS);
    lazy_static::initialize(&DB_POOL_SIZE);
}

/// Get metrics for Prometheus endpoint
pub fn gather() -> String {
    TextEncoder::new()
        .encode_to_string(&prometheus::default_registry().gather())
        .unwrap_or_else(|_| "# Error collecting metrics".to_string())
}

// =============================================================================
// HTTP METRICS
// =============================================================================

pub mod http {
    use super::*;
    
    /// Record HTTP request
    pub fn request(endpoint: &str, method: &str, status: u16) {
        HTTP_REQUESTS
            .with_label_values(&[endpoint, method, &status.to_string()])
            .inc();
    }
    
    /// Start timing HTTP request
    pub fn timer(endpoint: &str) -> prometheus::HistogramTimer {
        HTTP_DURATION.with_label_values(&[endpoint]).start_timer()
    }
}

// =============================================================================
// AUTH OPERATIONS
// =============================================================================

pub mod auth {
    use super::*;
    
    const SUCCESS: &str = "success";
    const FAILURE: &str = "failure";
    
    pub fn login_success() {
        AUTH_OPERATIONS.with_label_values(&["login", SUCCESS]).inc();
    }
    
    pub fn login_failure() {
        AUTH_OPERATIONS.with_label_values(&["login", FAILURE]).inc();
    }
    
    pub fn register_success() {
        AUTH_OPERATIONS.with_label_values(&["register", SUCCESS]).inc();
    }
    
    pub fn register_failure() {
        AUTH_OPERATIONS.with_label_values(&["register", FAILURE]).inc();
    }
    
    pub fn logout_success() {
        AUTH_OPERATIONS.with_label_values(&["logout", SUCCESS]).inc();
    }
    
    pub fn logout_failure() {
        AUTH_OPERATIONS.with_label_values(&["logout", FAILURE]).inc();
    }
    
    pub fn token_refresh_success() {
        AUTH_OPERATIONS.with_label_values(&["token_refresh", SUCCESS]).inc();
    }
    
    pub fn token_refresh_failure() {
        AUTH_OPERATIONS.with_label_values(&["token_refresh", FAILURE]).inc();
    }
    
    pub fn password_reset_request() {
        AUTH_OPERATIONS.with_label_values(&["password_reset_request", SUCCESS]).inc();
    }
    
    pub fn password_reset_confirm() {
        AUTH_OPERATIONS.with_label_values(&["password_reset_confirm", SUCCESS]).inc();
    }
    
    pub fn password_reset_failure() {
        AUTH_OPERATIONS.with_label_values(&["password_reset", FAILURE]).inc();
    }
    
    pub fn activation_success() {
        AUTH_OPERATIONS.with_label_values(&["activation", SUCCESS]).inc();
    }
    
    pub fn activation_failure() {
        AUTH_OPERATIONS.with_label_values(&["activation", FAILURE]).inc();
    }
    
    pub fn jwt_validation_success() {
        AUTH_OPERATIONS.with_label_values(&["jwt_validate", SUCCESS]).inc();
    }
    
    pub fn jwt_validation_failure() {
        AUTH_OPERATIONS.with_label_values(&["jwt_validate", FAILURE]).inc();
    }
}

// =============================================================================
// DATABASE OPERATIONS
// =============================================================================

pub mod db {
    use super::*;
    
    const SUCCESS: &str = "success";
    const FAILURE: &str = "failure";
    
    pub fn query_success(operation: &str) {
        DB_OPERATIONS.with_label_values(&[operation, SUCCESS]).inc();
    }
    
    pub fn query_failure(operation: &str) {
        DB_OPERATIONS.with_label_values(&[operation, FAILURE]).inc();
    }
    
    pub fn connection_acquired() {
        DB_OPERATIONS.with_label_values(&["connection_acquire", SUCCESS]).inc();
    }
    
    pub fn connection_failed() {
        DB_OPERATIONS.with_label_values(&["connection_acquire", FAILURE]).inc();
    }
    
    pub fn pool_configured(size: i64) {
        DB_POOL_SIZE.with_label_values(&["max"]).set(size);
    }
}

// =============================================================================
// EXTERNAL SERVICES
// =============================================================================

pub mod external {
    use super::*;
    
    const SUCCESS: &str = "success";
    const FAILURE: &str = "failure";
    
    // Redis operations
    pub fn redis_success(operation: &str) {
        EXTERNAL_CALLS.with_label_values(&["redis", operation, SUCCESS]).inc();
    }
    
    pub fn redis_failure(operation: &str) {
        EXTERNAL_CALLS.with_label_values(&["redis", operation, FAILURE]).inc();
    }
    
    // Email operations
    pub fn email_success(email_type: &str) {
        EXTERNAL_CALLS.with_label_values(&["email", email_type, SUCCESS]).inc();
    }
    
    pub fn email_failure(error_type: &str) {
        EXTERNAL_CALLS.with_label_values(&["email", "send", error_type]).inc();
    }
    
    pub fn email_sent() {
        EXTERNAL_CALLS.with_label_values(&["email", "send", SUCCESS]).inc();
    }
    
    pub fn email_failed() {
        EXTERNAL_CALLS.with_label_values(&["email", "send", FAILURE]).inc();
    }
}

// =============================================================================
// SECURITY METRICS
// =============================================================================

pub mod security {
    use super::*;
    
    pub fn login_allowed() {
        SECURITY_EVENTS.with_label_values(&["login_allowed"]).inc();
    }
    
    pub fn login_blocked(reason: &str) {
        SECURITY_EVENTS
            .with_label_values(&[&format!("login_blocked_{}", reason)])
            .inc();
    }
    
    pub fn login_guard_error() {
        SECURITY_EVENTS.with_label_values(&["login_guard_error"]).inc();
    }
    
    pub fn login_guard_degraded() {
        SECURITY_EVENTS.with_label_values(&["login_guard_degraded"]).inc();
    }
    
    pub fn rate_limit_exceeded() {
        SECURITY_EVENTS.with_label_values(&["rate_limit_exceeded"]).inc();
    }
    
    pub fn rate_limit_blocked() {
        SECURITY_EVENTS.with_label_values(&["rate_limit_blocked"]).inc();
    }
    
    pub fn rate_limit_allowed() {
        SECURITY_EVENTS.with_label_values(&["rate_limit_allowed"]).inc();
    }
    
    pub fn rate_limit_fail_open() {
        SECURITY_EVENTS.with_label_values(&["rate_limit_fail_open"]).inc();
    }
}

// =============================================================================
// ERROR METRICS
// =============================================================================

pub mod errors {
    use super::*;
    
    pub fn configuration() {
        ERROR_COUNTS.with_label_values(&["configuration"]).inc();
    }
    
    pub fn database() {
        ERROR_COUNTS.with_label_values(&["database"]).inc();
    }
    
    pub fn validation() {
        ERROR_COUNTS.with_label_values(&["validation"]).inc();
    }
    
    pub fn authentication() {
        ERROR_COUNTS.with_label_values(&["authentication"]).inc();
    }
    
    pub fn external() {
        ERROR_COUNTS.with_label_values(&["external"]).inc();
    }
    
    pub fn internal() {
        ERROR_COUNTS.with_label_values(&["internal"]).inc();
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_initialization() {
        init();
        
        // Test HTTP metrics
        http::request("/login", "POST", 200);
        let _timer = http::timer("/login");
        
        // Test auth metrics
        auth::login_success();
        auth::register_failure();
        auth::jwt_validation_success();
        
        // Test db metrics
        db::query_success("find_user");
        db::connection_acquired();
        db::pool_configured(25);
        
        // Test external metrics
        external::redis_success("get");
        external::email_success("activation");
        
        // Test security metrics
        security::login_allowed();
        security::rate_limit_exceeded();
        
        // Test error metrics
        errors::validation();
        errors::authentication();
        
        // Verify we can gather metrics
        let output = gather();
        assert!(output.contains("http_requests_total"));
        assert!(output.contains("auth_operations_total"));
        assert!(output.contains("security_events_total"));
        assert!(output.contains("errors_total"));
    }
    
    #[test]
    fn test_gather_handles_errors() {
        init();
        let output = gather();
        assert!(!output.starts_with("# Error"));
    }
}