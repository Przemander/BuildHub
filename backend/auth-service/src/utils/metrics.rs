//! Minimal, production-ready metrics for auth service.
//!
//! Clean, simple, and effective - no over-engineering.

use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec, TextEncoder,
};
use std::sync::LazyLock;

// =============================================================================
// HTTP METRICS
// =============================================================================

/// HTTP requests by endpoint, method, and status
static HTTP_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "http_requests_total",
        "HTTP requests by endpoint, method and status",
        &["endpoint", "method", "status"]
    )
    .unwrap()
});

/// HTTP request duration
static HTTP_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration",
        &["endpoint"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    )
    .unwrap()
});

// =============================================================================
// BUSINESS METRICS
// =============================================================================

/// Core auth operations
static AUTH_OPERATIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "auth_operations_total",
        "Authentication operations by type and result",
        &["operation", "result"]
    )
    .unwrap()
});

/// Database operations
static DB_OPERATIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "db_operations_total",
        "Database operations by type and result",
        &["operation", "result"]
    )
    .unwrap()
});

/// External service calls (Redis, Email)
static EXTERNAL_CALLS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "external_calls_total",
        "External service calls by service and result",
        &["service", "operation", "result"]
    )
    .unwrap()
});

/// Security events (rate limiting, login attempts)
static SECURITY_EVENTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "security_events_total",
        "Security events by type",
        &["event"]
    )
    .unwrap()
});

/// Error counts by type
static ERROR_COUNTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!("errors_total", "Errors by type", &["error_type"]).unwrap()
});

/// Database pool state
static DB_POOL_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "db_pool_size",
        "Database connection pool size",
        &["state"]
    )
    .unwrap()
});

// =============================================================================
// PUBLIC API
// =============================================================================

/// Initialize metrics (call once at startup)
pub fn init() {
    // Force LazyLock initialization
    LazyLock::force(&HTTP_REQUESTS);
    LazyLock::force(&HTTP_DURATION);
    LazyLock::force(&AUTH_OPERATIONS);
    LazyLock::force(&DB_OPERATIONS);
    LazyLock::force(&EXTERNAL_CALLS);
    LazyLock::force(&SECURITY_EVENTS);
    LazyLock::force(&ERROR_COUNTS);
    LazyLock::force(&DB_POOL_SIZE);
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
        AUTH_OPERATIONS
            .with_label_values(&["token_refresh", SUCCESS])
            .inc();
    }

    pub fn token_refresh_failure() {
        AUTH_OPERATIONS
            .with_label_values(&["token_refresh", FAILURE])
            .inc();
    }

    pub fn password_reset_request() {
        AUTH_OPERATIONS
            .with_label_values(&["password_reset_request", SUCCESS])
            .inc();
    }

    pub fn password_reset_confirm() {
        AUTH_OPERATIONS
            .with_label_values(&["password_reset_confirm", SUCCESS])
            .inc();
    }

    pub fn password_reset_failure() {
        AUTH_OPERATIONS
            .with_label_values(&["password_reset", FAILURE])
            .inc();
    }

    pub fn activation_success() {
        AUTH_OPERATIONS.with_label_values(&["activation", SUCCESS]).inc();
    }

    pub fn activation_failure() {
        AUTH_OPERATIONS.with_label_values(&["activation", FAILURE]).inc();
    }

    pub fn jwt_validation_success() {
        AUTH_OPERATIONS
            .with_label_values(&["jwt_validate", SUCCESS])
            .inc();
    }

    pub fn jwt_validation_failure() {
        AUTH_OPERATIONS
            .with_label_values(&["jwt_validate", FAILURE])
            .inc();
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
        DB_OPERATIONS
            .with_label_values(&["connection_acquire", SUCCESS])
            .inc();
    }

    pub fn connection_failed() {
        DB_OPERATIONS
            .with_label_values(&["connection_acquire", FAILURE])
            .inc();
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
        EXTERNAL_CALLS
            .with_label_values(&["redis", operation, SUCCESS])
            .inc();
    }

    pub fn redis_failure(operation: &str) {
        EXTERNAL_CALLS
            .with_label_values(&["redis", operation, FAILURE])
            .inc();
    }

    // Email operations
    pub fn email_success(email_type: &str) {
        EXTERNAL_CALLS
            .with_label_values(&["email", email_type, SUCCESS])
            .inc();
    }

    pub fn email_failure(error_type: &str) {
        EXTERNAL_CALLS
            .with_label_values(&["email", "send", error_type])
            .inc();
    }
}

// =============================================================================
// SECURITY METRICS
// =============================================================================

pub mod security {
    use super::*;

    pub fn rate_limit_blocked() {
        SECURITY_EVENTS
            .with_label_values(&["rate_limit_blocked"])
            .inc();
    }

    pub fn rate_limit_fail_open() {
        SECURITY_EVENTS
            .with_label_values(&["rate_limit_fail_open"])
            .inc();
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
        
        // Record at least one value for each metric type to ensure they appear
        http::request("/test", "GET", 200);
        let _timer = http::timer("/test");
        drop(_timer);
        auth::login_success();
        db::query_success("test");
        external::redis_success("test");
        security::rate_limit_blocked();
        errors::configuration();
        db::pool_configured(10);
        
        // Verify all metrics are initialized and present in output
        let output = gather();
        assert!(output.contains("http_requests_total"));
        assert!(output.contains("http_request_duration_seconds"));
        assert!(output.contains("auth_operations_total"));
        assert!(output.contains("db_operations_total"));
        assert!(output.contains("external_calls_total"));
        assert!(output.contains("security_events_total"));
        assert!(output.contains("errors_total"));
        assert!(output.contains("db_pool_size"));
    }

    #[test]
    fn test_http_request_metrics() {
        init();
        http::request("/login", "POST", 200);
        http::request("/register", "POST", 201);
        http::request("/logout", "POST", 400);
        
        let output = gather();
        assert!(output.contains("http_requests_total"));
        assert!(output.contains("/login"));
        assert!(output.contains("POST"));
    }

    #[test]
    fn test_http_timer() {
        init();
        let timer = http::timer("/test");
        drop(timer); // Timer records when dropped
        
        let output = gather();
        assert!(output.contains("http_request_duration_seconds"));
    }

    #[test]
    fn test_auth_operations_success_metrics() {
        init();
        auth::login_success();
        auth::register_success();
        auth::logout_success();
        auth::token_refresh_success();
        auth::activation_success();
        auth::jwt_validation_success();
        auth::password_reset_request();
        auth::password_reset_confirm();
        
        let output = gather();
        assert!(output.contains("auth_operations_total"));
        assert!(output.contains("success"));
    }

    #[test]
    fn test_auth_operations_failure_metrics() {
        init();
        auth::login_failure();
        auth::register_failure();
        auth::logout_failure();
        auth::token_refresh_failure();
        auth::activation_failure();
        auth::jwt_validation_failure();
        auth::password_reset_failure();
        
        let output = gather();
        assert!(output.contains("auth_operations_total"));
        assert!(output.contains("failure"));
    }

    #[test]
    fn test_db_operations_metrics() {
        init();
        db::query_success("find_user");
        db::query_failure("update_user");
        db::connection_acquired();
        db::connection_failed();
        
        let output = gather();
        assert!(output.contains("db_operations_total"));
        assert!(output.contains("find_user"));
    }

    #[test]
    fn test_db_pool_metrics() {
        init();
        db::pool_configured(25);
        db::pool_configured(50);
        
        let output = gather();
        assert!(output.contains("db_pool_size"));
        assert!(output.contains("max"));
    }

    #[test]
    fn test_redis_operations_metrics() {
        init();
        external::redis_success("get");
        external::redis_success("set");
        external::redis_failure("get");
        
        let output = gather();
        assert!(output.contains("external_calls_total"));
        assert!(output.contains("redis"));
    }

    #[test]
    fn test_email_operations_metrics() {
        init();
        external::email_success("activation");
        external::email_success("password_reset");
        external::email_failure("smtp_error");
        
        let output = gather();
        assert!(output.contains("external_calls_total"));
        assert!(output.contains("email"));
    }

    #[test]
    fn test_security_metrics() {
        init();
        security::rate_limit_blocked();
        security::rate_limit_blocked();
        security::rate_limit_fail_open();
        
        let output = gather();
        assert!(output.contains("security_events_total"));
        assert!(output.contains("rate_limit_blocked"));
        assert!(output.contains("rate_limit_fail_open"));
    }

    #[test]
    fn test_error_metrics_all_types() {
        init();
        errors::configuration();
        errors::database();
        errors::validation();
        errors::authentication();
        errors::external();
        errors::internal();
        
        let output = gather();
        assert!(output.contains("errors_total"));
        assert!(output.contains("configuration"));
        assert!(output.contains("database"));
        assert!(output.contains("validation"));
        assert!(output.contains("authentication"));
        assert!(output.contains("external"));
        assert!(output.contains("internal"));
    }

    #[test]
    fn test_gather_returns_valid_prometheus_format() {
        init();
        
        // Add a metric to ensure output is not empty
        auth::login_success();
        
        let output = gather();
        
        // Should contain HELP or TYPE comments
        assert!(output.contains("# HELP") || output.contains("# TYPE"));
        
        // Should not contain error messages
        assert!(!output.starts_with("# Error"));
        assert!(!output.contains("Error collecting metrics"));
    }

    #[test]
    fn test_gather_handles_no_recorded_metrics() {
        init();
        let output = gather();
        // Should not error even with no metrics recorded
        assert!(!output.starts_with("# Error"));
    }

    #[test]
    fn test_multiple_calls_increment_counters() {
        init();
        
        // Call same metric multiple times
        auth::login_success();
        auth::login_success();
        auth::login_success();
        
        let output = gather();
        assert!(output.contains("auth_operations_total"));
        // Should have incremented (value would be at least 3)
    }

    #[test]
    fn test_metrics_with_different_labels() {
        init();
        
        // Same metric type, different labels
        db::query_success("select");
        db::query_success("insert");
        db::query_success("update");
        db::query_failure("delete");
        
        let output = gather();
        assert!(output.contains("db_operations_total"));
    }

    #[test]
    fn test_http_metrics_with_various_status_codes() {
        init();
        
        http::request("/api/test", "GET", 200);
        http::request("/api/test", "GET", 404);
        http::request("/api/test", "POST", 500);
        http::request("/api/test", "DELETE", 204);
        
        let output = gather();
        assert!(output.contains("http_requests_total"));
    }

    #[test]
    fn test_lazy_lock_initialization_is_safe() {
        // Multiple init calls should be safe
        init();
        init();
        init();
        
        // Add a metric to ensure output
        auth::login_success();
        
        let output = gather();
        assert!(output.contains("http_requests_total") || output.contains("auth_operations_total"));
    }

    #[test]
    fn test_timer_drops_properly() {
        init();
        
        {
            let _timer = http::timer("/endpoint1");
            // Timer dropped here
        }
        
        {
            let _timer = http::timer("/endpoint2");
            // Timer dropped here
        }
        
        let output = gather();
        assert!(output.contains("http_request_duration_seconds"));
    }

    #[test]
    fn test_gauge_can_be_set_multiple_times() {
        init();
        
        db::pool_configured(10);
        db::pool_configured(20);
        db::pool_configured(30);
        
        let output = gather();
        assert!(output.contains("db_pool_size"));
        // Last value should be 30
    }

    #[test]
    fn test_metrics_output_is_not_empty_with_data() {
        init();
        
        // Add at least one metric
        auth::login_success();
        
        let output = gather();
        assert!(!output.is_empty());
        assert!(output.len() > 100); // Should have substantial content
    }
}