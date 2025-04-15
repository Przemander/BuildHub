//! Prometheus metrics for the BuildHub authentication service.
//!
//! This module gathers a variety of metrics (counters, gauges, histograms)
//! covering authentication, token operations, database and Redis usage,
//! email transactions, HTTP request measurements, logging statistics, and
//! user operations. Its data helps monitor performance, reliability, and usage.
//!
//! Usage:
//! 1. Call `metrics::init()` during startup to force initialization.
//! 2. Use `gather_metrics()` to output the metrics in Prometheus text format,
//!    for instance via a `/metrics` HTTP endpoint.
//! 3. Update metrics as needed in your code by importing the appropriate static ref.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_histogram, register_histogram_vec, register_gauge,
    register_gauge_vec, CounterVec, Histogram, HistogramVec, Gauge, GaugeVec, Registry, Encoder,
    TextEncoder,
};
use std::sync::Mutex;

// Global registry for all metrics.
lazy_static! {
    static ref REGISTRY: Mutex<Registry> = Mutex::new(Registry::new());
}

// ===== Authentication Metrics =====
lazy_static! {
    /// Tracks login attempts by result (e.g. "success" or "failure").
    pub static ref AUTH_LOGIN_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_login_attempts_total", 
        "Number of login attempts",
        &["result"]
    ).unwrap();

    /// Tracks registration attempts by result.
    pub static ref AUTH_REGISTRATIONS: CounterVec = register_counter_vec!(
        "auth_registrations_total", 
        "Number of registration attempts",
        &["result"]
    ).unwrap();

    /// Tracks account activations by result.
    pub static ref AUTH_ACTIVATIONS: CounterVec = register_counter_vec!(
        "auth_activations_total", 
        "Number of account activation attempts",
        &["result"]
    ).unwrap();

    /// Tracks password reset operations.
    pub static ref AUTH_PASSWORD_RESETS: CounterVec = register_counter_vec!(
        "auth_password_resets_total", 
        "Number of password reset operations",
        &["operation", "result"]
    ).unwrap();
}

// ===== JWT Authentication Metrics =====
lazy_static! {
    /// Tracks total JWT authentication attempts.
    pub static ref JWT_AUTH_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_jwt_auth_attempts_total",
        "Total number of JWT authentication attempts",
        &["result"] // e.g. "attempt"
    ).unwrap();

    /// Tracks successful JWT authentications.
    pub static ref JWT_AUTH_SUCCESS: CounterVec = register_counter_vec!(
        "auth_jwt_auth_success_total",
        "Total number of successful JWT authentications",
        &["result"] // e.g. "success"
    ).unwrap();

    /// Tracks failed JWT authentications.
    pub static ref JWT_AUTH_FAILURE: CounterVec = register_counter_vec!(
        "auth_jwt_auth_failure_total",
        "Total number of failed JWT authentications",
        &["reason"] // e.g. "missing_header", "invalid_format", etc.
    ).unwrap();
}

// ===== Token Metrics =====
lazy_static! {
    /// Tracks token operations by type and operation (e.g. "generate", "revoke").
    pub static ref TOKEN_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_token_operations_total", 
        "Number of token operations",
        &["type", "operation"]
    ).unwrap();

    /// Tracks token validations with results.
    pub static ref TOKEN_VALIDATIONS: CounterVec = register_counter_vec!(
        "auth_token_validations_total", 
        "Number of token validations",
        &["result"]
    ).unwrap();

    /// Tracks currently active tokens by type.
    pub static ref ACTIVE_TOKENS: GaugeVec = register_gauge_vec!(
        "auth_active_tokens", 
        "Number of active tokens",
        &["type"]
    ).unwrap();
}

// ===== Database Metrics =====
lazy_static! {
    /// Tracks database operations by type and result.
    pub static ref DB_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_db_operations_total", 
        "Number of database operations",
        &["operation", "result"]
    ).unwrap();

    /// Gauge indicating database health (1 = healthy, 0 = unhealthy).
    pub static ref DB_HEALTH: Gauge = register_gauge!(
        "auth_db_health", 
        "Database health status (1 = healthy, 0 = unhealthy)"
    ).unwrap();

    /// Tracks statistics of the database connection pool by state.
    pub static ref DB_POOL_SIZE: GaugeVec = register_gauge_vec!(
        "auth_db_pool", 
        "Database connection pool statistics",
        &["state"] // e.g. "in_use", "idle", "total"
    ).unwrap();
}

// ===== Redis/Cache Metrics =====
lazy_static! {
    /// Tracks Redis operations by type and result.
    pub static ref REDIS_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_redis_operations_total", 
        "Number of Redis operations",
        &["operation", "result"]
    ).unwrap();

    /// Gauge indicating Redis connection health (1 = connected, 0 = disconnected).
    pub static ref REDIS_HEALTH: Gauge = register_gauge!(
        "auth_redis_health", 
        "Redis connection health (1 = connected, 0 = disconnected)"
    ).unwrap();
}

// ===== Email Metrics =====
lazy_static! {
    /// Tracks emails sent grouped by type and result (e.g. "activation", "success").
    pub static ref EMAILS_SENT: CounterVec = register_counter_vec!(
        "auth_emails_sent_total", 
        "Number of emails sent",
        &["type", "result"]
    ).unwrap();
}

// ===== Request/Response Metrics =====
lazy_static! {
    /// Histogram measuring request durations (in seconds) by endpoint and status.
    pub static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "auth_request_duration_seconds", 
        "Request duration in seconds",
        &["endpoint", "status"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap();

    /// Counter for total HTTP requests by endpoint, method, and status.
    pub static ref REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "auth_requests_total", 
        "Total number of HTTP requests",
        &["endpoint", "method", "status"]
    ).unwrap();

    /// Gauge for currently active HTTP requests.
    pub static ref ACTIVE_REQUESTS: Gauge = register_gauge!(
        "auth_active_requests", 
        "Number of currently active requests"
    ).unwrap();
}

// ===== System Metrics =====
lazy_static! {
    /// Counts log entries generated, grouped by log level (e.g. "info", "error").
    pub static ref LOG_ENTRIES: CounterVec = register_counter_vec!(
        "auth_log_entries_total", 
        "Number of log entries generated",
        &["level"]
    ).unwrap();

    /// Histogram capturing log processing times (in seconds).
    pub static ref LOG_PROCESSING_TIME: Histogram = register_histogram!(
        "auth_log_processing_seconds", 
        "Time spent processing logs",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    ).unwrap();

    /// Tracks log channel usage (e.g. "accepted" versus "dropped").
    pub static ref LOG_CHANNEL_USAGE: CounterVec = register_counter_vec!(
        "auth_log_channel_usage", 
        "Log channel usage statistics",
        &["status"]
    ).unwrap();
}

// ===== User Metrics =====
lazy_static! {
    /// Gauge for total registered users.
    pub static ref TOTAL_USERS: Gauge = register_gauge!(
        "auth_total_users", 
        "Total number of registered users"
    ).unwrap();

    /// Gauge for active user sessions.
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "auth_active_sessions", 
        "Number of active user sessions"
    ).unwrap();

    /// Tracks user operations (e.g. update, delete) by operation name and result.
    pub static ref USER_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_user_operations_total", 
        "Number of user operations",
        &["operation", "result"]
    ).unwrap();
}

// ===== Validation Metrics =====
lazy_static! {
    /// Tracks input validation operations by field and result.
    pub static ref VALIDATION_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_validation_operations_total", 
        "Number of input validation operations",
        &["field", "result"]
    ).unwrap();

    /// Histogram capturing validation execution times (in seconds) per field.
    pub static ref VALIDATION_TIMING: HistogramVec = register_histogram_vec!(
        "auth_validation_seconds",
        "Time spent on input validation operations",
        &["field"],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
    ).unwrap();

    /// Gauge for application build information (e.g. version and commit).
    pub static ref APP_INFO: GaugeVec = register_gauge_vec!(
        "auth_app_info", 
        "Application build information",
        &["version", "commit"]
    ).unwrap();
}

/// Initialize all metrics.
/// Call this function early in the application startup to force registration.
pub fn init() {
    let _ = &AUTH_LOGIN_ATTEMPTS;
    let _ = &AUTH_REGISTRATIONS;
    let _ = &AUTH_ACTIVATIONS;
    let _ = &AUTH_PASSWORD_RESETS;
    let _ = &JWT_AUTH_ATTEMPTS;
    let _ = &JWT_AUTH_SUCCESS;
    let _ = &JWT_AUTH_FAILURE;
    let _ = &TOKEN_OPERATIONS;
    let _ = &TOKEN_VALIDATIONS;
    let _ = &ACTIVE_TOKENS;
    let _ = &DB_OPERATIONS;
    let _ = &DB_HEALTH;
    let _ = &DB_POOL_SIZE;
    let _ = &REDIS_OPERATIONS;
    let _ = &REDIS_HEALTH;
    let _ = &EMAILS_SENT;
    let _ = &REQUEST_DURATION;
    let _ = &REQUESTS_TOTAL;
    let _ = &ACTIVE_REQUESTS;
    let _ = &LOG_ENTRIES;
    let _ = &LOG_PROCESSING_TIME;
    let _ = &LOG_CHANNEL_USAGE;
    let _ = &TOTAL_USERS;
    let _ = &ACTIVE_SESSIONS;
    let _ = &USER_OPERATIONS;
    let _ = &VALIDATION_OPERATIONS;
    let _ = &VALIDATION_TIMING;
    let _ = &APP_INFO;
}

/// Retrieve the metrics registry.
/// This is used to expose the metrics via an HTTP endpoint.
pub fn get_registry() -> Registry {
    let registry = Registry::new();
    registry.register(Box::new(AUTH_LOGIN_ATTEMPTS.clone())).unwrap();
    registry.register(Box::new(AUTH_REGISTRATIONS.clone())).unwrap();
    registry.register(Box::new(AUTH_ACTIVATIONS.clone())).unwrap();
    registry.register(Box::new(AUTH_PASSWORD_RESETS.clone())).unwrap();
    registry.register(Box::new(JWT_AUTH_ATTEMPTS.clone())).unwrap();
    registry.register(Box::new(JWT_AUTH_SUCCESS.clone())).unwrap();
    registry.register(Box::new(JWT_AUTH_FAILURE.clone())).unwrap();
    registry.register(Box::new(TOKEN_OPERATIONS.clone())).unwrap();
    registry.register(Box::new(TOKEN_VALIDATIONS.clone())).unwrap();
    registry.register(Box::new(ACTIVE_TOKENS.clone())).unwrap();
    registry.register(Box::new(DB_OPERATIONS.clone())).unwrap();
    registry.register(Box::new(DB_HEALTH.clone())).unwrap();
    registry.register(Box::new(DB_POOL_SIZE.clone())).unwrap();
    registry.register(Box::new(REDIS_OPERATIONS.clone())).unwrap();
    registry.register(Box::new(REDIS_HEALTH.clone())).unwrap();
    registry.register(Box::new(EMAILS_SENT.clone())).unwrap();
    registry.register(Box::new(REQUEST_DURATION.clone())).unwrap();
    registry.register(Box::new(REQUESTS_TOTAL.clone())).unwrap();
    registry.register(Box::new(ACTIVE_REQUESTS.clone())).unwrap();
    registry.register(Box::new(LOG_ENTRIES.clone())).unwrap();
    registry.register(Box::new(LOG_PROCESSING_TIME.clone())).unwrap();
    registry.register(Box::new(LOG_CHANNEL_USAGE.clone())).unwrap();
    registry.register(Box::new(TOTAL_USERS.clone())).unwrap();
    registry.register(Box::new(ACTIVE_SESSIONS.clone())).unwrap();
    registry.register(Box::new(USER_OPERATIONS.clone())).unwrap();
    registry.register(Box::new(VALIDATION_OPERATIONS.clone())).unwrap();
    registry.register(Box::new(VALIDATION_TIMING.clone())).unwrap();
    registry.register(Box::new(APP_INFO.clone())).unwrap();
    registry
}

/// Gather metrics in Prometheus text format.
/// This can be used as the response body for a /metrics endpoint.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let registry = get_registry();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Update database health based on health checks.
/// A healthy database sets the gauge to 1.0, otherwise 0.0.
pub fn update_db_health(is_healthy: bool) {
    DB_HEALTH.set(if is_healthy { 1.0 } else { 0.0 });
}

/// Update Redis health based on connectivity checks.
pub fn update_redis_health(is_connected: bool) {
    REDIS_HEALTH.set(if is_connected { 1.0 } else { 0.0 });
}

/// Update user-related metrics with total registered and active sessions.
pub fn update_user_metrics(total_users: i64, active_sessions: i64) {
    TOTAL_USERS.set(total_users as f64);
    ACTIVE_SESSIONS.set(active_sessions as f64);
}

/// A simple request timer helper to measure request durations.
/// The timer starts when the request begins and is completed when the response is sent.
pub struct RequestTimer<'a> {
    timer: prometheus::HistogramTimer,
    endpoint: &'a str,
    status: &'a str,
}

impl<'a> RequestTimer<'a> {
    /// Starts a new timer for a given endpoint.
    pub fn start(endpoint: &'a str) -> Self {
        let timer = REQUEST_DURATION
            .with_label_values(&[endpoint, "unknown"])
            .start_timer();
        ACTIVE_REQUESTS.inc();
        Self {
            timer,
            endpoint,
            status: "unknown",
        }
    }
    
    /// Sets the response status code to be recorded.
    pub fn set_status(&mut self, status: &'a str) {
        self.status = status;
    }
    
    /// Completes the timer and records the request metrics.
    /// The method parameter is used to classify the request (e.g., "GET", "POST").
    pub fn complete(self, method: &str) {
        ACTIVE_REQUESTS.dec();
        REQUESTS_TOTAL
            .with_label_values(&[self.endpoint, method, self.status])
            .inc();
        // The timer automatically observes duration upon drop.
    }
}