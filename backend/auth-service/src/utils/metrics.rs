//! Prometheus metrics for the BuildHub authentication service.
//!
//! This module gathers a variety of metrics (counters, gauges, histograms)
//! covering authentication, token operations, database and Redis usage,
//! email transactions, HTTP request measurements, logging statistics, and
//! user operations. Its data helps monitor performance, reliability, and usage.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramVec,
    TextEncoder,
};
use once_cell::sync::Lazy;

// ===== Authentication Metrics =====
lazy_static! {
    pub static ref AUTH_LOGIN_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_login_attempts_total",
        "Number of login attempts",
        &["result"] // result: "success", "failure"
    ).expect("Failed to register AUTH_LOGIN_ATTEMPTS");

    pub static ref AUTH_REGISTRATIONS: CounterVec = register_counter_vec!(
        "auth_registrations_total",
        "Number of registration attempts",
        &["result"] // result: "success", "validation_error", "already_exists", "system_error"
    ).expect("Failed to register AUTH_REGISTRATIONS");

    pub static ref AUTH_ACTIVATIONS: CounterVec = register_counter_vec!(
        "auth_activations_total",
        "Number of account activation attempts",
        &["result"] // result: "success", "invalid_code", "user_not_found", "already_active", "system_error"
    ).expect("Failed to register AUTH_ACTIVATIONS");

    pub static ref AUTH_PASSWORD_RESETS: CounterVec = register_counter_vec!(
        "auth_password_resets_total",
        "Number of password reset operations",
        &["operation", "result"] // operation: "request", "complete"; result: "success", "failure"
    ).expect("Failed to register AUTH_PASSWORD_RESETS");

    pub static ref AUTH_LOGOUTS: CounterVec = register_counter_vec!(
        "auth_logouts_total",
        "Number of logout attempts",
        &["result"] // result: "success", "failure", "system_error"
    ).expect("Failed to register AUTH_LOGOUTS");

    pub static ref AUTH_REFRESHES: CounterVec = register_counter_vec!(
        "auth_refreshes_total",
        "Number of token refresh attempts",
        &["result"] // result: "success", "failure", "system_error", "expired", "revoked", "invalid_signature", "invalid", "wrong_type", "revoke_failed"
    ).expect("Failed to register AUTH_REFRESHES");
}

// ===== JWT Authentication Metrics =====
lazy_static! {
    pub static ref JWT_AUTH_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_jwt_auth_attempts_total",
        "Total number of JWT authentication attempts",
        &["result"] // result: "success", "failure"
    ).expect("Failed to register JWT_AUTH_ATTEMPTS");

    pub static ref JWT_AUTH_SUCCESS: CounterVec = register_counter_vec!(
        "auth_jwt_auth_success_total",
        "Total number of successful JWT authentications",
        &["result"] // result: "success"
    ).expect("Failed to register JWT_AUTH_SUCCESS");

    pub static ref JWT_AUTH_FAILURE: CounterVec = register_counter_vec!(
        "auth_jwt_auth_failure_total",
        "Total number of failed JWT authentications",
        &["reason"] // reason: "expired", "invalid", "revoked", etc.
    ).expect("Failed to register JWT_AUTH_FAILURE");
}

// ===== Token Metrics =====
lazy_static! {
    pub static ref TOKEN_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_token_operations_total",
        "Number of token operations",
        &["type", "operation"] // type: "access", "refresh", "any"; operation: "generate", "revoke", "error", etc.
    ).expect("Failed to register TOKEN_OPERATIONS");

    pub static ref TOKEN_VALIDATIONS: CounterVec = register_counter_vec!(
        "auth_token_validations_total",
        "Number of token validations",
        &["operation", "result"] // was just &["result"]
    ).expect("Failed to register TOKEN_VALIDATIONS");

    pub static ref ACTIVE_TOKENS: GaugeVec = register_gauge_vec!(
        "auth_active_tokens",
        "Number of active tokens",
        &["type"] // type: "access", "refresh"
    ).expect("Failed to register ACTIVE_TOKENS");
}

// ===== Database Metrics =====
lazy_static! {
    pub static ref DB_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_db_operations_total",
        "Number of database operations",
        &["operation", "result"] // operation: "connection", "query", "insert", "update", "migration"; result: "success", "failure", "attempt"
    ).expect("Failed to register DB_OPERATIONS");

    pub static ref DB_HEALTH: Gauge = register_gauge!(
        "auth_db_health",
        "Database health status (1 = healthy, 0 = unhealthy)"
    ).expect("Failed to register DB_HEALTH");

    pub static ref DB_POOL_SIZE: GaugeVec = register_gauge_vec!(
        "auth_db_pool",
        "Database connection pool statistics",
        &["state"] // state: "used", "idle"
    ).expect("Failed to register DB_POOL_SIZE");
}

// ===== Redis/Cache Metrics =====
lazy_static! {
    pub static ref REDIS_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_redis_operations_total",
        "Number of Redis operations",
        &["operation", "result"] // operation: "init", "get", "set_ex", "del", "ping", "block_token", "is_token_blocked", "connection"; result: "success", "failure", "not_found", "attempt"
    ).expect("Failed to register REDIS_OPERATIONS");

    pub static ref REDIS_HEALTH: Gauge = register_gauge!(
        "auth_redis_health",
        "Redis connection health (1 = connected, 0 = disconnected)"
    ).expect("Failed to register REDIS_HEALTH");
}

// ===== Email Metrics =====
lazy_static! {
    pub static ref EMAILS_SENT: CounterVec = register_counter_vec!(
        "auth_emails_sent_total",
        "Number of emails sent",
        &["type", "result"] // type: "activation", "reset", "config", "build", "addressing"; result: "success", "failure", "attempt"
    ).expect("Failed to register EMAILS_SENT");
}

// ===== Request/Response Metrics =====
lazy_static! {
    pub static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "auth_request_duration_seconds",
        "Request duration in seconds",
        &["endpoint", "status"], // endpoint: static route names only; status: HTTP status code as string
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).expect("Failed to register REQUEST_DURATION");

    pub static ref REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "auth_requests_total",
        "Total number of HTTP requests",
        &["endpoint", "method", "status"] // endpoint: static route names only; method: "GET", "POST", etc.; status: HTTP status code as string
    ).expect("Failed to register REQUESTS_TOTAL");

    pub static ref ACTIVE_REQUESTS: Gauge = register_gauge!(
        "auth_active_requests",
        "Number of currently active requests"
    ).expect("Failed to register ACTIVE_REQUESTS");
}

// ===== System Metrics =====
lazy_static! {
    pub static ref LOG_ENTRIES: CounterVec = register_counter_vec!(
        "auth_log_entries_total",
        "Number of log entries generated",
        &["level"] // level: "info", "warn", "error", "debug"
    ).expect("Failed to register LOG_ENTRIES");

    pub static ref LOG_PROCESSING_TIME: Histogram = register_histogram!(
        "auth_log_processing_seconds",
        "Time spent processing logs",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    ).expect("Failed to register LOG_PROCESSING_TIME");

    pub static ref LOG_CHANNEL_USAGE: CounterVec = register_counter_vec!(
        "auth_log_channel_usage",
        "Log channel usage statistics",
        &["status"] // status: "success", "failure"
    ).expect("Failed to register LOG_CHANNEL_USAGE");
}

// ===== User Metrics =====
lazy_static! {
    pub static ref TOTAL_USERS: Gauge = register_gauge!(
        "auth_total_users",
        "Total number of registered users"
    ).expect("Failed to register TOTAL_USERS");

    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "auth_active_sessions",
        "Number of active user sessions"
    ).expect("Failed to register ACTIVE_SESSIONS");
}

// ===== Validation Metrics =====
lazy_static! {
    pub static ref VALIDATION_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_validation_operations_total",
        "Number of input validation operations",
        &["field", "result"] // field: "username", "email", "password"; result: "success", "failure"
    ).expect("Failed to register VALIDATION_OPERATIONS");

    pub static ref VALIDATION_TIMING: HistogramVec = register_histogram_vec!(
        "auth_validation_seconds",
        "Time spent on input validation operations",
        &["field"], // field: "username", "email", "password"
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
    ).expect("Failed to register VALIDATION_TIMING");
}

// ===== Rate Limiting Metrics =====
pub static RATE_LIMIT_BLOCKS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "rate_limit_blocks",
        "Number of requests blocked by rate limiting",
        &["endpoint"]
    )
    .unwrap()
});

/// Initialize all metrics.
/// Call this function early in the application startup to force registration.
#[allow(dead_code)]
pub fn init() {
    let _ = &AUTH_LOGIN_ATTEMPTS;
    let _ = &AUTH_REGISTRATIONS;
    let _ = &AUTH_ACTIVATIONS;
    let _ = &AUTH_PASSWORD_RESETS;
    let _ = &AUTH_LOGOUTS;
    let _ = &AUTH_REFRESHES;
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
    let _ = &VALIDATION_OPERATIONS;
    let _ = &VALIDATION_TIMING;
    let _ = &RATE_LIMIT_BLOCKS;
}

/// Gather metrics in Prometheus text format.
/// This can be used as the response body for a /metrics endpoint.
#[allow(dead_code)]
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// A simple request timer helper to measure request durations.
/// The timer starts when the request begins and is completed when the response is sent.
///
/// # Usage
/// - Create with `RequestTimer::start(endpoint, method)`.
/// - Call `set_status()` before completion if you want to record a specific status code.
/// - Metrics are always recorded on drop, even if the handler returns early.
pub struct RequestTimer<'a> {
    timer: Option<prometheus::HistogramTimer>,
    endpoint: &'a str,
    method: &'a str,
    status: &'a str,
    completed: bool,
}

impl<'a> RequestTimer<'a> {
    /// Starts a new timer for a given endpoint and method.
    #[allow(dead_code)]
    pub fn start(endpoint: &'a str, method: &'a str) -> Self {
        let timer = REQUEST_DURATION
            .with_label_values(&[endpoint, "unknown"])
            .start_timer();
        ACTIVE_REQUESTS.inc();
        Self {
            timer: Some(timer),
            endpoint,
            method,
            status: "unknown",
            completed: false,
        }
    }

    /// Sets the response status code to be recorded.
    #[allow(dead_code)]
    pub fn set_status(&mut self, status: &'a str) {
        self.status = status;
    }

    /// Completes the timer and records the request metrics.
    #[allow(dead_code)]
    pub fn complete(mut self) {
        self.record();
        self.completed = true;
    }

    fn record(&mut self) {
        ACTIVE_REQUESTS.dec();
        REQUESTS_TOTAL
            .with_label_values(&[self.endpoint, self.method, self.status])
            .inc();
        if let Some(timer) = self.timer.take() {
            timer.observe_duration();
        }
    }
}

impl<'a> Drop for RequestTimer<'a> {
    fn drop(&mut self) {
        if !self.completed {
            self.record();
            self.completed = true;
        }
    }
}