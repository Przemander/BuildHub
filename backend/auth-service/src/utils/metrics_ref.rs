//! Prometheus metrics for the BuildHub Auth Service.
//!
//! Collects counters, gauges, and histograms for authentication, tokens,
//! database, cache, emails, HTTP requests, logging, users, and validation.

use once_cell::sync::Lazy;
use prometheus::{
    CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, TextEncoder,
    register_counter_vec, register_gauge, register_gauge_vec,
    register_histogram, register_histogram_vec, Encoder,
};

// ===== Authentication =====
static AUTH_LOGIN_ATTEMPTS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_login_attempts_total",
        "Number of login attempts",
        &["result"] // "success", "failure"
    ).unwrap()
});
static AUTH_REGISTRATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_registrations_total",
        "Number of registration attempts",
        &["result"] // various outcomes
    ).unwrap()
});
static AUTH_ACTIVATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_activations_total",
        "Number of account activation attempts",
        &["result"]
    ).unwrap()
});
static AUTH_PASSWORD_RESETS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_password_resets_total",
        "Number of password reset operations",
        &["operation", "result"]
    ).unwrap()
});
static AUTH_LOGOUTS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_logouts_total",
        "Number of logout attempts",
        &["result"]
    ).unwrap()
});
static AUTH_REFRESHES: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_refreshes_total",
        "Number of token refresh attempts",
        &["result"]
    ).unwrap()
});

// ===== JWT Authentication =====
static JWT_AUTH_ATTEMPTS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_jwt_auth_attempts_total",
        "Total number of JWT auth attempts",
        &["result"]
    ).unwrap()
});
static JWT_AUTH_SUCCESS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_jwt_auth_success_total",
        "Total successful JWT authentications",
        &["result"]
    ).unwrap()
});
static JWT_AUTH_FAILURE: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_jwt_auth_failure_total",
        "Total failed JWT authentications",
        &["reason"]
    ).unwrap()
});

// ===== Token Operations =====
static TOKEN_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_token_operations_total",
        "Number of token operations",
        &["type", "operation"]
    ).unwrap()
});
static TOKEN_VALIDATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_token_validations_total",
        "Number of token validations",
        &["operation", "result"]
    ).unwrap()
});
static ACTIVE_TOKENS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "auth_active_tokens",
        "Number of active tokens",
        &["type"]
    ).unwrap()
});

// ===== Database =====
static DB_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_db_operations_total",
        "Number of database operations",
        &["operation", "result"]
    ).unwrap()
});
static DB_HEALTH: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "auth_db_health",
        "Database health status (1=healthy)"
    ).unwrap()
});
static DB_POOL_SIZE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "auth_db_pool",
        "DB connection pool stats",
        &["state"]
    ).unwrap()
});

// ===== Redis/Cache =====
static REDIS_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_redis_operations_total",
        "Number of Redis operations",
        &["operation", "result"]
    ).unwrap()
});
static REDIS_HEALTH: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "auth_redis_health",
        "Redis connection health (1=connected)"
    ).unwrap()
});

// ===== Email =====
static EMAILS_SENT: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_emails_sent_total",
        "Number of emails sent",
        &["type", "result"]
    ).unwrap()
});

// ===== HTTP =====
static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "auth_request_duration_seconds",
        "Request duration in seconds",
        &["endpoint", "status"],
        vec![0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    ).unwrap()
});
static REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_requests_total",
        "Total HTTP requests",
        &["endpoint", "method", "status"]
    ).unwrap()
});
static ACTIVE_REQUESTS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "auth_active_requests",
        "Number of active HTTP requests"
    ).unwrap()
});

// ===== Logging =====
static LOG_ENTRIES: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_log_entries_total",
        "Number of log entries",
        &["level"]
    ).unwrap()
});
static LOG_PROCESSING_TIME: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "auth_log_processing_seconds",
        "Time spent processing logs",
        vec![0.001, 0.005, 0.01, 0.1]
    ).unwrap()
});
static LOG_CHANNEL_USAGE: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_log_channel_usage",
        "Log channel usage",
        &["status"]
    ).unwrap()
});

// ===== User & Validation =====
static TOTAL_USERS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "auth_total_users",
        "Total number of registered users"
    ).unwrap()
});
static ACTIVE_SESSIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "auth_active_sessions",
        "Number of active sessions"
    ).unwrap()
});
static VALIDATION_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_validation_operations_total",
        "Number of validation ops",
        &["field", "result"]
    ).unwrap()
});
static VALIDATION_TIMING: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "auth_validation_seconds",
        "Time spent on validations",
        &["field"],
        vec![0.0001, 0.001, 0.01, 0.1]
    ).unwrap()
});

// ===== Rate Limiting =====
static RATE_LIMIT_BLOCKS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "rate_limit_blocks",
        "Number of rate limit blocks",
        &["endpoint"]
    ).unwrap()
});

/// Initialize all metrics (call at startup).
pub fn init_metrics() {
    let _ = &*AUTH_LOGIN_ATTEMPTS;
    let _ = &*AUTH_REGISTRATIONS;
    let _ = &*AUTH_ACTIVATIONS;
    let _ = &*AUTH_PASSWORD_RESETS;
    let _ = &*AUTH_LOGOUTS;
    let _ = &*AUTH_REFRESHES;
    let _ = &*JWT_AUTH_ATTEMPTS;
    let _ = &*JWT_AUTH_SUCCESS;
    let _ = &*JWT_AUTH_FAILURE;
    let _ = &*TOKEN_OPERATIONS;
    let _ = &*TOKEN_VALIDATIONS;
    let _ = &*ACTIVE_TOKENS;
    let _ = &*DB_OPERATIONS;
    let _ = &*DB_HEALTH;
    let _ = &*DB_POOL_SIZE;
    let _ = &*REDIS_OPERATIONS;
    let _ = &*REDIS_HEALTH;
    let _ = &*EMAILS_SENT;
    let _ = &*REQUEST_DURATION;
    let _ = &*REQUESTS_TOTAL;
    let _ = &*ACTIVE_REQUESTS;
    let _ = &*LOG_ENTRIES;
    let _ = &*LOG_PROCESSING_TIME;
    let _ = &*LOG_CHANNEL_USAGE;
    let _ = &*TOTAL_USERS;
    let _ = &*ACTIVE_SESSIONS;
    let _ = &*VALIDATION_OPERATIONS;
    let _ = &*VALIDATION_TIMING;
    let _ = &*RATE_LIMIT_BLOCKS;
}

/// Gathers metrics in Prometheus text format for `/metrics` endpoint.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&prometheus::gather(), &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// RAII timer for HTTP request metrics.
pub struct RequestTimer<'a> {
    timer: Option<prometheus::HistogramTimer>,
    endpoint: &'a str,
    method: &'a str,
    status: &'a str,
}

impl<'a> RequestTimer<'a> {
    /// Start timing a request.
    pub fn start(endpoint: &'a str, method: &'a str) -> Self {
        let timer = REQUEST_DURATION
            .with_label_values(&[endpoint, "unknown"])
            .start_timer();
        ACTIVE_REQUESTS.inc();
        Self { timer: Some(timer), endpoint, method, status: "unknown" }
    }

    /// Record the status code before dropping.
    pub fn set_status(mut self, status: &'a str) -> Self {
        self.status = status;
        self
    }

    fn record(&mut self) {
        ACTIVE_REQUESTS.dec();
        prometheus::register_counter_vec!(REQUESTS_TOTAL.clone()).unwrap()
            .with_label_values(&[self.endpoint, self.method, self.status])
            .inc();
        if let Some(t) = self.timer.take() {
            t.observe_duration();
        }
    }
}

impl<'a> Drop for RequestTimer<'a> {
    fn drop(&mut self) {
        self.record();
    }
}
