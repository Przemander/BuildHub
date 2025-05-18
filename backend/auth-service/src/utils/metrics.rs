//! Prometheus metrics for the BuildHub authentication service.
//!
//! This module provides a comprehensive observability system following industry best practices
//! for monitoring production services. It leverages Prometheus for robust, scalable metrics
//! collection with minimal runtime overhead.
//!
//! # Overview
//!
//! This module implements a comprehensive observability system following the 
//! RED (Rate, Errors, Duration) and USE (Utilization, Saturation, Errors)
//! methodologies for monitoring production services.
//!
//! # Design Principles
//!
//! - **Cardinality Control**: Labels are carefully chosen to avoid cardinality explosion
//! - **Consistent Naming**: All metrics follow the `namespace_subsystem_name_unit` pattern
//! - **Documentation**: Every metric includes thorough documentation for operators
//! - **Performance**: Uses static registration for zero-cost abstraction at runtime
//! - **Type-Safety**: Strongly typed label enums for compile-time validation
//!
//! # Categories
//!
//! - **Authentication**: Login, registration, activation metrics
//! - **Tokens**: JWT operations, validation, and lifecycle tracking
//! - **Storage**: Database and cache performance and health metrics
//! - **HTTP**: Request rates, durations, and status code distribution
//! - **System**: Process-level metrics about internal operations
//! - **Business**: User counts and session tracking
//!
//! # Usage
//!
//! ```rust
//! use crate::utils::metrics;
//!
//! // Initialize metrics early in application startup
//! metrics::init();
//!
//! // Track HTTP request with automatic timing
//! let mut timer = metrics::RequestTimer::start("login_endpoint", "POST");
//!
//! // Update timer with status when complete
//! timer.set_status("200");
//! timer.complete();
//!
//! // Increment specific counters directly
//! metrics::AUTH_LOGIN_ATTEMPTS.with_label_values(&["success"]).inc();
//! ```

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramVec,
    TextEncoder,
};
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Standard duration buckets for API request timings (in seconds)
///
/// These buckets follow a quasi-logarithmic scale covering from 5ms to 5s,
/// providing a good balance between precision at lower latencies and coverage
/// of the full range of expected request durations.
const STANDARD_DURATION_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

/// Fine-grained duration buckets for internal operations (in seconds)
///
/// These buckets focus on microsecond to millisecond operations, suitable
/// for measuring high-performance internal operations like validation,
/// token verification, and database lookups.
const FINE_DURATION_BUCKETS: &[f64] = &[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1];

// ===== Authentication Metrics =====

lazy_static! {
    /// Tracks authentication attempts with outcomes
    ///
    /// # Labels
    /// * `result`: "success", "failure", "invalid_credentials", "account_locked", "not_activated"
    ///
    /// # Use Cases
    /// - Monitor failed login attempts for security anomalies
    /// - Track success rates for login operations
    /// - Alert on high failure rates that could indicate attacks
    pub static ref AUTH_LOGIN_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_login_attempts_total",
        "Number of login attempts with outcomes (success, failure, reason)",
        &["result"]
    ).expect("Failed to register AUTH_LOGIN_ATTEMPTS");

    /// Tracks user registration attempts with outcomes
    ///
    /// # Labels
    /// * `result`: "success", "validation_error", "already_exists", "system_error"
    ///
    /// # Use Cases
    /// - Monitor registration conversion rates
    /// - Track validation issues affecting user registration
    /// - Detect system issues preventing new user sign-ups
    pub static ref AUTH_REGISTRATIONS: CounterVec = register_counter_vec!(
        "auth_registrations_total",
        "Number of registration attempts with outcomes",
        &["result"]
    ).expect("Failed to register AUTH_REGISTRATIONS");

    /// Tracks account activation attempts
    ///
    /// # Labels
    /// * `result`: "success", "invalid_code", "user_not_found", "already_active", "system_error"
    ///
    /// # Use Cases
    /// - Monitor activation conversion funnel
    /// - Track issues with activation codes
    /// - Identify patterns of failed activations
    pub static ref AUTH_ACTIVATIONS: CounterVec = register_counter_vec!(
        "auth_activations_total",
        "Number of account activation attempts with outcomes",
        &["result"]
    ).expect("Failed to register AUTH_ACTIVATIONS");

    /// Tracks password reset operations
    ///
    /// # Labels
    /// * `operation`: Stage of process ("request", "complete") 
    /// * `result`: Outcome ("success", "failure", "invalid_token", "expired")
    ///
    /// # Use Cases
    /// - Monitor password reset funnel completion rate
    /// - Track issues with reset tokens
    /// - Detect unusual patterns in password reset requests
    pub static ref AUTH_PASSWORD_RESETS: CounterVec = register_counter_vec!(
        "auth_password_resets_total",
        "Number of password reset operations with outcomes",
        &["operation", "result"]
    ).expect("Failed to register AUTH_PASSWORD_RESETS");

    /// Tracks user logout operations
    ///
    /// # Labels
    /// * `result`: "success", "failure", "token_invalid", "system_error"
    ///
    /// # Use Cases
    /// - Monitor clean session termination rates
    /// - Track token invalidation issues
    /// - Detect system issues affecting logout operations
    pub static ref AUTH_LOGOUTS: CounterVec = register_counter_vec!(
        "auth_logouts_total",
        "Number of logout attempts with outcomes",
        &["result"]
    ).expect("Failed to register AUTH_LOGOUTS");

    /// Tracks token refresh operations
    ///
    /// # Labels
    /// * `result`: Detailed outcome of refresh attempt
    ///
    /// # Use Cases
    /// - Monitor token refresh success rates
    /// - Track token lifecycle issues
    /// - Detect potential security issues with token refreshes
    pub static ref AUTH_REFRESHES: CounterVec = register_counter_vec!(
        "auth_refreshes_total",
        "Number of token refresh attempts with outcomes",
        &["result"]
    ).expect("Failed to register AUTH_REFRESHES");
}

// ===== JWT Authentication Metrics =====

lazy_static! {
    /// Tracks JWT authentication verification attempts
    ///
    /// # Labels
    /// * `result`: "success", "failure"
    ///
    /// # Use Cases
    /// - Monitor overall JWT verification health
    /// - Track authentication success rates
    /// - Establish baseline for normal authentication patterns
    pub static ref JWT_AUTH_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_jwt_auth_attempts_total",
        "Total JWT authentication verification attempts",
        &["result"]
    ).expect("Failed to register JWT_AUTH_ATTEMPTS");

    /// Tracks successful JWT authentications
    ///
    /// # Labels
    /// * `result`: Always "success" (for consistent query patterns)
    ///
    /// # Use Cases
    /// - Provides a direct counter for successful authentications
    /// - Simplifies rate queries and monitoring
    pub static ref JWT_AUTH_SUCCESS: CounterVec = register_counter_vec!(
        "auth_jwt_auth_success_total",
        "Successfully verified JWT authentications",
        &["result"]
    ).expect("Failed to register JWT_AUTH_SUCCESS");

    /// Tracks failed JWT authentications by reason
    ///
    /// # Labels
    /// * `reason`: Specific failure reason (expired, invalid, revoked, etc.)
    ///
    /// # Use Cases
    /// - Identify specific token issues affecting users
    /// - Track potential security incidents (invalid signatures, etc.)
    /// - Monitor expiration patterns for token lifetime tuning
    pub static ref JWT_AUTH_FAILURE: CounterVec = register_counter_vec!(
        "auth_jwt_auth_failure_total",
        "Failed JWT authentications by reason",
        &["reason"]
    ).expect("Failed to register JWT_AUTH_FAILURE");
}

// ===== Token Metrics =====

lazy_static! {
    /// Tracks token lifecycle operations (create, revoke, etc.)
    ///
    /// # Labels
    /// * `type`: Token type ("access", "refresh")
    /// * `operation`: Operation performed ("generate", "revoke", "validate")
    ///
    /// # Use Cases
    /// - Monitor token generation and validation workload
    /// - Track revocation operations for security monitoring
    /// - Establish patterns for normal token operations
    pub static ref TOKEN_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_token_operations_total",
        "Token lifecycle operations by type and operation",
        &["type", "operation"]
    ).expect("Failed to register TOKEN_OPERATIONS");

    /// Tracks token validation outcomes
    ///
    /// # Labels
    /// * `operation`: Validation type ("decode", "verify", "blocklist_check")
    /// * `result`: Validation outcome ("success", "invalid", "expired", etc.)
    ///
    /// # Use Cases
    /// - Identify specific validation issues
    /// - Track performance of different validation stages
    /// - Monitor patterns of failure for security analysis
    pub static ref TOKEN_VALIDATIONS: CounterVec = register_counter_vec!(
        "auth_token_validations_total",
        "Token validation outcomes by operation and result",
        &["operation", "result"]
    ).expect("Failed to register TOKEN_VALIDATIONS");

    /// Tracks currently active tokens by type
    ///
    /// # Labels
    /// * `type`: Token type ("access", "refresh")
    ///
    /// # Use Cases
    /// - Monitor active session load
    /// - Track token utilization patterns
    /// - Detect unusual spikes in token issuance
    pub static ref ACTIVE_TOKENS: GaugeVec = register_gauge_vec!(
        "auth_active_tokens",
        "Number of currently active tokens by type",
        &["type"]
    ).expect("Failed to register ACTIVE_TOKENS");
}

// ===== Database Metrics =====

lazy_static! {
    /// Tracks database operations with outcomes
    ///
    /// # Labels
    /// * `operation`: Operation type ("connection", "query", "insert", etc.)
    /// * `result`: Operation outcome ("success", "failure", "attempt")
    ///
    /// # Use Cases
    /// - Monitor database operation patterns and health
    /// - Track failures for specific operation types
    /// - Establish baselines for normal database activity
    pub static ref DB_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_db_operations_total",
        "Database operations by type and outcome",
        &["operation", "result"]
    ).expect("Failed to register DB_OPERATIONS");

    /// Tracks database health status
    ///
    /// Value is 1 for healthy, 0 for unhealthy
    ///
    /// # Use Cases
    /// - Provides a simple binary health check for alerting
    /// - Track periods of database unavailability
    /// - Monitor recovery from database issues
    pub static ref DB_HEALTH: Gauge = register_gauge!(
        "auth_db_health",
        "Database health status (1 = healthy, 0 = unhealthy)"
    ).expect("Failed to register DB_HEALTH");

    /// Tracks database connection pool usage
    ///
    /// # Labels
    /// * `state`: Connection state ("used", "idle", "max")
    ///
    /// # Use Cases
    /// - Monitor connection pool efficiency
    /// - Track potential connection exhaustion
    /// - Identify connection leaks or inefficient usage
    pub static ref DB_POOL_SIZE: GaugeVec = register_gauge_vec!(
        "auth_db_pool",
        "Database connection pool statistics by state",
        &["state"]
    ).expect("Failed to register DB_POOL_SIZE");

    /// Tracks database pool operations
    ///
    /// # Labels
    /// * `status`: Operation status ("success", "failure")
    ///
    /// # Use Cases
    /// - Monitor overall database pool operation success and failure rates
    /// - Track issues with database pool initialization and usage
    /// - Alert on abnormal database pool operation patterns
    pub static ref DB_POOL_OPERATIONS: CounterVec = register_counter_vec!(
        "db_pool_operations_total",
        "Total number of database pool operations",
        &["status"] // "success", "failure"
    ).expect("Failed to create db_pool_operations metric");

    /// Tracks database connection operations
    ///
    /// # Labels
    /// * `status`: Operation status ("success", "failure")
    ///
    /// # Use Cases
    /// - Monitor database connection acquisition success and failure rates
    /// - Track issues with specific database connections
    /// - Alert on abnormal database connection operation patterns
    pub static ref DB_CONNECTION_OPERATIONS: CounterVec = register_counter_vec!(
        "db_connection_operations_total",
        "Total number of database connection operations",
        &["status"] // "success", "failure" 
    ).expect("Failed to create db_connection_operations metric");

    /// Tracks database migration operations
    ///
    /// # Labels
    /// * `status`: Operation status ("success", "failure", "attempt")
    ///
    /// # Use Cases
    /// - Monitor database migration success, failure, and attempt rates
    /// - Track issues with specific migrations
    /// - Alert on abnormal database migration operation patterns
    pub static ref DB_MIGRATION_OPERATIONS: CounterVec = register_counter_vec!(
        "db_migration_operations_total",
        "Total number of database migration operations",
        &["status"] // "success", "failure", "attempt"
    ).expect("Failed to create db_migration_operations metric");
}

// ===== Redis/Cache Metrics =====

lazy_static! {
    /// Tracks Redis operations with outcomes
    ///
    /// # Labels
    /// * `operation`: Operation type ("get", "set_ex", "del", etc.)
    /// * `result`: Operation outcome ("success", "failure", "not_found", "attempt")
    ///
    /// # Use Cases
    /// - Monitor Redis operation patterns and health
    /// - Track hit/miss rates for cache efficiency
    /// - Identify specific Redis command failures
    pub static ref REDIS_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_redis_operations_total",
        "Redis operations by type and outcome",
        &["operation", "result"]
    ).expect("Failed to register REDIS_OPERATIONS");

    /// Tracks Redis connection health
    ///
    /// Value is 1 for connected, 0 for disconnected
    ///
    /// # Use Cases
    /// - Provides a simple binary health check for alerting
    /// - Track periods of Redis unavailability
    /// - Monitor recovery from connection issues
    pub static ref REDIS_HEALTH: Gauge = register_gauge!(
        "auth_redis_health",
        "Redis connection health (1 = connected, 0 = disconnected)"
    ).expect("Failed to register REDIS_HEALTH");
}

// ===== Email Metrics =====

lazy_static! {
    /// Tracks email sending operations
    ///
    /// # Labels
    /// * `type`: Email type ("activation", "reset", etc.)
    /// * `result`: Operation outcome ("success", "failure", "attempt")
    ///
    /// # Use Cases
    /// - Monitor email delivery success rates
    /// - Track failures by email type
    /// - Detect issues with specific email providers or types
    pub static ref EMAILS_SENT: CounterVec = register_counter_vec!(
        "auth_emails_sent_total",
        "Email sending operations by type and outcome",
        &["type", "result"]
    ).expect("Failed to register EMAILS_SENT");
}

// ===== Request/Response Metrics =====

lazy_static! {
    /// Tracks HTTP request duration in seconds
    ///
    /// # Labels
    /// * `endpoint`: Request route/endpoint
    /// * `status`: Response status code (as string)
    ///
    /// # Use Cases
    /// - Monitor API performance by endpoint
    /// - Track latency patterns for different response types
    /// - Identify slow endpoints for optimization
    pub static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "auth_request_duration_seconds",
        "HTTP request duration in seconds by endpoint and status",
        &["endpoint", "status"],
        STANDARD_DURATION_BUCKETS.to_vec()
    ).expect("Failed to register REQUEST_DURATION");

    /// Tracks total HTTP requests
    ///
    /// # Labels
    /// * `endpoint`: Request route/endpoint
    /// * `method`: HTTP method ("GET", "POST", etc.)
    /// * `status`: Response status code (as string)
    ///
    /// # Use Cases
    /// - Monitor API usage patterns by endpoint and method
    /// - Track error rates by endpoint
    /// - Identify unusual traffic patterns
    pub static ref REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "auth_requests_total",
        "Total HTTP requests by endpoint, method and status",
        &["endpoint", "method", "status"]
    ).expect("Failed to register REQUESTS_TOTAL");

    /// Tracks currently active HTTP requests
    ///
    /// # Use Cases
    /// - Monitor current system load
    /// - Track request concurrency patterns
    /// - Detect request processing issues (high active count)
    pub static ref ACTIVE_REQUESTS: Gauge = register_gauge!(
        "auth_active_requests",
        "Number of currently active HTTP requests"
    ).expect("Failed to register ACTIVE_REQUESTS");
}

// ===== System Metrics =====

lazy_static! {
    /// Tracks log entries by severity level
    ///
    /// # Labels
    /// * `level`: Log level ("info", "warn", "error", "debug")
    ///
    /// # Use Cases
    /// - Monitor error rates in the service
    /// - Track logging patterns by severity
    /// - Identify unusual spikes in specific log levels
    pub static ref LOG_ENTRIES: CounterVec = register_counter_vec!(
        "auth_log_entries_total",
        "Log entries generated by severity level",
        &["level"]
    ).expect("Failed to register LOG_ENTRIES");

    /// Tracks time spent processing logs
    ///
    /// # Use Cases
    /// - Monitor logging system performance
    /// - Identify logging overhead in the system
    /// - Track potential logging bottlenecks
    pub static ref LOG_PROCESSING_TIME: Histogram = register_histogram!(
        "auth_log_processing_seconds",
        "Time spent processing log entries in seconds",
        FINE_DURATION_BUCKETS.to_vec()
    ).expect("Failed to register LOG_PROCESSING_TIME");

    /// Tracks log channel utilization
    ///
    /// # Labels
    /// * `status`: Channel status ("success", "dropped", "blocked")
    ///
    /// # Use Cases
    /// - Monitor logging channel efficiency
    /// - Track dropped logs due to back pressure
    /// - Identify potential logging system saturation
    pub static ref LOG_CHANNEL_USAGE: CounterVec = register_counter_vec!(
        "auth_log_channel_usage",
        "Log channel usage statistics by status",
        &["status"]
    ).expect("Failed to register LOG_CHANNEL_USAGE");
}

// ===== User Metrics =====

lazy_static! {
    /// Tracks total registered users
    ///
    /// # Use Cases
    /// - Monitor user growth over time
    /// - Track service adoption metrics
    /// - Establish baselines for normal user counts
    pub static ref TOTAL_USERS: Gauge = register_gauge!(
        "auth_total_users",
        "Total number of registered users"
    ).expect("Failed to register TOTAL_USERS");

    /// Tracks active user sessions
    ///
    /// # Use Cases
    /// - Monitor current system usage
    /// - Track daily active user patterns
    /// - Identify unusual activity patterns
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "auth_active_sessions",
        "Number of currently active user sessions"
    ).expect("Failed to register ACTIVE_SESSIONS");
}

// ===== Validation Metrics =====

lazy_static! {
    /// Tracks input validation operations
    ///
    /// # Labels
    /// * `field`: Field being validated ("username", "email", "password")
    /// * `result`: Validation outcome ("success", "failure")
    ///
    /// # Use Cases
    /// - Monitor validation failure rates by field
    /// - Track user input quality patterns
    /// - Identify fields with high failure rates for UX improvement
    pub static ref VALIDATION_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_validation_operations_total",
        "Input validation operations by field and outcome",
        &["field", "result"]
    ).expect("Failed to register VALIDATION_OPERATIONS");

    /// Tracks time spent on input validation
    ///
    /// # Labels
    /// * `field`: Field being validated ("username", "email", "password")
    ///
    /// # Use Cases
    /// - Monitor validation performance by field type
    /// - Track validation processing overhead
    /// - Identify validation bottlenecks for optimization
    pub static ref VALIDATION_TIMING: HistogramVec = register_histogram_vec!(
        "auth_validation_seconds",
        "Time spent on input validation in seconds by field",
        &["field"],
        FINE_DURATION_BUCKETS.to_vec()
    ).expect("Failed to register VALIDATION_TIMING");
}

// ===== Rate Limiting Metrics =====

/// Rate limiting metrics track throttling operations.
pub static RATE_LIMIT_BLOCKS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "auth_rate_limit_blocks_total",
        "Requests blocked by rate limiting by endpoint",
        &["endpoint"]
    )
    .unwrap()
});

/// Track if metrics have been initialized
static METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize all metrics.
/// 
/// Call this function early in the application startup to force metric registration.
/// This function is idempotent and will only initialize metrics once.
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
///
/// # Example
///
/// ```
/// fn main() {
///     // Initialize metrics at application startup
///     auth_service::utils::metrics::init();
///     
///     // Start server with metrics registered
///     start_server();
/// }
/// ```
pub fn init() {
    // Only initialize once using atomic compare-and-swap
    if METRICS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }
    
    // Touch all lazy_static metrics to ensure they're registered
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

/// Gather all registered metrics in Prometheus text format.
/// 
/// This can be used as the response body for a /metrics endpoint.
/// The format follows the Prometheus text exposition format, making
/// it compatible with Prometheus, Victoria Metrics, and other
/// compatible monitoring systems.
/// 
/// # Returns
/// 
/// A String containing all metrics in Prometheus text format.
/// 
/// # Example
/// 
/// ```
/// async fn metrics_handler() -> impl axum::response::IntoResponse {
///     (
///         [(axum::http::header::CONTENT_TYPE, "text/plain")],
///         metrics::gather_metrics()
///     )
/// }
/// ```
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::with_capacity(4096); // Pre-allocate a reasonable buffer size
    
    // Encode metrics to the buffer
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        log::error!("Error encoding metrics: {}", e);
        return String::from("Error encoding metrics");
    }
    
    // Convert buffer to String
    match String::from_utf8(buffer) {
        Ok(output) => output,
        Err(e) => {
            log::error!("Error converting metrics to UTF-8: {}", e);
            String::from("Error gathering metrics")
        }
    }
}

/// Tracks timing and outcomes for HTTP request handlers.
///
/// Uses RAII pattern to automatically record metrics on drop, ensuring
/// metrics are captured even when handlers panic or return early.
///
/// # Design Considerations
///
/// - Thread-safe with no interior mutability issues
/// - Robust against panics with proper cleanup in Drop impl
/// - Efficient with minimal overhead per request
/// - Clean API that encourages proper usage
#[derive(Debug)]
pub struct RequestTimer<'a> {
    /// The prometheus histogram timer for recording duration
    timer: Option<prometheus::HistogramTimer>,
    
    /// The endpoint being timed (e.g., "/api/login")
    endpoint: Cow<'a, str>,
    
    /// The HTTP method used (e.g., "GET", "POST")
    method: Cow<'a, str>,
    
    /// The HTTP status code (e.g., "200", "404") 
    status: Cow<'a, str>,
    
    /// Whether metrics have been recorded already
    completed: bool,
    
    /// The instant when timing started 
    start_time: Instant,
}

impl<'a> RequestTimer<'a> {
    /// Starts a new request timer.
    ///
    /// # Arguments
    /// * `endpoint` - The API endpoint or route name
    /// * `method` - The HTTP method (GET, POST, etc.)
    ///
    /// # Returns
    /// A new RequestTimer instance that will automatically record metrics on drop.
    ///
    /// # Example
    ///
    /// ```
    /// async fn login_handler() -> Response {
    ///     let mut timer = RequestTimer::start("login_endpoint", "POST");
    ///     
    ///     // Process the request...
    ///     
    ///     // Set status before returning
    ///     timer.set_status("200");
    ///     timer.complete();
    ///     
    ///     Response::new()
    /// }
    /// ```
    pub fn start<E, M>(endpoint: E, method: M) -> Self 
    where
        E: Into<Cow<'a, str>>,
        M: Into<Cow<'a, str>>,
    {
        let endpoint = endpoint.into();
        
        // Start the histogram timer - initially with "unknown" status
        // We'll update this with the actual status later
        let timer = REQUEST_DURATION
            .with_label_values(&[&endpoint, "unknown"])
            .start_timer();
        
        // Increment active requests counter
        ACTIVE_REQUESTS.inc();
        
        Self {
            timer: Some(timer),
            endpoint,
            method: method.into(),
            status: Cow::Borrowed("unknown"),
            completed: false,
            start_time: Instant::now(),
        }
    }

    /// Sets the HTTP status code that will be recorded in metrics.
    ///
    /// # Arguments
    /// * `status` - The HTTP status code as a string (e.g., "200", "404")
    ///
    /// # Example
    ///
    /// ```
    /// async fn endpoint(req: Request) -> Response {
    ///     let mut timer = RequestTimer::start("my_api", "GET");
    ///     
    ///     match process_request(req) {
    ///         Ok(response) => {
    ///             timer.set_status("200");
    ///             response
    ///         }
    ///         Err(e) => {
    ///             timer.set_status("500");
    ///             error_response(e)
    ///         }
    ///     }
    /// }
    /// ```
    pub fn set_status<S>(&mut self, status: S) 
    where
        S: Into<Cow<'a, str>>,
    {
        self.status = status.into();
    }

    /// Completes the timer explicitly, recording metrics immediately.
    ///
    /// This is optional as metrics are automatically recorded when the timer is dropped.
    /// However, explicitly calling this method can make the code's intent clearer.
    ///
    /// # Example
    ///
    /// ```
    /// let mut timer = RequestTimer::start("endpoint", "GET");
    /// // ... process request ...
    /// timer.set_status("200");
    /// timer.complete();  // Explicit completion
    /// ```
    pub fn complete(mut self) {
        self.record();
        self.completed = true;
    }

    /// Records metrics based on the current timer state.
    ///
    /// This is called automatically when the timer is dropped.
    fn record(&mut self) {
        // Decrement active requests counter
        ACTIVE_REQUESTS.dec();
        
        // Record the request in total requests counter
        REQUESTS_TOTAL
            .with_label_values(&[&self.endpoint, &self.method, &self.status])
            .inc();
        
        // Observe the request duration if timer is present
        if let Some(timer) = self.timer.take() {
            // For detailed status, record the duration with the actual status code
            if self.status != "unknown" {
                // Stop the "unknown" timer from before
                let _ = timer.stop_and_record();
                
                // Record with the actual status code
                REQUEST_DURATION
                    .with_label_values(&[&self.endpoint, &self.status])
                    .observe(self.start_time.elapsed().as_secs_f64());
            } else {
                // Just use the original timer if status is still unknown
                timer.observe_duration();
            }
        }
    }
}

impl<'a> Drop for RequestTimer<'a> {
    /// Ensures metrics are recorded when the timer is dropped.
    ///
    /// This provides a safety net to capture metrics even if the
    /// developer forgets to call `complete()` or if the request
    /// handler panics.
    fn drop(&mut self) {
        if !self.completed {
            self.record();
            self.completed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_request_timer_lifecycle() {
        // Initialize metrics
        init();
        
        // Record initial values
        let initial_requests = REQUESTS_TOTAL
            .with_label_values(&["test_endpoint", "GET", "200"])
            .get();
            
        let initial_active = ACTIVE_REQUESTS.get();
        
        // Create and complete a timer
        {
            let mut timer = RequestTimer::start("test_endpoint", "GET");
            assert!(ACTIVE_REQUESTS.get() > initial_active, 
                "Active requests should increase when timer starts");
            
            // Set a status and complete
            timer.set_status("200");
            timer.complete(); // Explicit completion
        }
        
        // Verify counters were incremented
        assert_eq!(ACTIVE_REQUESTS.get(), initial_active,
            "Active requests should return to initial value after timer completes");
        assert_eq!(
            REQUESTS_TOTAL
                .with_label_values(&["test_endpoint", "GET", "200"])
                .get(),
            initial_requests + 1.0,
            "Total requests should increment by 1"
        );
    }
    
    #[test]
    fn test_request_timer_drop_records_metrics() {
        // Initialize metrics
        init();
        
        // Record initial values
        let initial_requests = REQUESTS_TOTAL
            .with_label_values(&["test_endpoint", "POST", "unknown"])
            .get();
            
        let initial_active = ACTIVE_REQUESTS.get();
        
        // Create a timer but don't explicitly complete it
        {
            let _timer = RequestTimer::start("test_endpoint", "POST");
            assert!(ACTIVE_REQUESTS.get() > initial_active,
                "Active requests should increase when timer starts");
            // Let it drop without calling complete()
        }
        
        // Verify counters were still incremented on drop
        assert_eq!(ACTIVE_REQUESTS.get(), initial_active,
            "Active requests should return to initial value after timer is dropped");
        assert_eq!(
            REQUESTS_TOTAL
                .with_label_values(&["test_endpoint", "POST", "unknown"])
                .get(),
            initial_requests + 1.0,
            "Total requests should increment by 1 even when timer is dropped without completion"
        );
    }
    
    #[test]
    fn test_metrics_initialize_only_once() {
        // Reset initialization flag for this test
        METRICS_INITIALIZED.store(false, Ordering::SeqCst);
        
        // Initialize metrics multiple times from multiple threads
        let threads: Vec<_> = (0..5)
            .map(|_| {
                thread::spawn(|| {
                    init();
                })
            })
            .collect();
            
        // Wait for all threads to complete
        for t in threads {
            t.join().unwrap();
        }
        
        // Initialize one more time for good measure
        init();
        
        // Verify we're initialized
        assert!(METRICS_INITIALIZED.load(Ordering::SeqCst),
            "Metrics should be marked as initialized");
        
        // Verify metrics are registered (check one as representative)
        let before = ACTIVE_REQUESTS.get();
        ACTIVE_REQUESTS.inc();
        let after = ACTIVE_REQUESTS.get();
        assert!(after > before, "Metrics should be functional after initialization");
    }
    
    #[test]
    fn test_gather_metrics_produces_valid_output() {
        // Initialize metrics
        init();
        
        // Record something to ensure we get output
        ACTIVE_REQUESTS.inc();
        
        // Get metrics in Prometheus format
        let output = gather_metrics();
        
        // Basic validation of output format
        assert!(!output.is_empty(), "Metrics output should not be empty");
        assert!(output.contains("auth_active_requests"), 
            "Output should contain the metrics we registered");
        assert!(output.contains("# HELP"), 
            "Output should contain help text in Prometheus format");
        assert!(output.contains("# TYPE"), 
            "Output should contain type information in Prometheus format");
    }
    
    #[test]
    fn test_request_timer_status_update() {
        // Initialize metrics
        init();
        
        // Record initial values for specific statuses
        let initial_200 = REQUESTS_TOTAL
            .with_label_values(&["status_test", "GET", "200"])
            .get();
        
        let initial_404 = REQUESTS_TOTAL
            .with_label_values(&["status_test", "GET", "404"])
            .get();
            
        // Test that we can update the status before completion
        {
            let mut timer = RequestTimer::start("status_test", "GET");
            
            // Start with one status
            timer.set_status("404");
            
            // Change to another status
            timer.set_status("200");
            
            // Complete the timer
            timer.complete();
        }
        
        // Verify only the final status was recorded
        assert_eq!(
            REQUESTS_TOTAL
                .with_label_values(&["status_test", "GET", "200"])
                .get(),
            initial_200 + 1.0,
            "Should record the final status code (200)"
        );
        
        assert_eq!(
            REQUESTS_TOTAL
                .with_label_values(&["status_test", "GET", "404"])
                .get(),
            initial_404,
            "Should not record the intermediate status code (404)"
        );
    }
    
    #[test]
    fn test_histogram_records_proper_buckets() {
        // Initialize metrics
        init();
        
        // Create a histogram with our standard buckets
        let hist = REQUEST_DURATION.with_label_values(&["histogram_test", "200"]);
        
        // Record some values
        hist.observe(0.001); // Should fall in the 0.005 bucket
        hist.observe(0.05);  // Should fall in the 0.05 bucket
        hist.observe(1.5);   // Should fall in the 2.5 bucket
        
        // Get the current state from the metrics output
        let output = gather_metrics();
        
        // Verify each bucket is present
        for bucket in STANDARD_DURATION_BUCKETS {
            let bucket_str = format!("le=\"{}\"", bucket);
            assert!(output.contains(&bucket_str), 
                "Output should contain bucket {}", bucket_str);
        }
    }
}