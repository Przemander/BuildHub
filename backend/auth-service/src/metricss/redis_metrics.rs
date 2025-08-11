//! # Redis Metrics - Production-Ready Redis Infrastructure Monitoring
//!
//! Comprehensive Redis monitoring for JWT blacklisting, rate limiting, account activation,
//! and password reset flows with full production-grade observability features.

use crate::log_info;
use lazy_static::lazy_static;
use prometheus::{register_gauge, register_gauge_vec};
use prometheus::{CounterVec, Gauge, GaugeVec, HistogramVec};
use redis::Client;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};

// Import only the core functions that actually exist
use super::core::{
    create_counter_vec, create_histogram_vec, observe_counter_vec, LATENCY_BUCKETS_MEDIUM,
};

// =============================================================================
// HELPER FUNCTIONS (To replace missing core functions)
// =============================================================================

/// Creates a Gauge metric with proper error handling
fn create_gauge(name: &str, help: &str) -> Result<Gauge, prometheus::Error> {
    register_gauge!(name, help)
}

/// Creates a GaugeVec metric with proper error handling
fn create_gauge_vec(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<GaugeVec, prometheus::Error> {
    register_gauge_vec!(name, help, labels)
}

/// Updates a gauge value with proper error handling
fn observe_gauge(gauge: &Gauge, value: f64) {
    gauge.set(value);
}

// =============================================================================
// METRIC DEFINITIONS
// =============================================================================

lazy_static! {
    /// Redis infrastructure health status (1=healthy, 0=down)
    pub static ref REDIS_HEALTH: Gauge = prometheus::register_gauge!(
        "redis_health",
        "Redis infrastructure health status (1=healthy, 0=down)"
    ).expect("Failed to register REDIS_HEALTH");

    /// Redis operations by operation type and result
    /// Labels: operation, result
    pub static ref REDIS_OPERATIONS: CounterVec = create_counter_vec(
        "redis_operations_total",
        "Redis operations by operation type and result",
        &["operation", "result"]
    ).expect("Failed to create REDIS_OPERATIONS metric");

    /// Redis operation duration by operation type
    /// Labels: operation
    pub static ref REDIS_OPERATION_DURATION: HistogramVec = create_histogram_vec(
        "redis_operation_duration_seconds",
        "Redis operation duration by operation type",
        &["operation"],
        LATENCY_BUCKETS_MEDIUM
    ).expect("Failed to create REDIS_OPERATION_DURATION metric");

    /// Redis connection pool statistics
    /// Labels: state (idle, active, total)
    pub static ref REDIS_CONNECTION_POOL: GaugeVec = create_gauge_vec(
        "redis_connection_pool",
        "Redis connection pool statistics",
        &["state"]
    ).expect("Failed to create REDIS_CONNECTION_POOL metric");

    /// Redis server memory usage in bytes
    pub static ref REDIS_MEMORY_USAGE: Gauge = create_gauge(
        "redis_memory_usage_bytes",
        "Redis server memory usage in bytes"
    ).expect("Failed to create REDIS_MEMORY_USAGE metric");

    /// Redis server key count
    pub static ref REDIS_KEYS_TOTAL: Gauge = create_gauge(
        "redis_keys_total",
        "Total number of keys in Redis database"
    ).expect("Failed to create REDIS_KEYS_TOTAL metric");
}

static REDIS_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn init_redis_metrics() {
    if REDIS_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&REDIS_HEALTH);
    lazy_static::initialize(&REDIS_OPERATIONS);
    lazy_static::initialize(&REDIS_OPERATION_DURATION);
    lazy_static::initialize(&REDIS_CONNECTION_POOL);
    lazy_static::initialize(&REDIS_MEMORY_USAGE);
    lazy_static::initialize(&REDIS_KEYS_TOTAL);

    // Set initial values for gauges
    REDIS_HEALTH.set(0.0);
    REDIS_CONNECTION_POOL.with_label_values(&["idle"]).set(0.0);
    REDIS_CONNECTION_POOL
        .with_label_values(&["active"])
        .set(0.0);
    REDIS_CONNECTION_POOL.with_label_values(&["total"]).set(0.0);
    REDIS_MEMORY_USAGE.set(0.0);
    REDIS_KEYS_TOTAL.set(0.0);

    log_info!(
        "Metrics",
        "Redis metrics initialized (enhanced production version)",
        "redis_metrics_init"
    );
}

// =============================================================================
// CORE API (Using standardized observation functions)
// =============================================================================

/// Sets Redis health status
pub fn set_redis_health(is_healthy: bool) {
    REDIS_HEALTH.set(if is_healthy { 1.0 } else { 0.0 });
}

/// Records a Redis operation result
pub fn record_redis_operation(operation: &str, result: &str) {
    observe_counter_vec(
        &REDIS_OPERATIONS,
        "redis_operations_total",
        &[operation, result],
    );
}

/// Creates a timer for measuring Redis operation duration
pub fn time_redis_operation(operation: &str) -> prometheus::HistogramTimer {
    // Note: Timers are automatically observed when dropped
    REDIS_OPERATION_DURATION
        .with_label_values(&[operation])
        .start_timer()
}

/// Updates Redis connection pool statistics
pub fn update_connection_pool_stats(idle: f64, active: f64, total: f64) {
    REDIS_CONNECTION_POOL.with_label_values(&["idle"]).set(idle);
    REDIS_CONNECTION_POOL
        .with_label_values(&["active"])
        .set(active);
    REDIS_CONNECTION_POOL
        .with_label_values(&["total"])
        .set(total);
}

/// Updates Redis memory usage metric
pub fn update_redis_memory_usage(bytes: f64) {
    observe_gauge(&REDIS_MEMORY_USAGE, bytes);
}

/// Updates Redis total keys count
pub fn update_redis_keys_total(count: f64) {
    observe_gauge(&REDIS_KEYS_TOTAL, count);
}

/// Sanitizes rate limit key to prevent cardinality explosion
pub fn sanitize_rate_limit_key(key: &str) -> String {
    // Define max key length to prevent cardinality explosion
    const MAX_KEY_LENGTH: usize = 100;

    // If key is too long, hash the excess portion
    if key.len() > MAX_KEY_LENGTH {
        let mut hasher = DefaultHasher::new();
        key[MAX_KEY_LENGTH..].hash(&mut hasher);
        let hash = hasher.finish();

        format!("{}_{:x}", &key[..MAX_KEY_LENGTH], hash)
    } else {
        key.to_string()
    }
}

/// Spawns a background task that periodically collects Redis server statistics
pub fn spawn_metrics_collector(client: Client) {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(60); // Collect every minute

        loop {
            collect_redis_stats(&client).await;
            tokio::time::sleep(interval).await;
        }
    });
}

// =============================================================================
// OPERATION CONSTANTS (Type-safe operation names)
// =============================================================================

pub mod operations {
    pub const HEALTH_CHECK: &str = "health_check";
    pub const BLOCK_TOKEN: &str = "block_token";
    pub const TOKEN_VALIDATION: &str = "token_validation";
    pub const ACTIVATION_STORE: &str = "activation_store";
    pub const ACTIVATION_VERIFY: &str = "activation_verify";
    pub const ACTIVATION_CLEANUP: &str = "activation_cleanup";
    pub const RESET_STORE: &str = "reset_store";
    pub const RESET_VERIFY: &str = "reset_verify";
    pub const RESET_CLEANUP: &str = "reset_cleanup";
    pub const RATE_LIMIT_CHECK: &str = "rate_limit_check";
    pub const RATE_LIMIT_EXPIRE: &str = "rate_limit_expire";
    pub const CLIENT_INIT: &str = "client_init";
    pub const CONNECTION_ACQUISITION: &str = "connection_acquisition";
}

pub mod results {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
    pub const BLOCKED: &str = "blocked";
    pub const VALID: &str = "valid";
    pub const NOT_FOUND: &str = "not_found";
    pub const ALLOWED: &str = "allowed";
    pub const CONNECTION_FAILURE: &str = "connection_failure";
    pub const COMMAND_FAILURE: &str = "command_failure";
    pub const UNEXPECTED_RESPONSE: &str = "unexpected_response";
}

// =============================================================================
// BACKGROUND METRICS COLLECTION
// =============================================================================

/// Collects Redis server statistics and updates metrics
async fn collect_redis_stats(client: &Client) {
    if let Ok(mut conn) = client.get_async_connection().await {
        // Get memory usage
        if let Ok(info) = redis::cmd("INFO")
            .arg("memory")
            .query_async::<_, String>(&mut conn)
            .await
        {
            if let Some(used_memory_str) = info
                .lines()
                .find(|line| line.starts_with("used_memory:"))
                .and_then(|line| line.split(':').nth(1))
            {
                if let Ok(memory) = used_memory_str.trim().parse::<f64>() {
                    update_redis_memory_usage(memory);
                }
            }
        }

        // Get client connection stats
        if let Ok(info) = redis::cmd("INFO")
            .arg("clients")
            .query_async::<_, String>(&mut conn)
            .await
        {
            let mut connected: f64 = 0.0;
            let mut blocked: f64 = 0.0;

            for line in info.lines() {
                if line.starts_with("connected_clients:") {
                    if let Some(val) = line
                        .split(':')
                        .nth(1)
                        .and_then(|s| s.trim().parse::<f64>().ok())
                    {
                        connected = val;
                    }
                } else if line.starts_with("blocked_clients:") {
                    if let Some(val) = line
                        .split(':')
                        .nth(1)
                        .and_then(|s| s.trim().parse::<f64>().ok())
                    {
                        blocked = val;
                    }
                }
            }

            update_connection_pool_stats(connected - blocked, blocked, connected);
        }

        // Get total keys count
        if let Ok(count) = redis::cmd("DBSIZE").query_async::<_, i64>(&mut conn).await {
            update_redis_keys_total(count as f64);
        }
    }
}

// =============================================================================
// HELPER MODULES (Complete implementation)
// =============================================================================

/// Health check helpers
pub mod health {
    use super::*;

    pub fn record_success() {
        record_redis_operation(operations::HEALTH_CHECK, results::SUCCESS);
    }

    pub fn record_connection_failure() {
        record_redis_operation(operations::HEALTH_CHECK, results::CONNECTION_FAILURE);
    }

    pub fn record_command_failure() {
        record_redis_operation(operations::HEALTH_CHECK, results::COMMAND_FAILURE);
    }

    pub fn record_unexpected_response() {
        record_redis_operation(operations::HEALTH_CHECK, results::UNEXPECTED_RESPONSE);
    }
}

/// JWT token helpers
pub mod jwt {
    use super::*;

    pub fn record_block_success() {
        record_redis_operation(operations::BLOCK_TOKEN, results::SUCCESS);
    }

    pub fn record_block_failure() {
        record_redis_operation(operations::BLOCK_TOKEN, results::FAILURE);
    }

    pub fn record_validation_blocked() {
        record_redis_operation(operations::TOKEN_VALIDATION, results::BLOCKED);
    }

    pub fn record_validation_valid() {
        record_redis_operation(operations::TOKEN_VALIDATION, results::VALID);
    }

    pub fn record_validation_failure() {
        record_redis_operation(operations::TOKEN_VALIDATION, results::FAILURE);
    }
}

/// Rate limiting helpers
pub mod rate_limit {
    use super::*;

    pub fn record_allowed() {
        record_redis_operation(operations::RATE_LIMIT_CHECK, results::ALLOWED);
    }

    pub fn record_blocked() {
        record_redis_operation(operations::RATE_LIMIT_CHECK, results::BLOCKED);
    }

    pub fn record_failure() {
        record_redis_operation(operations::RATE_LIMIT_CHECK, results::FAILURE);
    }
}

/// Activation flow helpers - complete set
pub mod activation {
    use super::*;

    pub fn record_store_success() {
        record_redis_operation(operations::ACTIVATION_STORE, results::SUCCESS);
    }

    pub fn record_store_failure() {
        record_redis_operation(operations::ACTIVATION_STORE, results::FAILURE);
    }

    pub fn record_verify_success() {
        record_redis_operation(operations::ACTIVATION_VERIFY, results::SUCCESS);
    }

    pub fn record_verify_failure() {
        record_redis_operation(operations::ACTIVATION_VERIFY, results::FAILURE);
    }

    pub fn record_verify_not_found() {
        record_redis_operation(operations::ACTIVATION_VERIFY, results::NOT_FOUND);
    }

    pub fn record_cleanup_success() {
        record_redis_operation(operations::ACTIVATION_CLEANUP, results::SUCCESS);
    }

    pub fn record_cleanup_failure() {
        record_redis_operation(operations::ACTIVATION_CLEANUP, results::FAILURE);
    }
}

/// Password reset flow helpers - complete set
pub mod reset {
    use super::*;

    pub fn record_store_success() {
        record_redis_operation(operations::RESET_STORE, results::SUCCESS);
    }

    pub fn record_store_failure() {
        record_redis_operation(operations::RESET_STORE, results::FAILURE);
    }

    pub fn record_verify_success() {
        record_redis_operation(operations::RESET_VERIFY, results::SUCCESS);
    }

    pub fn record_verify_failure() {
        record_redis_operation(operations::RESET_VERIFY, results::FAILURE);
    }

    pub fn record_verify_not_found() {
        record_redis_operation(operations::RESET_VERIFY, results::NOT_FOUND);
    }

    pub fn record_cleanup_success() {
        record_redis_operation(operations::RESET_CLEANUP, results::SUCCESS);
    }

    pub fn record_cleanup_failure() {
        record_redis_operation(operations::RESET_CLEANUP, results::FAILURE);
    }
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_health() {
        init_redis_metrics();

        set_redis_health(true);
        assert_eq!(REDIS_HEALTH.get(), 1.0);

        set_redis_health(false);
        assert_eq!(REDIS_HEALTH.get(), 0.0);
    }

    #[test]
    fn test_redis_operations() {
        init_redis_metrics();

        let before = REDIS_OPERATIONS
            .with_label_values(&[operations::HEALTH_CHECK, results::SUCCESS])
            .get();

        record_redis_operation(operations::HEALTH_CHECK, results::SUCCESS);

        let after = REDIS_OPERATIONS
            .with_label_values(&[operations::HEALTH_CHECK, results::SUCCESS])
            .get();

        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_redis_duration() {
        init_redis_metrics();

        let timer = time_redis_operation(operations::BLOCK_TOKEN);
        drop(timer); // Timer is observed when dropped

        let count = REDIS_OPERATION_DURATION
            .with_label_values(&[operations::BLOCK_TOKEN])
            .get_sample_count();
        assert!(count > 0);
    }

    #[test]
    fn test_connection_pool_metrics() {
        init_redis_metrics();

        update_connection_pool_stats(5.0, 2.0, 7.0);

        assert_eq!(
            REDIS_CONNECTION_POOL.with_label_values(&["idle"]).get(),
            5.0
        );
        assert_eq!(
            REDIS_CONNECTION_POOL.with_label_values(&["active"]).get(),
            2.0
        );
        assert_eq!(
            REDIS_CONNECTION_POOL.with_label_values(&["total"]).get(),
            7.0
        );
    }

    #[test]
    fn test_memory_usage_metrics() {
        init_redis_metrics();

        update_redis_memory_usage(1024.0 * 1024.0);

        assert_eq!(REDIS_MEMORY_USAGE.get(), 1024.0 * 1024.0);
    }

    #[test]
    fn test_rate_limit_key_sanitization() {
        // Test normal key
        let normal_key = "user:123:login";
        assert_eq!(sanitize_rate_limit_key(normal_key), normal_key);

        // Test long key that needs sanitization
        let long_key = "x".repeat(200);
        let sanitized = sanitize_rate_limit_key(&long_key);

        assert!(sanitized.len() < long_key.len());
        assert!(sanitized.contains('_'));

        // Test edge case - empty key
        assert_eq!(sanitize_rate_limit_key(""), "");
    }

    #[test]
    fn test_complete_activation_helpers() {
        init_redis_metrics();

        // Test all helpers including the new failure cases
        activation::record_store_success();
        activation::record_store_failure();
        activation::record_verify_success();
        activation::record_verify_failure();
        activation::record_verify_not_found();
        activation::record_cleanup_success();
        activation::record_cleanup_failure();

        // Verify at least the new ones
        assert!(
            REDIS_OPERATIONS
                .with_label_values(&[operations::ACTIVATION_STORE, results::FAILURE])
                .get()
                > 0.0
        );
        assert!(
            REDIS_OPERATIONS
                .with_label_values(&[operations::ACTIVATION_VERIFY, results::FAILURE])
                .get()
                > 0.0
        );
        assert!(
            REDIS_OPERATIONS
                .with_label_values(&[operations::ACTIVATION_CLEANUP, results::FAILURE])
                .get()
                > 0.0
        );
    }

    #[test]
    fn test_complete_reset_helpers() {
        init_redis_metrics();

        // Test all helpers including the new failure cases
        reset::record_store_success();
        reset::record_store_failure();
        reset::record_verify_success();
        reset::record_verify_failure();
        reset::record_verify_not_found();
        reset::record_cleanup_success();
        reset::record_cleanup_failure();

        // Verify at least the new ones
        assert!(
            REDIS_OPERATIONS
                .with_label_values(&[operations::RESET_STORE, results::FAILURE])
                .get()
                > 0.0
        );
        assert!(
            REDIS_OPERATIONS
                .with_label_values(&[operations::RESET_VERIFY, results::FAILURE])
                .get()
                > 0.0
        );
        assert!(
            REDIS_OPERATIONS
                .with_label_values(&[operations::RESET_CLEANUP, results::FAILURE])
                .get()
                > 0.0
        );
    }

    #[tokio::test]
    async fn test_collect_redis_stats() {
        init_redis_metrics();

        // Skip if we don't have Redis available
        let client = match Client::open("redis://127.0.0.1:6379") {
            Ok(client) => client,
            Err(_) => return, // Skip test if Redis unavailable
        };

        // Initial values
        let initial_memory = REDIS_MEMORY_USAGE.get();
        let initial_keys = REDIS_KEYS_TOTAL.get();

        // Collect stats
        collect_redis_stats(&client).await;

        // Check that metrics were updated
        assert!(REDIS_MEMORY_USAGE.get() >= initial_memory);
        assert!(REDIS_KEYS_TOTAL.get() >= initial_keys);
        assert!(REDIS_CONNECTION_POOL.with_label_values(&["total"]).get() > 0.0);
    }
}
