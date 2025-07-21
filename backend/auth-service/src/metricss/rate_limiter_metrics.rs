//! # Rate Limiter Metrics - Production-Grade Rate Limiting Monitoring
//!
//! Comprehensive rate limiting monitoring for security and performance analysis.
//! Integrates with the standardized metrics infrastructure from `core.rs`.
//!
//! ## Key Features
//! - **Security Monitoring**: Track attack patterns and blocked requests
//! - **Infrastructure Health**: Monitor Redis failures and fail-open scenarios
//! - **Performance Analysis**: Measure rate limiting overhead and latency
//! - **Context Separation**: Distinguish between startup and runtime operations
//!
//! This module uses the standardized metrics infrastructure from `core.rs` which provides:
//! - Automatic label validation and sanitization
//! - Cardinality protection
//! - Graceful error handling
//! - Consistent timing measurement

use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec};

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
    /// Rate limiting decisions by result and context
    /// Labels: result (allowed, blocked, fail_open), context (startup, runtime)
    pub static ref RATE_LIMIT_REQUESTS: CounterVec = create_counter_vec(
        "rate_limit_requests_total",
        "Rate limiting decisions by result and context",
        &["result", "context"]
    ).expect("Failed to create RATE_LIMIT_REQUESTS metric");

    /// Redis errors during rate limiting operations
    /// Labels: error_type (connection, timeout, command), context (startup, runtime)
    pub static ref RATE_LIMIT_REDIS_ERRORS: CounterVec = create_counter_vec(
        "rate_limit_redis_errors_total",
        "Redis errors in rate limiting operations",
        &["error_type", "context"]
    ).expect("Failed to create RATE_LIMIT_REDIS_ERRORS metric");

    /// Rate limit check duration with fine-grained buckets for performance analysis
    /// Labels: context (startup, runtime)
    pub static ref RATE_LIMIT_CHECK_DURATION: HistogramVec = create_histogram_vec(
        "rate_limit_check_duration_seconds",
        "Rate limit check duration by context",
        &["context"],
        LATENCY_BUCKETS_FAST
    ).expect("Failed to create RATE_LIMIT_CHECK_DURATION metric");
}

// =============================================================================
// CORE API (Using standardized observation functions)
// =============================================================================

/// Records rate limiting request result with enhanced error handling
pub fn record_rate_limit_request(result: &str, is_startup: bool) {
    let context = if is_startup { "startup" } else { "runtime" };
    observe_counter_vec(
        &RATE_LIMIT_REQUESTS,
        "rate_limit_requests_total",
        &[result, context]
    );
}

/// Records Redis error during rate limiting with enhanced error handling
pub fn record_rate_limit_redis_error(error_type: &str, is_startup: bool) {
    let context = if is_startup { "startup" } else { "runtime" };
    observe_counter_vec(
        &RATE_LIMIT_REDIS_ERRORS,
        "rate_limit_redis_errors_total",
        &[error_type, context]
    );
}

/// Creates timer for rate limit check duration with enhanced error handling
pub fn time_rate_limit_check(is_startup: bool) -> prometheus::HistogramTimer {
    let context = if is_startup { "startup" } else { "runtime" };
    // Note: Timers are automatically observed when dropped
    RATE_LIMIT_CHECK_DURATION
        .with_label_values(&[context])
        .start_timer()
}

// =============================================================================
// CONSTANTS (Type-safe values for consistent labeling)
// =============================================================================

pub mod results {
    pub const ALLOWED: &str = "allowed";
    pub const BLOCKED: &str = "blocked";
    pub const FAIL_OPEN: &str = "fail_open";
}

pub mod errors {
    pub const CONNECTION: &str = "connection";
    pub const TIMEOUT: &str = "timeout";
    pub const COMMAND: &str = "command";
}

// =============================================================================
// HELPER MODULES (Only what's actually used)
// =============================================================================

/// Request result helpers for runtime operations
pub mod request {
    use super::*;
    
    pub fn record_runtime_allowed() {
        record_rate_limit_request(results::ALLOWED, false);
    }
    
    pub fn record_runtime_blocked() {
        record_rate_limit_request(results::BLOCKED, false);
    }
    
    pub fn record_runtime_fail_open() {
        record_rate_limit_request(results::FAIL_OPEN, false);
    }
}

/// Redis error helpers for runtime operations
pub mod redis {
    use super::*;
    
    pub fn record_runtime_connection_error() {
        record_rate_limit_redis_error(errors::CONNECTION, false);
    }
    
    pub fn record_runtime_timeout_error() {
        record_rate_limit_redis_error(errors::TIMEOUT, false);
    }
    
    pub fn record_runtime_command_error() {
        record_rate_limit_redis_error(errors::COMMAND, false);
    }
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_request_tracking() {
        let before = RATE_LIMIT_REQUESTS
            .with_label_values(&[results::ALLOWED, "runtime"])
            .get();
        
        request::record_runtime_allowed();
        
        let after = RATE_LIMIT_REQUESTS
            .with_label_values(&[results::ALLOWED, "runtime"])
            .get();
        
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_redis_error_tracking() {
        let before = RATE_LIMIT_REDIS_ERRORS
            .with_label_values(&[errors::CONNECTION, "runtime"])
            .get();
        
        redis::record_runtime_connection_error();
        
        let after = RATE_LIMIT_REDIS_ERRORS
            .with_label_values(&[errors::CONNECTION, "runtime"])
            .get();
        
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_duration_timer() {
        let timer = time_rate_limit_check(false);
        drop(timer);
        
        let count = RATE_LIMIT_CHECK_DURATION
            .with_label_values(&["runtime"])
            .get_sample_count();
        assert!(count > 0);
    }

    #[test]
    fn test_context_separation() {
        // Test runtime operations
        request::record_runtime_blocked();
        redis::record_runtime_timeout_error();
        
        // Verify context separation
        let runtime_requests = RATE_LIMIT_REQUESTS
            .with_label_values(&[results::BLOCKED, "runtime"])
            .get();
        let runtime_errors = RATE_LIMIT_REDIS_ERRORS
            .with_label_values(&[errors::TIMEOUT, "runtime"])
            .get();
        
        assert!(runtime_requests >= 1.0);
        assert!(runtime_errors >= 1.0);
    }

    #[test]
    fn test_all_request_types() {
        request::record_runtime_allowed();
        request::record_runtime_blocked();
        request::record_runtime_fail_open();
        
        let allowed = RATE_LIMIT_REQUESTS
            .with_label_values(&[results::ALLOWED, "runtime"])
            .get();
        let blocked = RATE_LIMIT_REQUESTS
            .with_label_values(&[results::BLOCKED, "runtime"])
            .get();
        let fail_open = RATE_LIMIT_REQUESTS
            .with_label_values(&[results::FAIL_OPEN, "runtime"])
            .get();
        
        assert!(allowed >= 1.0);
        assert!(blocked >= 1.0);
        assert!(fail_open >= 1.0);
    }

    #[test]
    fn test_all_redis_error_types() {
        redis::record_runtime_connection_error();
        redis::record_runtime_timeout_error();
        redis::record_runtime_command_error();
        
        let connection_errors = RATE_LIMIT_REDIS_ERRORS
            .with_label_values(&[errors::CONNECTION, "runtime"])
            .get();
        let timeout_errors = RATE_LIMIT_REDIS_ERRORS
            .with_label_values(&[errors::TIMEOUT, "runtime"])
            .get();
        let command_errors = RATE_LIMIT_REDIS_ERRORS
            .with_label_values(&[errors::COMMAND, "runtime"])
            .get();
        
        assert!(connection_errors >= 1.0);
        assert!(timeout_errors >= 1.0);
        assert!(command_errors >= 1.0);
    }
}