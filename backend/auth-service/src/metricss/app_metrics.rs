//! Application-level metrics for BuildHub Auth Service.
//!
//! This module provides specific metrics for tracking application lifecycle
//! and router construction events. These metrics complement the core metrics
//! infrastructure with application-specific monitoring capabilities.

use lazy_static::lazy_static;
use prometheus::{Counter, CounterVec, Histogram, HistogramVec, Opts};
use crate::metricss::core::{
    create_counter, create_counter_vec, create_histogram_vec,
    LATENCY_BUCKETS_FAST, MetricError,
};
use crate::utils::log_new::Log;

// =============================================================================
// APPLICATION BUILD METRICS
// =============================================================================

lazy_static! {
    /// Counter for application build attempts
    static ref APP_BUILD_ATTEMPTS: Counter = create_counter(
        "buildhub_auth_app_build_attempts_total",
        "Total number of application build attempts"
    ).expect("Failed to create app build attempts counter");

    /// Counter for successful application builds
    static ref APP_BUILD_SUCCESS: Counter = create_counter(
        "buildhub_auth_app_build_success_total", 
        "Total number of successful application builds"
    ).expect("Failed to create app build success counter");

    /// Counter for failed application builds
    static ref APP_BUILD_FAILURES: Counter = create_counter(
        "buildhub_auth_app_build_failures_total",
        "Total number of failed application builds"
    ).expect("Failed to create app build failures counter");

    /// Histogram for application build duration
    static ref APP_BUILD_DURATION: Histogram = create_histogram_vec(
        "buildhub_auth_app_build_duration_seconds",
        "Time spent building the application",
        &["component"],
        LATENCY_BUCKETS_FAST
    ).expect("Failed to create app build duration histogram")
    .with_label_values(&["total"]);
}

// =============================================================================
// ROUTE METRICS
// =============================================================================

lazy_static! {
    /// Counter for route registrations
    static ref ROUTE_REGISTRATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_route_registrations_total",
        "Total number of route registrations by type",
        &["route_type", "method"]
    ).expect("Failed to create route registrations counter");

    /// Counter for middleware attachments
    static ref MIDDLEWARE_ATTACHMENTS: CounterVec = create_counter_vec(
        "buildhub_auth_middleware_attachments_total", 
        "Total number of middleware attachments by type",
        &["middleware_type", "route"]
    ).expect("Failed to create middleware attachments counter");
}

// =============================================================================
// CORS AND RATE LIMITING METRICS
// =============================================================================

lazy_static! {
    /// Counter for CORS configuration events
    static ref CORS_CONFIGURATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_cors_configurations_total",
        "Total number of CORS configuration events",
        &["environment", "status"]
    ).expect("Failed to create CORS configurations counter");

    /// Counter for rate limiter configurations
    static ref RATE_LIMITER_CONFIGURATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_rate_limiter_configurations_total",
        "Total number of rate limiter configuration events", 
        &["backend_type", "status"]
    ).expect("Failed to create rate limiter configurations counter");
}

// =============================================================================
// APPLICATION STATE METRICS
// =============================================================================

lazy_static! {
    /// Counter for application state creation events
    static ref APP_STATE_CREATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_app_state_creations_total",
        "Total number of application state creation events",
        &["redis_enabled", "email_enabled"]
    ).expect("Failed to create app state creations counter");
}

// =============================================================================
// PUBLIC API FUNCTIONS
// =============================================================================

/// Records an application build attempt
pub fn record_app_build_attempt() {
    APP_BUILD_ATTEMPTS.inc();
    Log::event(
        "DEBUG",
        "App Metrics",
        "Recorded application build attempt",
        "app_build_attempt_recorded",
        "record_app_build_attempt"
    );
}

/// Records a successful application build
pub fn record_app_build_success() {
    APP_BUILD_SUCCESS.inc();
    Log::event(
        "INFO", 
        "App Metrics",
        "Recorded successful application build",
        "app_build_success_recorded",
        "record_app_build_success"
    );
}

/// Records a failed application build
pub fn record_app_build_failure() {
    APP_BUILD_FAILURES.inc();
    Log::event(
        "ERROR",
        "App Metrics", 
        "Recorded failed application build",
        "app_build_failure_recorded",
        "record_app_build_failure"
    );
}

/// Records application build duration
pub fn record_app_build_duration(duration_seconds: f64) {
    APP_BUILD_DURATION.observe(duration_seconds);
    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded application build duration: {:.3}s", duration_seconds),
        "app_build_duration_recorded", 
        "record_app_build_duration"
    );
}

/// Records a route registration
pub fn record_route_registration(route_type: &str, method: &str) {
    use crate::metricss::core::observe_counter_vec;
    observe_counter_vec(
        &ROUTE_REGISTRATIONS,
        "buildhub_auth_route_registrations_total",
        &[route_type, method]
    );
    
    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded route registration: {} {}", method, route_type),
        "route_registration_recorded",
        "record_route_registration"
    );
}

/// Records a middleware attachment
pub fn record_middleware_attachment(middleware_type: &str, route: &str) {
    use crate::metricss::core::observe_counter_vec;
    observe_counter_vec(
        &MIDDLEWARE_ATTACHMENTS,
        "buildhub_auth_middleware_attachments_total", 
        &[middleware_type, route]
    );
    
    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded middleware attachment: {} on {}", middleware_type, route),
        "middleware_attachment_recorded",
        "record_middleware_attachment"
    );
}

/// Records a CORS configuration event
pub fn record_cors_configuration(environment: &str, status: &str) {
    use crate::metricss::core::observe_counter_vec;
    observe_counter_vec(
        &CORS_CONFIGURATIONS,
        "buildhub_auth_cors_configurations_total",
        &[environment, status]
    );
    
    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded CORS configuration: {} - {}", environment, status),
        "cors_configuration_recorded",
        "record_cors_configuration"
    );
}

/// Records a rate limiter configuration event
pub fn record_rate_limiter_configuration(backend_type: &str, status: &str) {
    use crate::metricss::core::observe_counter_vec;
    observe_counter_vec(
        &RATE_LIMITER_CONFIGURATIONS,
        "buildhub_auth_rate_limiter_configurations_total",
        &[backend_type, status]
    );
    
    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded rate limiter configuration: {} - {}", backend_type, status),
        "rate_limiter_configuration_recorded",
        "record_rate_limiter_configuration"
    );
}

/// Records an application state creation event
pub fn record_app_state_creation(redis_enabled: bool, email_enabled: bool) {
    use crate::metricss::core::observe_counter_vec;
    
    let redis_str = if redis_enabled { "true" } else { "false" };
    let email_str = if email_enabled { "true" } else { "false" };
    
    observe_counter_vec(
        &APP_STATE_CREATIONS,
        "buildhub_auth_app_state_creations_total",
        &[redis_str, email_str]
    );
    
    Log::event(
        "DEBUG",
        "App Metrics", 
        &format!("Recorded app state creation: redis={}, email={}", redis_enabled, email_enabled),
        "app_state_creation_recorded",
        "record_app_state_creation"
    );
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_app_build_metrics() {
        // Test all app build metrics
        record_app_build_attempt();
        assert!(APP_BUILD_ATTEMPTS.get() >= 1.0);
        
        record_app_build_success();
        assert!(APP_BUILD_SUCCESS.get() >= 1.0);
        
        record_app_build_failure();
        assert!(APP_BUILD_FAILURES.get() >= 1.0);
    }
    
    #[test]
    fn test_app_build_duration() {
        let initial_count = APP_BUILD_DURATION.get_sample_count();
        record_app_build_duration(0.5);
        assert_eq!(APP_BUILD_DURATION.get_sample_count(), initial_count + 1);
    }
    
    #[test]
    fn test_route_registration() {
        record_route_registration("auth", "POST");
        // Verify it doesn't panic and logs properly
    }
    
    #[test]
    fn test_middleware_attachment() {
        record_middleware_attachment("rate_limiter", "/auth/login");
        // Verify it doesn't panic and logs properly
    }
    
    #[test]
    fn test_cors_configuration() {
        record_cors_configuration("development", "success");
        // Verify it doesn't panic and logs properly
    }
    
    #[test]
    fn test_rate_limiter_configuration() {
        record_rate_limiter_configuration("redis", "success");
        // Verify it doesn't panic and logs properly
    }
    
    #[test]
    fn test_app_state_creation() {
        record_app_state_creation(true, false);
        // Verify it doesn't panic and logs properly
    }
}