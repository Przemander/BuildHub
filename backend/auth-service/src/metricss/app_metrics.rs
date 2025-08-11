//! # Application-level Metrics for BuildHub Auth Service
//!
//! This module provides comprehensive metrics for tracking application lifecycle events,
//! router construction, middleware configuration, and other application-level concerns.
//! These metrics complement the business-oriented metrics by focusing on the technical
//! aspects of application deployment and configuration.
//!
//! ## Design Philosophy
//! - **Complete Lifecycle Coverage**: Track from build time through runtime configuration
//! - **Deployment Observability**: Capture infrastructure and environment context
//! - **Self-Describing Architecture**: Use metrics to document system composition
//! - **Configuration Verification**: Validate system setup through metrics

use crate::metricss::core::{
    create_counter, create_counter_vec, create_histogram_vec, observe_counter_vec,
    LATENCY_BUCKETS_FAST,
};
use crate::utils::log_new::Log;
use lazy_static::lazy_static;
use prometheus::{Counter, CounterVec, Histogram};

// =============================================================================
// CONSTANTS - Label Values (Type Safety)
// =============================================================================

/// Status constants for configuration metrics
#[allow(dead_code)]
pub mod status {
    /// Configuration operation completed successfully
    pub const SUCCESS: &str = "success";
    /// Configuration operation failed
    pub const FAILURE: &str = "failure";
    /// Configuration operation partially succeeded with warnings
    pub const WARNING: &str = "warning";
}

/// Environment constants for configuration metrics
#[allow(dead_code)]
pub mod environment {
    /// Development environment
    pub const DEV: &str = "development";
    /// Testing environment
    pub const TEST: &str = "test";
    /// Staging environment
    pub const STAGING: &str = "staging";
    /// Production environment
    pub const PRODUCTION: &str = "production";
}

/// Backend type constants for rate limiter configuration
#[allow(dead_code)]
pub mod backend {
    /// Redis-backed rate limiter
    pub const REDIS: &str = "redis";
    /// In-memory rate limiter
    pub const MEMORY: &str = "memory";
    /// No rate limiting (disabled)
    pub const NONE: &str = "none";
}

/// Route types for registration metrics
#[allow(dead_code)]
pub mod route_type {
    /// Authentication routes
    pub const AUTH: &str = "auth";
    /// User management routes
    pub const USER: &str = "user";
    /// Health check routes
    pub const HEALTH: &str = "health";
    /// Debug and metrics routes
    pub const DEBUG: &str = "debug";
}

/// HTTP methods for route registration
#[allow(dead_code)]
pub mod method {
    /// HTTP GET method
    pub const GET: &str = "GET";
    /// HTTP POST method
    pub const POST: &str = "POST";
    /// HTTP PUT method
    pub const PUT: &str = "PUT";
    /// HTTP DELETE method
    pub const DELETE: &str = "DELETE";
    /// HTTP PATCH method
    pub const PATCH: &str = "PATCH";
}

/// Middleware types for attachment metrics
#[allow(dead_code)]
pub mod middleware {
    /// Rate limiting middleware
    pub const RATE_LIMITER: &str = "rate_limiter";
    /// JWT authentication middleware
    pub const JWT_AUTH: &str = "jwt_auth";
    /// Telemetry middleware
    pub const TELEMETRY: &str = "telemetry";
    /// CORS middleware
    pub const CORS: &str = "cors";
    /// Login checks middleware
    pub const LOGIN_CHECKS: &str = "login_checks";
}

// =============================================================================
// APPLICATION BUILD METRICS
// =============================================================================

lazy_static! {
    /// Counter for application build attempts
    ///
    /// Tracks how many times the application has attempted to initialize,
    /// useful for detecting startup issues in containerized environments.
    pub static ref APP_BUILD_ATTEMPTS: Counter = create_counter(
        "buildhub_auth_app_build_attempts_total",
        "Total number of application build attempts"
    ).expect("Failed to create app build attempts counter");

    /// Counter for successful application builds
    ///
    /// Tracks how many times the application has successfully initialized.
    /// Used to calculate build success rate in CI/CD and production.
    pub static ref APP_BUILD_SUCCESS: Counter = create_counter(
        "buildhub_auth_app_build_success_total",
        "Total number of successful application builds"
    ).expect("Failed to create app build success counter");

    /// Counter for failed application builds
    ///
    /// Tracks how many times the application has failed to initialize.
    /// Critical for detecting configuration or environment issues.
    pub static ref APP_BUILD_FAILURES: Counter = create_counter(
        "buildhub_auth_app_build_failures_total",
        "Total number of failed application builds"
    ).expect("Failed to create app build failures counter");

    /// Histogram for application build duration
    ///
    /// Measures how long it takes to build the application, useful for
    /// optimizing startup time and detecting slowdowns.
    pub static ref APP_BUILD_DURATION: Histogram = create_histogram_vec(
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
    ///
    /// Tracks how many routes of each type have been registered.
    /// Used to verify API completeness and detect missing endpoints.
    pub static ref ROUTE_REGISTRATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_route_registrations_total",
        "Total number of route registrations by type",
        &["route_type", "method"]
    ).expect("Failed to create route registrations counter");

    /// Counter for middleware attachments
    ///
    /// Tracks how many middleware components have been attached to routes.
    /// Used to verify security and cross-cutting concerns.
    pub static ref MIDDLEWARE_ATTACHMENTS: CounterVec = create_counter_vec(
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
    ///
    /// Tracks CORS configuration by environment, important for
    /// security monitoring and verification.
    pub static ref CORS_CONFIGURATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_cors_configurations_total",
        "Total number of CORS configuration events",
        &["environment", "status"]
    ).expect("Failed to create CORS configurations counter");

    /// Counter for rate limiter configurations
    ///
    /// Tracks rate limiter setup by backend type, important for
    /// DoS protection verification.
    pub static ref RATE_LIMITER_CONFIGURATIONS: CounterVec = create_counter_vec(
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
    ///
    /// Tracks application dependency availability at startup.
    /// Critical for diagnosing configuration issues.
    pub static ref APP_STATE_CREATIONS: CounterVec = create_counter_vec(
        "buildhub_auth_app_state_creations_total",
        "Total number of application state creation events",
        &["redis_enabled", "email_enabled"]
    ).expect("Failed to create app state creations counter");
}

// =============================================================================
// PUBLIC API FUNCTIONS
// =============================================================================

/// Records an application build attempt
#[allow(dead_code)]
pub fn record_app_build_attempt() {
    APP_BUILD_ATTEMPTS.inc();
    Log::event(
        "DEBUG",
        "App Metrics",
        "Recorded application build attempt",
        "app_build_attempt_recorded",
        "record_app_build_attempt",
    );
}

/// Records a successful application build
#[allow(dead_code)]
pub fn record_app_build_success() {
    APP_BUILD_SUCCESS.inc();
    Log::event(
        "INFO",
        "App Metrics",
        "Recorded successful application build",
        "app_build_success_recorded",
        "record_app_build_success",
    );
}

/// Records a failed application build
#[allow(dead_code)]
pub fn record_app_build_failure() {
    APP_BUILD_FAILURES.inc();
    Log::event(
        "ERROR",
        "App Metrics",
        "Recorded failed application build",
        "app_build_failure_recorded",
        "record_app_build_failure",
    );
}

/// Records application build duration
#[allow(dead_code)]
pub fn record_app_build_duration(duration_seconds: f64) {
    APP_BUILD_DURATION.observe(duration_seconds);
    Log::event(
        "DEBUG",
        "App Metrics",
        &format!(
            "Recorded application build duration: {:.3}s",
            duration_seconds
        ),
        "app_build_duration_recorded",
        "record_app_build_duration",
    );
}

/// Records a route registration
#[allow(dead_code)]
pub fn record_route_registration(route_type: &str, method: &str) {
    observe_counter_vec(
        &ROUTE_REGISTRATIONS,
        "buildhub_auth_route_registrations_total",
        &[route_type, method],
    );

    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded route registration: {} {}", method, route_type),
        "route_registration_recorded",
        "record_route_registration",
    );
}

/// Records a middleware attachment
#[allow(dead_code)]
pub fn record_middleware_attachment(middleware_type: &str, route: &str) {
    observe_counter_vec(
        &MIDDLEWARE_ATTACHMENTS,
        "buildhub_auth_middleware_attachments_total",
        &[middleware_type, route],
    );

    Log::event(
        "DEBUG",
        "App Metrics",
        &format!(
            "Recorded middleware attachment: {} on {}",
            middleware_type, route
        ),
        "middleware_attachment_recorded",
        "record_middleware_attachment",
    );
}

/// Records a CORS configuration event
#[allow(dead_code)]
pub fn record_cors_configuration(environment: &str, status: &str) {
    observe_counter_vec(
        &CORS_CONFIGURATIONS,
        "buildhub_auth_cors_configurations_total",
        &[environment, status],
    );

    Log::event(
        "DEBUG",
        "App Metrics",
        &format!("Recorded CORS configuration: {} - {}", environment, status),
        "cors_configuration_recorded",
        "record_cors_configuration",
    );
}

/// Records a rate limiter configuration event
#[allow(dead_code)]
pub fn record_rate_limiter_configuration(backend_type: &str, status: &str) {
    observe_counter_vec(
        &RATE_LIMITER_CONFIGURATIONS,
        "buildhub_auth_rate_limiter_configurations_total",
        &[backend_type, status],
    );

    Log::event(
        "DEBUG",
        "App Metrics",
        &format!(
            "Recorded rate limiter configuration: {} - {}",
            backend_type, status
        ),
        "rate_limiter_configuration_recorded",
        "record_rate_limiter_configuration",
    );
}

/// Records an application state creation event
#[allow(dead_code)]
pub fn record_app_state_creation(redis_enabled: bool, email_enabled: bool) {
    let redis_str = if redis_enabled { "true" } else { "false" };
    let email_str = if email_enabled { "true" } else { "false" };

    observe_counter_vec(
        &APP_STATE_CREATIONS,
        "buildhub_auth_app_state_creations_total",
        &[redis_str, email_str],
    );

    Log::event(
        "DEBUG",
        "App Metrics",
        &format!(
            "Recorded app state creation: redis={}, email={}",
            redis_enabled, email_enabled
        ),
        "app_state_creation_recorded",
        "record_app_state_creation",
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
        // Test with string literals instead of constants
        record_route_registration("auth", "POST");
        
        // Verify custom values also work
        record_route_registration("custom_route", "CUSTOM");
    }

    #[test]
    fn test_middleware_attachment() {
        // Test with string literals instead of constants
        record_middleware_attachment("rate_limiter", "/auth/login");
        
        // Verify custom values also work
        record_middleware_attachment("custom_middleware", "/custom/path");
    }

    #[test]
    fn test_cors_configuration() {
        // Test with string literals instead of constants
        record_cors_configuration("development", "success");
        record_cors_configuration("production", "warning");
    }

    #[test]
    fn test_rate_limiter_configuration() {
        // Test with string literals instead of constants
        record_rate_limiter_configuration("redis", "success");
        record_rate_limiter_configuration("memory", "warning");
        record_rate_limiter_configuration("none", "failure");
    }

    #[test]
    fn test_app_state_creation() {
        // Test all combinations
        record_app_state_creation(true, true);
        record_app_state_creation(true, false);
        record_app_state_creation(false, true);
        record_app_state_creation(false, false);
    }
}
