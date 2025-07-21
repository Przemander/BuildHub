//! # Error Metrics - Production-Grade Application Error Monitoring
//!
//! Comprehensive error tracking integrated with the standardized core metrics infrastructure.
//! Focus on actionable metrics for production alerts, debugging, and business intelligence.
//!
//! ## Design Philosophy
//! - **Alert-Driven**: Only metrics that trigger actual production alerts
//! - **Business Context**: HTTP responses and application errors with proper categorization
//! - **Security Aware**: Track security-related errors for threat detection
//! - **Performance SLA**: Monitor error rates for service level agreements
//! - **Low Cardinality**: Controlled label values to prevent metric explosion
//! - **Core Integration**: Uses standardized infrastructure for consistency
//!
//! ## Core Metrics (2 Essential)
//! - `auth_service_errors_total`: Application errors by category and type
//! - `http_responses_total`: HTTP response tracking by status and endpoint group
//!
//! ## Production Alerts
//! - Infrastructure failures (database/cache down)
//! - Security events (authentication attacks)
//! - High error rates (SLA breaches)
//! - Performance degradation patterns

use lazy_static::lazy_static;
use prometheus::CounterVec;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::log_info;

// Import our standardized metrics infrastructure
use super::core::{
    create_counter_vec,
    observe_counter_vec,
};

// =============================================================================
// METRIC DEFINITIONS (Using standardized infrastructure)
// =============================================================================

lazy_static! {
    /// **Core Business Metric**: Application errors by category and specific type
    ///
    /// Essential for monitoring application health, infrastructure issues, and security events.
    /// Provides granular error classification for targeted alerting and debugging.
    ///
    /// # Labels
    /// * `error_category`: High-level error classification
    ///   - `"database"`: Database connection, query, migration issues
    ///   - `"cache"`: Redis/cache connection and operation failures  
    ///   - `"jwt"`: Authentication token validation issues
    ///   - `"rate_limit"`: Rate limiting configuration and operation errors
    ///   - `"validation"`: Input validation and data integrity errors
    ///   - `"configuration"`: Service configuration and environment errors
    /// * `error_type`: Specific error subtype for detailed analysis
    ///   - Database: `"connection_pool"`, `"query"`, `"migration"`
    ///   - Cache: `"connection"`, `"operation"`, `"key_not_found"`, `"serialization"`
    ///   - JWT: `"expired"`, `"invalid_signature"`, `"invalid"`, `"revoked"`, etc.
    ///   - Rate Limit: `"limit_exceeded"`, `"configuration"`, `"cache_operation"`
    ///   - Validation: `"invalid_value"`, `"missing_field"`, `"too_long"`
    ///   - Configuration: `"general"`
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: Infrastructure down
    /// - alert: DatabaseDown
    ///   expr: rate(auth_service_errors_total{error_category="database", error_type="connection_pool"}[5m]) > 0
    ///   severity: critical
    ///
    /// - alert: CacheDown  
    ///   expr: rate(auth_service_errors_total{error_category="cache", error_type="connection"}[5m]) > 0
    ///   severity: critical
    ///
    /// # Warning: Security events
    /// - alert: JWTAttacks
    ///   expr: rate(auth_service_errors_total{error_category="jwt", error_type="invalid_signature"}[5m]) > 10
    ///   severity: warning
    ///
    /// # Warning: High error rate
    /// - alert: HighApplicationErrorRate
    ///   expr: rate(auth_service_errors_total[5m]) > 5
    ///   severity: warning
    /// ```
    ///
    /// # Business Dashboards
    /// ```promql
    /// # Error rate by category
    /// sum by (error_category) (rate(auth_service_errors_total[5m]))
    ///
    /// # Security events tracking
    /// rate(auth_service_errors_total{error_category="jwt", error_type=~"invalid_signature|revoked"}[5m])
    ///
    /// # Infrastructure health
    /// rate(auth_service_errors_total{error_category=~"database|cache", error_type=~"connection.*"}[5m])
    /// ```
    pub static ref AUTH_SERVICE_ERRORS: CounterVec = create_counter_vec(
        "auth_service_errors_total",
        "Application errors by category and specific type",
        &["error_category", "error_type"]
    ).expect("Failed to create AUTH_SERVICE_ERRORS metric");

    /// **HTTP Monitoring Metric**: HTTP responses by status code and endpoint group
    ///
    /// Essential for monitoring client experience, API health, and endpoint performance.
    /// Provides comprehensive HTTP traffic analysis for SLA monitoring and capacity planning.
    ///
    /// # Labels  
    /// * `status_code`: HTTP status code for response classification
    ///   - `"200"`, `"201"`, `"204"`: Success responses
    ///   - `"400"`, `"401"`, `"403"`, `"404"`: Client errors
    ///   - `"429"`: Rate limiting responses  
    ///   - `"500"`, `"502"`, `"503"`: Server errors
    /// * `endpoint_group`: Logical grouping of endpoints for analysis
    ///   - `"unknown"`: Default group when context is unavailable
    ///
    /// # HTTP SLA Targets (Production)
    /// - **Success Rate**: >99.5% for auth endpoints, >99.9% for public endpoints
    /// - **Error Rate**: <0.5% 5xx errors, <2% 4xx errors (excluding expected 401s)
    /// - **Availability**: <1% 503 responses during normal operation
    ///
    /// # Production Alerts
    /// ```yaml
    /// # Critical: High error rate
    /// - alert: HighHTTPErrorRate
    ///   expr: rate(http_responses_total{status_code=~"5.."}[5m]) / rate(http_responses_total[5m]) > 0.05
    ///   severity: critical
    ///   annotations:
    ///     summary: "HTTP 5xx error rate: {{ $value | humanizePercentage }}"
    ///
    /// # Critical: Service unavailable
    /// - alert: ServiceUnavailable
    ///   expr: rate(http_responses_total{status_code="503"}[5m]) > 1
    ///   severity: critical
    ///
    /// # Info: High client error rate (potential attack)
    /// - alert: HighClientErrorRate
    ///   expr: rate(http_responses_total{status_code=~"4.."}[5m]) > 20
    ///   severity: info
    /// ```
    ///
    /// # Business Dashboards
    /// ```promql
    /// # Overall success rate
    /// rate(http_responses_total{status_code=~"2.."}[5m]) / rate(http_responses_total[5m])
    ///
    /// # Request volume by endpoint group
    /// sum by (endpoint_group) (rate(http_responses_total[5m]))
    ///
    /// # Error breakdown
    /// sum by (status_code) (rate(http_responses_total{status_code!~"2.."}[5m]))
    /// ```
    pub static ref HTTP_RESPONSES: CounterVec = create_counter_vec(
        "http_responses_total",
        "HTTP responses by status code and endpoint group",
        &["status_code", "endpoint_group"]
    ).expect("Failed to create HTTP_RESPONSES metric");
}

static ERROR_METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn init_error_metrics() {
    if ERROR_METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    // Force initialization of all metrics
    lazy_static::initialize(&AUTH_SERVICE_ERRORS);
    lazy_static::initialize(&HTTP_RESPONSES);

    log_info!("Metrics", "Error metrics initialized (enhanced production version with core integration)", "error_metrics_init");
}

// =============================================================================
// CORE API (Using standardized observation functions)
// =============================================================================

/// Records an application error occurrence with enhanced error handling
pub fn record_error(error_category: &str, error_type: &str) {
    observe_counter_vec(
        &AUTH_SERVICE_ERRORS,
        "auth_service_errors_total",
        &[error_category, error_type]
    );
}

/// Records HTTP response with enhanced error handling
pub fn record_http_response(status_code: u16, endpoint_group: &str) {
    observe_counter_vec(
        &HTTP_RESPONSES,
        "http_responses_total",
        &[&status_code.to_string(), endpoint_group]
    );
}

// =============================================================================
// CONSTANTS (Type-safe error classification)
// =============================================================================

pub mod categories {
    pub const DATABASE: &str = "database";
    pub const CACHE: &str = "cache";
    pub const JWT: &str = "jwt";
    pub const RATE_LIMIT: &str = "rate_limit";
    pub const VALIDATION: &str = "validation";
    pub const CONFIGURATION: &str = "configuration";
}

pub mod database_types {
    pub const CONNECTION_POOL: &str = "connection_pool";
    pub const QUERY: &str = "query";
    pub const MIGRATION: &str = "migration";
}

pub mod cache_types {
    pub const CONNECTION: &str = "connection";
    pub const OPERATION: &str = "operation";
    pub const KEY_NOT_FOUND: &str = "key_not_found";
    pub const SERIALIZATION: &str = "serialization";
}

pub mod jwt_types {
    pub const EXPIRED: &str = "expired";
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    pub const INVALID: &str = "invalid";
    pub const REVOKED: &str = "revoked";
    pub const INVALID_IAT: &str = "invalid_iat";
    pub const CONFIGURATION: &str = "configuration";
    pub const INTERNAL: &str = "internal";
}

pub mod rate_limit_types {
    pub const LIMIT_EXCEEDED: &str = "limit_exceeded";
    pub const CONFIGURATION: &str = "configuration";
    pub const CACHE_OPERATION: &str = "cache_operation";
    pub const INVALID_KEY: &str = "invalid_key";
}

pub mod validation_types {
    pub const INVALID_VALUE: &str = "invalid_value";
    pub const MISSING_FIELD: &str = "missing_field";
    pub const TOO_LONG: &str = "too_long";
    pub const PASSWORD_HASH: &str = "password_hash";
}

pub mod configuration_types {
    pub const GENERAL: &str = "general";
}

pub mod endpoint_groups {
    /// Default group when endpoint context is unavailable
    pub const UNKNOWN: &str = "unknown";
}

// =============================================================================
// HELPER MODULES (Enhanced with comprehensive tracking)
// =============================================================================

/// Database error helpers
pub mod database {
    use super::*;
    
    pub fn record_connection_pool_error() {
        record_error(categories::DATABASE, database_types::CONNECTION_POOL);
    }
    
    pub fn record_query_error() {
        record_error(categories::DATABASE, database_types::QUERY);
    }
    
    pub fn record_migration_error() {
        record_error(categories::DATABASE, database_types::MIGRATION);
    }
}

/// Cache error helpers
pub mod cache {
    use super::*;
    
    pub fn record_connection_error() {
        record_error(categories::CACHE, cache_types::CONNECTION);
    }
    
    pub fn record_operation_error() {
        record_error(categories::CACHE, cache_types::OPERATION);
    }
    
    pub fn record_key_not_found() {
        record_error(categories::CACHE, cache_types::KEY_NOT_FOUND);
    }
    
    pub fn record_serialization_error() {
        record_error(categories::CACHE, cache_types::SERIALIZATION);
    }
}

/// JWT error helpers
pub mod jwt {
    use super::*;
    
    pub fn record_expired() {
        record_error(categories::JWT, jwt_types::EXPIRED);
    }
    
    pub fn record_invalid_signature() {
        record_error(categories::JWT, jwt_types::INVALID_SIGNATURE);
    }
    
    pub fn record_invalid() {
        record_error(categories::JWT, jwt_types::INVALID);
    }
    
    pub fn record_revoked() {
        record_error(categories::JWT, jwt_types::REVOKED);
    }
    
    pub fn record_invalid_iat() {
        record_error(categories::JWT, jwt_types::INVALID_IAT);
    }
    
    pub fn record_configuration_error() {
        record_error(categories::JWT, jwt_types::CONFIGURATION);
    }
    
    pub fn record_internal_error() {
        record_error(categories::JWT, jwt_types::INTERNAL);
    }
}

/// Rate limiting error helpers
pub mod rate_limit {
    use super::*;
    
    pub fn record_limit_exceeded() {
        record_error(categories::RATE_LIMIT, rate_limit_types::LIMIT_EXCEEDED);
    }
    
    pub fn record_configuration_error() {
        record_error(categories::RATE_LIMIT, rate_limit_types::CONFIGURATION);
    }
    
    pub fn record_cache_operation_error() {
        record_error(categories::RATE_LIMIT, rate_limit_types::CACHE_OPERATION);
    }
    
    pub fn record_invalid_key_error() {
        record_error(categories::RATE_LIMIT, rate_limit_types::INVALID_KEY);
    }
}

/// Validation error helpers
pub mod validation {
    use super::*;
    
    pub fn record_invalid_value() {
        record_error(categories::VALIDATION, validation_types::INVALID_VALUE);
    }
    
    pub fn record_missing_field() {
        record_error(categories::VALIDATION, validation_types::MISSING_FIELD);
    }
    
    pub fn record_too_long() {
        record_error(categories::VALIDATION, validation_types::TOO_LONG);
    }
    
    pub fn record_password_hash_error() {
        record_error(categories::VALIDATION, validation_types::PASSWORD_HASH);
    }
}

/// Configuration error helpers
pub mod configuration {
    use super::*;
    
    pub fn record_general_error() {
        record_error(categories::CONFIGURATION, configuration_types::GENERAL);
    }
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_metrics_initialization() {
        init_error_metrics();
        
        // Test that all metrics are properly initialized
        assert_eq!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::DATABASE, database_types::CONNECTION_POOL]).get(), 0.0);
        assert_eq!(HTTP_RESPONSES.with_label_values(&["200", endpoint_groups::UNKNOWN]).get(), 0.0);
    }

    #[test]
    fn test_core_error_recording_with_standardized_functions() {
        init_error_metrics();
        
        let before = AUTH_SERVICE_ERRORS
            .with_label_values(&[categories::DATABASE, database_types::CONNECTION_POOL])
            .get();
        
        record_error(categories::DATABASE, database_types::CONNECTION_POOL);
        
        let after = AUTH_SERVICE_ERRORS
            .with_label_values(&[categories::DATABASE, database_types::CONNECTION_POOL])
            .get();
        
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_http_response_recording_with_enhanced_error_handling() {
        init_error_metrics();
        
        let before = HTTP_RESPONSES
            .with_label_values(&["500", endpoint_groups::UNKNOWN])
            .get();
        
        record_http_response(500, endpoint_groups::UNKNOWN);
        
        let after = HTTP_RESPONSES
            .with_label_values(&["500", endpoint_groups::UNKNOWN])
            .get();
        
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn test_helper_modules() {
        init_error_metrics();
        
        // Test database helpers
        database::record_connection_pool_error();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::DATABASE, database_types::CONNECTION_POOL]).get() >= 1.0);
        
        database::record_query_error();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::DATABASE, database_types::QUERY]).get() >= 1.0);
        
        // Test cache helpers
        cache::record_connection_error();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::CACHE, cache_types::CONNECTION]).get() >= 1.0);
        
        cache::record_operation_error();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::CACHE, cache_types::OPERATION]).get() >= 1.0);
        
        // Test JWT helpers
        jwt::record_expired();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::JWT, jwt_types::EXPIRED]).get() >= 1.0);
        
        jwt::record_invalid_signature();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::JWT, jwt_types::INVALID_SIGNATURE]).get() >= 1.0);
        
        // Test rate limit helpers
        rate_limit::record_limit_exceeded();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::RATE_LIMIT, rate_limit_types::LIMIT_EXCEEDED]).get() >= 1.0);
        
        // Test validation helpers
        validation::record_invalid_value();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::VALIDATION, validation_types::INVALID_VALUE]).get() >= 1.0);
        
        // Test configuration helpers
        configuration::record_general_error();
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::CONFIGURATION, configuration_types::GENERAL]).get() >= 1.0);
    }

    #[test]
    fn test_comprehensive_error_categories() {
        init_error_metrics();
        
        // Test all error categories and types
        record_error(categories::DATABASE, database_types::CONNECTION_POOL);
        record_error(categories::DATABASE, database_types::QUERY);
        record_error(categories::DATABASE, database_types::MIGRATION);
        
        record_error(categories::CACHE, cache_types::CONNECTION);
        record_error(categories::CACHE, cache_types::OPERATION);
        record_error(categories::CACHE, cache_types::KEY_NOT_FOUND);
        record_error(categories::CACHE, cache_types::SERIALIZATION);
        
        record_error(categories::JWT, jwt_types::EXPIRED);
        record_error(categories::JWT, jwt_types::INVALID_SIGNATURE);
        record_error(categories::JWT, jwt_types::INVALID);
        record_error(categories::JWT, jwt_types::REVOKED);
        record_error(categories::JWT, jwt_types::INVALID_IAT);
        record_error(categories::JWT, jwt_types::CONFIGURATION);
        record_error(categories::JWT, jwt_types::INTERNAL);
        
        record_error(categories::RATE_LIMIT, rate_limit_types::LIMIT_EXCEEDED);
        record_error(categories::RATE_LIMIT, rate_limit_types::CONFIGURATION);
        record_error(categories::RATE_LIMIT, rate_limit_types::CACHE_OPERATION);
        record_error(categories::RATE_LIMIT, rate_limit_types::INVALID_KEY);
        
        record_error(categories::VALIDATION, validation_types::INVALID_VALUE);
        record_error(categories::VALIDATION, validation_types::MISSING_FIELD);
        record_error(categories::VALIDATION, validation_types::TOO_LONG);
        record_error(categories::VALIDATION, validation_types::PASSWORD_HASH);
        
        record_error(categories::CONFIGURATION, configuration_types::GENERAL);
        
        // If we get here, all constants are valid and recording works
        assert!(true);
    }

    #[test]
    fn test_endpoint_groups() {
        init_error_metrics();
        
        // Test endpoint group
        record_http_response(500, endpoint_groups::UNKNOWN);
        
        // Verify group works
        assert!(HTTP_RESPONSES.with_label_values(&["500", endpoint_groups::UNKNOWN]).get() >= 1.0);
    }

    #[test]
    fn test_production_usage_patterns() {
        init_error_metrics();
        
        // Simulate production error patterns
        
        // Database connection issues (infrastructure failure)
        database::record_connection_pool_error();
        database::record_connection_pool_error();
        
        // JWT security events (potential attack)
        jwt::record_invalid_signature();
        jwt::record_invalid_signature();
        jwt::record_invalid_signature();
        
        // Rate limiting (normal protection)
        rate_limit::record_limit_exceeded();
        
        // HTTP responses (normal traffic)
        record_http_response(200, endpoint_groups::UNKNOWN);
        record_http_response(200, endpoint_groups::UNKNOWN);
        record_http_response(200, endpoint_groups::UNKNOWN);
        record_http_response(401, endpoint_groups::UNKNOWN);
        record_http_response(500, endpoint_groups::UNKNOWN);
        
        // Verify patterns are recorded correctly
        assert_eq!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::DATABASE, database_types::CONNECTION_POOL]).get(), 2.0);
        assert_eq!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::JWT, jwt_types::INVALID_SIGNATURE]).get(), 3.0);
        assert_eq!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::RATE_LIMIT, rate_limit_types::LIMIT_EXCEEDED]).get(), 1.0);
        
        assert_eq!(HTTP_RESPONSES.with_label_values(&["200", endpoint_groups::UNKNOWN]).get(), 3.0);
        assert_eq!(HTTP_RESPONSES.with_label_values(&["401", endpoint_groups::UNKNOWN]).get(), 1.0);
        assert_eq!(HTTP_RESPONSES.with_label_values(&["500", endpoint_groups::UNKNOWN]).get(), 1.0);
    }

    #[test]
    fn test_metric_error_handling() {
        init_error_metrics();
        
        // Test that invalid/long label values are handled gracefully
        // (These would be sanitized by the core infrastructure)
        record_error("very_long_category_name_that_might_cause_issues", "very_long_error_type");
        record_http_response(999, "invalid_endpoint_group!");
        
        // These should not panic due to the enhanced error handling in core.rs
        // The metrics should either be recorded with sanitized labels or ignored safely
    }

    #[test]
    fn test_constants_usage() {
        init_error_metrics();
        
        // Test using constants for type safety
        record_error(categories::JWT, jwt_types::EXPIRED);
        record_http_response(401, endpoint_groups::UNKNOWN);
        
        // Verify constants work correctly
        assert!(AUTH_SERVICE_ERRORS.with_label_values(&[categories::JWT, jwt_types::EXPIRED]).get() >= 1.0);
        assert!(HTTP_RESPONSES.with_label_values(&["401", endpoint_groups::UNKNOWN]).get() >= 1.0);
    }
}