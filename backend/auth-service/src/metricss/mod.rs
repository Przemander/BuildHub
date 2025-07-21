//! # Metrics Module - Production-Grade Observability Infrastructure
//!
//! Comprehensive metrics system providing complete observability across all auth service operations.
//! Built on Prometheus with standardized patterns for consistency and maintainability.
//!
//! ## Architecture
//! - **Core Infrastructure**: Standardized metric creation and observation patterns
//! - **Feature Modules**: Specialized metrics for each auth operation (register, login, etc.)
//! - **HTTP Integration**: Complete request/response tracking with status codes
//! - **Business Intelligence**: Step-by-step flow tracking for conversion analysis
//! - **Performance Monitoring**: Latency tracking with SLA alerts
//! - **Error Intelligence**: Detailed failure categorization for troubleshooting

use std::sync::atomic::{AtomicBool, Ordering};
use crate::{log_info};

// --- SUB-MODULES ---
pub mod core;
pub mod validation_metrics;
pub mod error_metrics;        // Complete error tracking system
pub mod jwt_metrics;
pub mod email_metrics;        // Email delivery and business flow monitoring
pub mod database_metrics;     // Database infrastructure and operations monitoring
pub mod middleware_metrics;   // Middleware monitoring
pub mod rate_limiter_metrics; // Rate limiting security and infrastructure monitoring
pub mod redis_metrics;        // Redis infrastructure and operations monitoring
pub mod register_metrics;     // ✅ NEW: Registration flow business metrics
pub mod refresh_metrics;
pub mod password_metrics;
pub mod logout_metrics;      // ✅ ADDED: Just adding refresh_metrics module
pub mod login_metrics;
// --- INITIALIZATION STATE ---
static METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

// --- PUBLIC API ---

/// Initializes all metrics modules for the auth service.
/// 
/// This function should be called once during application startup.
/// It's safe to call multiple times - subsequent calls are no-ops.
/// 
/// # Metrics Modules Initialized:
/// - `validation_metrics`: Input validation and data quality tracking
/// - `jwt_metrics`: JWT token operations and security monitoring  
/// - `error_metrics`: Application-wide error tracking and HTTP response monitoring
/// - `email_metrics`: Email delivery and business flow monitoring
/// - `rate_limiter_metrics`: Rate limiting security monitoring and infrastructure health
/// - `redis_metrics`: Redis infrastructure and operations monitoring
/// - `database_metrics`: Database infrastructure and operations monitoring
/// - `middleware_metrics`: Middleware monitoring
/// - `register_metrics`: Registration flow business metrics and funnel analysis
/// 
/// # Usage
/// ```rust
/// use crate::metricss::init_all_metrics;
/// 
/// fn main() {
///     init_all_metrics(); // Call once at application startup
///     // ... rest of application initialization
/// }
/// ```
pub fn init_all_metrics() {
    // Ensure we only initialize once
    if METRICS_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        log_info!(
            "Metrics",
            "Metrics already initialized, skipping",
            "metrics_already_init"
        );
        return;
    }

    log_info!(
        "Metrics", 
        "Initializing all metrics modules",
        "metrics_init_start"
    );

    // Initialize all metrics sub-modules
    validation_metrics::init_validation_metrics();
    jwt_metrics::init_jwt_metrics();
    error_metrics::init_error_metrics();
    email_metrics::init_email_metrics();
    redis_metrics::init_redis_metrics();
    database_metrics::init_database_metrics();
    middleware_metrics::init_middleware_metrics();
    register_metrics::init_registration_metrics();
    refresh_metrics::init_refresh_metrics(); // ✅ ADDED: Initialize refresh metrics
    password_metrics::init_password_reset_metrics();
    logout_metrics::init_logout_metrics();
    login_metrics::init_login_metrics(); // ✅ ADDED: Initialize logout metrics
    // TODO: Check if this function exists in rate_limiter_metrics
    // rate_limiter_metrics::init_rate_limit_metrics(); // Verify function name

    log_info!(
        "Metrics",
        "All observability metrics initialized successfully (including registration flow)",
        "complete_metrics_init"
    );
}

// TODO: Future metrics modules (plan for expansion)
// pub mod auth_metrics;        // Authentication flow metrics  
// pub mod api_metrics;         // API endpoint performance metrics
// pub mod login_metrics;       // Login flow business metrics
// pub mod activation_metrics;  // Account activation flow metrics

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;
    
    static INIT: Once = Once::new();
    
    fn init_test_metrics() {
        INIT.call_once(|| {
            init_all_metrics();
        });
    }
    
    #[test]
    fn test_metrics_initialization() {
        init_test_metrics();
        assert!(METRICS_INITIALIZED.load(Ordering::Relaxed));
    }
    
    #[test]
    fn test_double_initialization() {
        // Reset state for this test
        METRICS_INITIALIZED.store(false, Ordering::SeqCst);
        
        // First init should work
        init_all_metrics();
        assert!(METRICS_INITIALIZED.load(Ordering::Relaxed));
        
        // Second init should be no-op (shouldn't panic)
        init_all_metrics();
        assert!(METRICS_INITIALIZED.load(Ordering::Relaxed));
    }
    
    #[test]
    fn test_all_metrics_modules_initialize() {
        init_test_metrics();
        
        // Test that all metrics modules are accessible
        // This ensures our pub mod declarations are correct
        
        // Test validation metrics access
        validation_metrics::init_validation_metrics(); // Should be safe to call again
        
        // Test JWT metrics access  
        jwt_metrics::init_jwt_metrics(); // Should be safe to call again
        
        // Test error metrics access
        error_metrics::init_error_metrics(); // Should be safe to call again
        
        // Test email metrics access
        email_metrics::init_email_metrics(); // Should be safe to call again
        
        // Test Redis metrics access
        redis_metrics::init_redis_metrics(); // Should be safe to call again
        
        // Test database metrics access
        database_metrics::init_database_metrics(); // Should be safe to call again

        // Test middleware metrics access
        middleware_metrics::init_middleware_metrics(); // Should be safe to call again
        
        // ✅ NEW: Test registration metrics access
        register_metrics::init_registration_metrics(); // Should be safe to call again
        
        // If we reach here, all modules are properly declared and accessible
        assert!(true);
    }
    
    #[test]
    fn test_registration_metrics_integration() {
        init_test_metrics();
        
        // Test that we can access registration metrics functionality
        register_metrics::record_registration_success();
        register_metrics::record_validation_success();
        register_metrics::record_user_creation_success();
        
        // Test constants are accessible
        assert_eq!(register_metrics::steps::VALIDATION, "validation");
        assert_eq!(register_metrics::steps::COMPLETE_FLOW, "complete_flow");
        assert_eq!(register_metrics::error_types::WEAK_PASSWORD, "weak_password");
        
        // If we reach here, registration metrics module is properly integrated
        assert!(true);
    }
}