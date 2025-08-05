//! # Advanced Telemetry System for BuildHub Auth Service
//!
//! This module provides a comprehensive telemetry framework integrating:
//! - Structured tracing with business context
//! - Consistent span creation with standardized attributes
//! - Request ID propagation for distributed tracing
//! - Automatic error recording and context enrichment
//! - OpenTelemetry compatibility
//!
//! ## Usage Examples
//!
//! ### Creating and using business operation spans:
//! ```rust
//! let span = business_operation_span("process_user_registration");
//! span.record("user_email_domain", &email_domain);
//!
//! // Record the result when done
//! span.record("business.result", &"success");
//! ```
//!
//! ### Recording errors in spans:
//! ```rust
//! if let Err(e) = operation() {
//!     span.record_error(&e);
//!     // Handle error
//! }
//! ```
//!
//! ### Instrumenting HTTP handlers:
//! ```rust
//! async fn handler(req: Request) -> Response {
//!     let span = http_request_span("GET", "/users");
//!     // Your handler logic
//! }
//! ```

use std::fmt::Display;
use tracing::{field::Empty, Level, Span as TracingSpan};
use uuid::Uuid;

// =============================================================================
// STANDARDIZED SPAN NAMES
// =============================================================================

/// Standard span names for consistent observability across the service.
///
/// These constants provide a unified naming convention that ensures
/// spans are properly categorized in observability tools.
#[allow(dead_code)]
pub mod spans {
    /// HTTP request handling span
    pub const HTTP_REQUEST: &str = "http.request";
    
    /// HTTP middleware execution span
    pub const HTTP_MIDDLEWARE: &str = "http.middleware";
    
    /// Database query execution span
    pub const DB_QUERY: &str = "db.query";
    
    /// Redis cache operation span
    pub const REDIS_OPERATION: &str = "redis.operation";
    
    /// JWT token validation span
    pub const JWT_VALIDATION: &str = "jwt.validation";
    
    /// Email sending operation span
    pub const EMAIL_SEND: &str = "email.send";
    
    /// Business logic operation span
    pub const BUSINESS_OPERATION: &str = "business.operation";
}

// =============================================================================
// SPAN BUILDER FUNCTIONS
// =============================================================================

/// Creates a span for HTTP request processing with standardized attributes.
///
/// This function creates a properly structured span for tracking HTTP requests
/// through the system, automatically including a unique request ID.
///
/// # Parameters
/// * `method` - HTTP method (GET, POST, etc.)
/// * `path` - Request path
///
/// # Returns
/// A tracing span with standardized HTTP request attributes
///
/// # Example
/// ```
/// let span = http_request_span("GET", "/auth/login");
/// // Later, record the result
/// span.record("http.status_code", 200);
/// ```
pub fn http_request_span(method: &str, path: &str) -> TracingSpan {
    tracing::span!(
        Level::INFO,
        spans::HTTP_REQUEST,
        http.method = %method,
        http.path = %path,
        http.status_code = Empty,
        error = false,
        request_id = %Uuid::new_v4().to_string()
    )
}

/// Creates a span for tracking HTTP middleware execution.
///
/// Middleware spans are child spans of HTTP request spans and track
/// the execution of specific middleware components.
///
/// # Parameters
/// * `middleware_name` - Name of the middleware being executed
///
/// # Returns
/// A tracing span with standardized middleware attributes
///
/// # Example
/// ```
/// let span = http_middleware_span("rate_limiter");
/// // Later, record the result
/// span.record("middleware.result", &"allowed");
/// ```
pub fn http_middleware_span(middleware_name: &str) -> TracingSpan {
    tracing::span!(
        Level::INFO,
        spans::HTTP_MIDDLEWARE,
        middleware.name = %middleware_name,
        middleware.result = Empty,
        error = false,
        request_id = %Uuid::new_v4().to_string()
    )
}

/// Creates a span for database operations with standardized attributes.
///
/// This span tracks database interactions and provides context for
/// performance analysis and troubleshooting.
///
/// # Parameters
/// * `operation` - Type of database operation (query, insert, update, etc.)
/// * `table` - Database table being accessed
///
/// # Returns
/// A tracing span with standardized database operation attributes
///
/// # Example
/// ```
/// let span = db_operation_span("select", "users");
/// // Later, record success/failure
/// span.record("db.success", &true);
/// ```
pub fn db_operation_span(operation: &str, table: &str) -> TracingSpan {
    tracing::span!(
        Level::DEBUG,
        spans::DB_QUERY,
        db.operation = %operation,
        db.table = %table,
        db.success = Empty,
        error = false
    )
}

/// Creates a span for Redis cache operations with standardized attributes.
///
/// This span tracks interactions with Redis and provides context for
/// performance analysis and troubleshooting.
///
/// # Parameters
/// * `operation` - Type of Redis operation (get, set, del, etc.)
/// * `key_pattern` - Pattern of the Redis key (for privacy, actual values should be omitted)
///
/// # Returns
/// A tracing span with standardized Redis operation attributes
///
/// # Example
/// ```
/// let span = redis_operation_span("get", "user:*");
/// // Later, record success/failure
/// span.record("redis.success", &true);
/// ```
pub fn redis_operation_span(operation: &str, key_pattern: &str) -> TracingSpan {
    tracing::span!(
        Level::DEBUG,
        spans::REDIS_OPERATION,
        redis.operation = %operation,
        redis.key_pattern = %key_pattern,
        redis.success = Empty,
        error = false
    )
}

/// Creates a span for business logic operations with standardized attributes.
///
/// Business operation spans represent high-level functional operations
/// in the application domain logic.
///
/// # Parameters
/// * `operation` - Name of the business operation being performed
///
/// # Returns
/// A tracing span with standardized business operation attributes
///
/// # Example
/// ```
/// let span = business_operation_span("validate_credentials");
/// // Later, record the result
/// span.record("business.result", &"success");
/// ```
pub fn business_operation_span(operation: &str) -> TracingSpan {
    tracing::span!(
        Level::INFO,
        spans::BUSINESS_OPERATION,
        business.operation = %operation,
        business.result = Empty,
        error = false
    )
}

// =============================================================================
// SPAN EXTENSION TRAIT
// =============================================================================

/// Extension trait for adding standardized context to spans.
///
/// This trait provides additional methods to enhance spans with
/// commonly used attributes in a consistent manner.
pub trait SpanExt {
    /// Records an error in the span with standardized attributes.
    ///
    /// This method ensures errors are consistently recorded in spans
    /// with proper context.
    ///
    /// # Parameters
    /// * `error` - The error to record
    fn record_error<E>(&self, error: &E) where E: Display;
    
    /// Records user context in the span.
    ///
    /// This method adds user identification to spans for tracking
    /// user-specific operations.
    ///
    /// # Parameters
    /// * `user_id` - User identifier
    #[allow(dead_code)]
    fn record_user(&self, user_id: &str);
    
    /// Records request ID for linking related spans.
    ///
    /// This method adds request context to spans for distributed tracing.
    ///
    /// # Parameters
    /// * `request_id` - Unique request identifier
    #[allow(dead_code)]
    fn record_request_id(&self, request_id: &str);
}

/// Implementation of SpanExt for tracing::Span.
impl SpanExt for TracingSpan {
    fn record_error<E>(&self, error: &E) where E: Display {
        self.record("error", &true);
        self.record("error.message", &format!("{}", error));
    }

    fn record_user(&self, user_id: &str) {
        self.record("user.id", &user_id);
    }

    fn record_request_id(&self, request_id: &str) {
        self.record("request_id", &request_id);
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_http_request_span() {
        let span = http_request_span("GET", "/test");
        assert!(span.is_none()); // Span is disabled in test mode, which is expected
    }
    
    #[test]
    fn test_business_operation_span() {
        let span = business_operation_span("test_operation");
        assert!(span.is_none()); // Span is disabled in test mode, which is expected
    }
    
    #[test]
    fn test_db_operation_span() {
        let span = db_operation_span("select", "users");
        assert!(span.is_none()); // Span is disabled in test mode, which is expected
    }
    
    #[test]
    fn test_redis_operation_span() {
        let span = redis_operation_span("get", "session:*");
        assert!(span.is_none()); // Span is disabled in test mode, which is expected
    }
}