//! # Enterprise-Grade Error Architecture for BuildHub Auth Service
//!
//! This module implements a comprehensive, multi-layered error handling system with:
//!
//! - **Two-Layer Architecture**:
//!   1. Internal Layer: Rich context errors for diagnostics (`AuthServiceError`)
//!   2. Public Layer: Client-facing errors with consistent API responses (`ApiError`) 
//!
//! - **Observability Integration**: Complete metrics tracking for all error types
//! - **Context Preservation**: Error chain tracking with source capture
//! - **Security-First Design**: Prevents leaking sensitive information
//! - **Framework Integration**: Seamless Axum HTTP response conversion

use crate::utils::log_new::Log;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use tracing_error::SpanTrace;

// Import enhanced error metrics with helper modules
use crate::metricss::error_metrics::{
    record_http_response, endpoint_groups,
    // Import helper modules for cleaner usage
    database, cache, jwt, rate_limit, validation, configuration,
};

// =============================================================================
// LAYER 1: PUBLIC API CONTRACT (what the client sees)
// =============================================================================

/// Enum for API error statuses, providing type safety.
/// Serializes to `snake_case` in JSON responses.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    /// Input validation failed
    ValidationError,
    /// Resource already exists (e.g., username taken)
    UniqueConstraintError,
    /// Server encountered an unexpected error
    InternalError,
    /// Authentication or authorization failed
    Unauthorized,
    /// Requested resource does not exist
    NotFound,
    /// Service is misconfigured
    ConfigurationError,
    /// Request format or parameters are invalid
    BadRequest,
    /// Service is temporarily unavailable
    ServiceUnavailable,
    /// Client has exceeded rate limits
    TooManyRequests,
}

/// API error response structure, ensuring consistent JSON responses.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Machine-readable error code.
    pub status: ApiStatus,
    /// Human-readable error message.
    pub message: String,
    /// Optional HTTP headers to include in the response
    #[serde(skip)]
    pub headers: Vec<(String, String)>,
}

impl ApiError {
    /// The main `ApiError` constructor, which includes severity-based logging logic.
    ///
    /// # Arguments
    ///
    /// * `status` - The API status code for the error
    /// * `msg` - Human-readable message that will be sent to the client
    ///
    /// # Returns
    ///
    /// A new `ApiError` instance with appropriate logging based on severity
    #[inline]
    pub fn new(status: ApiStatus, msg: impl Into<String>) -> Self {
        let msg_str: String = msg.into();
        
        // Log with appropriate severity based on error type
        match status {
            ApiStatus::InternalError | ApiStatus::ConfigurationError => {
                Log::event(
                    "ERROR",
                    "API Error",
                    &msg_str,
                    &format!("{:?}", status),
                    "ApiError::new"
                );
            }
            ApiStatus::Unauthorized | ApiStatus::ServiceUnavailable => {
                Log::event(
                    "WARN",
                    "API Error",
                    &msg_str,
                    &format!("{:?}", status),
                    "ApiError::new"
                );
            }
            ApiStatus::NotFound | ApiStatus::UniqueConstraintError => {
                Log::event(
                    "INFO",
                    "API Error",
                    &msg_str,
                    &format!("{:?}", status),
                    "ApiError::new"
                );
            }
            ApiStatus::TooManyRequests => {
                Log::event(
                    "INFO",
                    "API Error",
                    &msg_str,
                    &format!("{:?}", status),
                    "ApiError::new"
                );
            }
            _ => {
                Log::event(
                    "DEBUG",
                    "API Error",
                    &msg_str,
                    &format!("{:?}", status),
                    "ApiError::new"
                );
            }
        }
        
        ApiError { 
            status, 
            message: msg_str,
            headers: Vec::new(),
        }
    }

    /// Adds a custom HTTP header to the error response.
    /// 
    /// This is useful for rate limiting (Retry-After), CORS, or other
    /// protocol-specific headers.
    ///
    /// # Arguments
    ///
    /// * `name` - Header name
    /// * `value` - Header value
    ///
    /// # Returns
    ///
    /// The modified ApiError with the added header
    ///
    /// # Example
    ///
    /// ```
    /// let error = ApiError::too_many_requests("Rate limit exceeded")
    ///     .with_header("Retry-After", "60");
    /// ```
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    // ==========================================================================
    // HELPER CONSTRUCTORS - For common error types
    // ==========================================================================

    /// Creates a UniqueConstraintError for conflicts like duplicate usernames
    #[inline]
    pub fn unique_constraint(field: &str, msg: &str) -> Self {
        Self::new(ApiStatus::UniqueConstraintError, format!("{}: {}", field, msg))
    }
    
    /// Creates an InternalError for unexpected server-side failures
    #[inline]
    pub fn internal<M: Into<String>>(msg: M) -> Self {
        Self::new(ApiStatus::InternalError, msg)
    }
    
    /// Creates a NotFound error for missing resources
    #[inline]
    pub fn not_found(resource: &str) -> Self {
        Self::new(ApiStatus::NotFound, format!("{} not found", resource))
    }
    
    /// Creates a ConfigurationError for service misconfiguration
    #[inline]
    pub fn configuration(msg: &str) -> Self {
        Self::new(ApiStatus::ConfigurationError, msg)
    }
    
    /// Creates a ServiceUnavailable error for temporary outages
    #[inline]
    pub fn service_unavailable(msg: &str) -> Self {
        Self::new(ApiStatus::ServiceUnavailable, msg)
    }
    
    /// Creates a BadRequest error for invalid input formats
    #[inline]
    pub fn bad_request(msg: &str) -> Self {
        Self::new(ApiStatus::BadRequest, msg)
    }
    
    /// Creates an Unauthorized error for authentication failures
    #[inline]
    pub fn unauthorized<M: Into<String>>(msg: M) -> Self {
        Self::new(ApiStatus::Unauthorized, msg)
    }
    
    /// Creates a TooManyRequests error for rate limit enforcement
    #[inline]
    pub fn too_many_requests(msg: &str) -> Self {
        Self::new(ApiStatus::TooManyRequests, msg)
    }
}

// =============================================================================
// LAYER 2: INTERNAL APPLICATION ERRORS (with full context)
// =============================================================================

/// Groups all errors related to database operations.
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// Connection pool failures (e.g., exhausted connections)
    #[error("Database connection pool error")]
    ConnectionPool {
        #[source] source: r2d2::Error,
        span: SpanTrace,
    },
    
    /// Query execution failures (e.g., SQL syntax errors)
    #[error("Database query error")]
    Query {
        #[source] source: diesel::result::Error,
        span: SpanTrace,
    },
    
    /// Database migration failures
    #[error("Database migration error")]
    Migration {
        #[source] source: Box<dyn std::error::Error + Send + Sync>,
        span: SpanTrace,
    },
}

/// Groups all errors related to Redis cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Redis connection failures
    #[error("Redis connection error")]
    Connection {
        #[source] source: Box<dyn std::error::Error + Send + Sync>,
        span: SpanTrace,
    },
    
    /// Redis command execution failures
    #[error("Redis operation error")]
    Operation {
        #[source] source: Box<dyn std::error::Error + Send + Sync>,
        span: SpanTrace,
    },
    
    /// Cache key not found in Redis
    #[error("Cache key not found")]
    KeyNotFound {
        key: String,
        span: SpanTrace,
    },
    
    /// JSON serialization/deserialization failures
    #[error("Cache serialization error")]
    Serialization {
        #[source] source: Box<dyn std::error::Error + Send + Sync>,
        span: SpanTrace,
    },
}

/// Groups all errors related to JWT token operations.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Token has passed its expiration time
    #[error("JWT token has expired")]
    Expired {
        span: SpanTrace,
    },
    
    /// Token signature verification failed
    #[error("JWT token signature is invalid")]
    InvalidSignature {
        span: SpanTrace,
    },
    
    /// Token format or content is invalid
    #[error("JWT token format is invalid")]
    Invalid {
        span: SpanTrace,
    },
    
    /// Token has been explicitly revoked
    #[error("JWT token has been revoked")]
    Revoked {
        span: SpanTrace,
    },
    
    /// Token has an invalid issued-at time
    #[error("JWT token issued at time is invalid")]
    InvalidIat {
        span: SpanTrace,
    },
    
    /// JWT configuration problems (e.g., missing keys)
    #[error("JWT configuration error: {message}")]
    Configuration {
        message: String,
        span: SpanTrace,
    },
    
    /// Other JWT-related internal errors
    #[error("JWT internal error: {message}")]
    Internal {
        message: String,
        span: SpanTrace,
    },
}

/// Groups all errors related to rate limiting operations.
#[derive(Debug, Error)]
pub enum RateLimitError {
    /// Client has exceeded their rate limit
    #[error("Rate limit exceeded for key: {key} (current: {current}/{limit})")]
    LimitExceeded {
        key: String,
        current: u32,
        limit: u32,
        reset_time: Option<usize>,
        span: SpanTrace,
    },
    
    /// Rate limiter configuration problems
    #[error("Rate limit configuration error: {message}")]
    Configuration {
        message: String,
        span: SpanTrace,
    },
    
    /// Redis operations failed during rate limiting
    #[error("Rate limit cache operation failed: {operation}")]
    CacheOperation {
        operation: String,
        #[source] source: CacheError,
        span: SpanTrace,
    },
    
    /// Rate limit key format is invalid
    #[error("Rate limit key format invalid: {key}")]
    InvalidKey {
        key: String,
        span: SpanTrace,
    },
}

/// Groups all validation-related errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Field value fails validation rules
    #[error("Invalid value for field '{field}': {message}")]
    InvalidValue {
        field: String,
        message: String,
        span: SpanTrace,
    },
    
    /// Required field is missing
    #[error("Missing required field: {field}")]
    MissingField {
        field: String,
        span: SpanTrace,
    },
    
    /// Field exceeds maximum allowed length
    #[error("Field '{field}' exceeds maximum length of {max_length}")]
    TooLong {
        field: String,
        max_length: usize,
        span: SpanTrace,
    },
    
    /// Password hashing operation failed
    #[error("Password hash operation failed: {message}")]
    PasswordHash {
        message: String,
        span: SpanTrace,
    },
}

/// The main, unified error type for the entire business logic.
///
/// This enum represents the complete error hierarchy for the auth service,
/// organizing errors into logical categories while preserving original error context.
/// Each variant includes rich debugging information via the inner error types.
#[derive(Debug, Error)]
pub enum AuthServiceError {
    /// Service configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Database-related errors
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// Cache-related errors
    #[error(transparent)]
    Cache(#[from] CacheError),

    /// JWT authentication errors
    #[error(transparent)]
    Jwt(#[from] JwtError),
    
    /// Rate limiting errors
    #[error(transparent)]
    RateLimit(#[from] RateLimitError),
    
    /// Input validation errors
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

// =============================================================================
// CONVERSIONS FROM LIBRARY ERRORS
// =============================================================================

impl From<r2d2::Error> for DatabaseError {
    fn from(err: r2d2::Error) -> Self {
        DatabaseError::ConnectionPool { 
            source: err, 
            span: SpanTrace::capture() 
        }
    }
}

impl From<diesel::result::Error> for DatabaseError {
    fn from(err: diesel::result::Error) -> Self {
        DatabaseError::Query { 
            source: err, 
            span: SpanTrace::capture() 
        }
    }
}

impl From<redis::RedisError> for CacheError {
    fn from(err: redis::RedisError) -> Self {
        CacheError::Operation { 
            source: Box::new(err), 
            span: SpanTrace::capture() 
        }
    }
}

impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                JwtError::Expired { 
                    span: SpanTrace::capture() 
                }
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                JwtError::InvalidSignature { 
                    span: SpanTrace::capture() 
                }
            }
            _ => {
                JwtError::Invalid { 
                    span: SpanTrace::capture() 
                }
            }
        }
    }
}

impl From<argon2::password_hash::Error> for ValidationError {
    fn from(err: argon2::password_hash::Error) -> Self {
        ValidationError::PasswordHash {
            message: err.to_string(),
            span: SpanTrace::capture(),
        }
    }
}

// Direct conversions to AuthServiceError
impl From<diesel::result::Error> for AuthServiceError {
    fn from(err: diesel::result::Error) -> Self {
        AuthServiceError::Database(DatabaseError::from(err))
    }
}

impl From<r2d2::Error> for AuthServiceError {
    fn from(err: r2d2::Error) -> Self {
        AuthServiceError::Database(DatabaseError::from(err))
    }
}

impl From<redis::RedisError> for AuthServiceError {
    fn from(err: redis::RedisError) -> Self {
        AuthServiceError::Cache(CacheError::from(err))
    }
}

impl From<argon2::password_hash::Error> for AuthServiceError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AuthServiceError::Validation(ValidationError::from(err))
    }
}

// Helper constructors for AuthServiceError
impl AuthServiceError {
    /// Creates a configuration error with the given message
    pub fn configuration(msg: &str) -> Self {
        AuthServiceError::Configuration(msg.to_string())
    }
    
    /// Creates a validation error for a specific field
    pub fn validation(field: &str, message: &str) -> Self {
        AuthServiceError::Validation(ValidationError::InvalidValue {
            field: field.to_string(),
            message: message.to_string(),
            span: SpanTrace::capture(),
        })
    }
    
    /// Creates a database error with a custom message
    pub fn database(msg: &str) -> Self {
        AuthServiceError::Database(DatabaseError::Query {
            source: diesel::result::Error::QueryBuilderError(msg.into()),
            span: SpanTrace::capture(),
        })
    }
}

// =============================================================================
// ERROR TO API CONVERSION WITH ENHANCED METRICS
// =============================================================================

/// Enhanced helper function to determine endpoint group from request context
fn determine_endpoint_group() -> &'static str {
    // For now, return unknown - this should be enhanced with actual request context
    endpoint_groups::UNKNOWN
}

/// Helper function for recording HTTP responses with appropriate status-specific helpers
fn record_response_by_status(status_code: u16, endpoint_group: &str) {
    // Since we don't have the http helper module imported, use the base function
    record_http_response(status_code, endpoint_group);
}

impl From<AuthServiceError> for ApiError {
    fn from(err: AuthServiceError) -> Self {
        Log::event(
            "ERROR",
            "Error Handler",
            &format!("Service error occurred: {:?}", err),
            "conversion",
            "AuthServiceError::into_api_error"
        );
        
        match err {
            AuthServiceError::Configuration(msg) => {
                // Use helper module for cleaner code
                configuration::record_general_error();
                ApiError::configuration(&msg)
            }
            
            AuthServiceError::Database(db_err) => match db_err {
                DatabaseError::ConnectionPool { .. } => {
                    database::record_connection_pool_error();
                    ApiError::service_unavailable("Could not get a database connection")
                }
                DatabaseError::Migration { .. } => {
                    database::record_migration_error();
                    ApiError::internal("Failed to run database migrations")
                }
                DatabaseError::Query { source, .. } => match source {
                    diesel::result::Error::NotFound => {
                        // Don't record NotFound as error - it's normal business logic
                        ApiError::not_found("Resource not found in the database")
                    }
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::UniqueViolation,
                        _,
                    ) => {
                        // Don't record unique violations as errors - they're business logic
                        ApiError::unique_constraint("resource", "already exists")
                    }
                    _ => {
                        database::record_query_error();
                        ApiError::internal("An unexpected database error occurred")
                    }
                },
            },

            AuthServiceError::Cache(cache_err) => match cache_err {
                CacheError::Connection { .. } => {
                    cache::record_connection_error();
                    ApiError::service_unavailable("Could not connect to cache service")
                }
                CacheError::Operation { .. } => {
                    cache::record_operation_error();
                    ApiError::internal("Cache operation failed")
                }
                CacheError::KeyNotFound { .. } => {
                    cache::record_key_not_found();
                    ApiError::not_found("Requested data not found in cache")
                }
                CacheError::Serialization { .. } => {
                    cache::record_serialization_error();
                    ApiError::internal("Failed to serialize/deserialize cache data")
                }
            },

            AuthServiceError::Jwt(jwt_err) => match jwt_err {
                JwtError::Expired { .. } => {
                    jwt::record_expired();
                    ApiError::unauthorized("Token has expired")
                }
                JwtError::InvalidSignature { .. } => {
                    jwt::record_invalid_signature();
                    ApiError::unauthorized("Invalid token")
                }
                JwtError::Invalid { .. } => {
                    jwt::record_invalid();
                    ApiError::unauthorized("Invalid token")
                }
                JwtError::Revoked { .. } => {
                    jwt::record_revoked();
                    ApiError::unauthorized("Token has been revoked")
                }
                JwtError::InvalidIat { .. } => {
                    jwt::record_invalid_iat();
                    ApiError::unauthorized("Token timing is invalid")
                }
                JwtError::Configuration { message, .. } => {
                    jwt::record_configuration_error();
                    ApiError::configuration(&message)
                }
                JwtError::Internal { message, .. } => {
                    jwt::record_internal_error();
                    ApiError::internal(&message)
                }
            },

            AuthServiceError::RateLimit(rate_err) => match rate_err {
                RateLimitError::LimitExceeded { current, limit, reset_time, .. } => {
                    rate_limit::record_limit_exceeded();
                    let message = match reset_time {
                        Some(reset_secs) => format!(
                            "Rate limit exceeded ({}/{}). Try again in {} seconds.", 
                            current, limit, reset_secs
                        ),
                        None => format!(
                            "Rate limit exceeded ({}/{}). Please try again later.", 
                            current, limit
                        ),
                    };
                    
                    let mut api_error = ApiError::too_many_requests(&message);
                    if let Some(reset_secs) = reset_time {
                        api_error = api_error.with_header("Retry-After", reset_secs.to_string());
                    }
                    api_error
                }
                RateLimitError::Configuration { message, .. } => {
                    rate_limit::record_configuration_error();
                    ApiError::configuration(&message)
                }
                RateLimitError::CacheOperation { .. } => {
                    rate_limit::record_cache_operation_error();
                    ApiError::service_unavailable("Rate limiting service temporarily unavailable")
                }
                RateLimitError::InvalidKey { key, .. } => {
                    rate_limit::record_invalid_key_error();
                    ApiError::bad_request(&format!("Invalid rate limit key format: {}", key))
                }
            },

            AuthServiceError::Validation(val_err) => match val_err {
                ValidationError::InvalidValue { field, message, .. } => {
                    validation::record_invalid_value();
                    ApiError::new(ApiStatus::ValidationError, format!("{}: {}", field, message))
                }
                ValidationError::MissingField { field, .. } => {
                    validation::record_missing_field();
                    ApiError::new(ApiStatus::ValidationError, format!("{} is required", field))
                }
                ValidationError::TooLong { field, max_length, .. } => {
                    validation::record_too_long();
                    ApiError::new(ApiStatus::ValidationError, format!("{} must be no more than {} characters", field, max_length))
                }
                ValidationError::PasswordHash { message, .. } => {
                    validation::record_password_hash_error();
                    ApiError::new(ApiStatus::InternalError, format!("Password processing failed: {}", message))
                }
            },
        }
    }
}

// =============================================================================
// AXUM FRAMEWORK INTEGRATION WITH ENHANCED METRICS
// =============================================================================

/// Allows Axum handlers to return `Result<_, AuthServiceError>`.
///
/// This implementation converts internal service errors to HTTP responses
/// with appropriate status codes and JSON bodies.
impl IntoResponse for AuthServiceError {
    fn into_response(self) -> Response {
        // Convert AuthServiceError to ApiError first
        let api_error = ApiError::from(self);
        
        // Map ApiStatus to HTTP status codes
        let status_code = match api_error.status {
            ApiStatus::ValidationError => StatusCode::BAD_REQUEST,
            ApiStatus::UniqueConstraintError => StatusCode::CONFLICT,
            ApiStatus::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiStatus::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiStatus::NotFound => StatusCode::NOT_FOUND,
            ApiStatus::ConfigurationError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiStatus::BadRequest => StatusCode::BAD_REQUEST,
            ApiStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ApiStatus::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        };

        // Record HTTP response using enhanced helper
        record_response_by_status(status_code.as_u16(), determine_endpoint_group());

        // Return JSON response
        (status_code, Json(api_error)).into_response()
    }
}

/// Converts the final `ApiError` into an HTTP response with the correct status code and JSON body.
///
/// This implementation handles custom headers, content type setting, and proper
/// error recovery if response building fails.
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.status {
            ApiStatus::ValidationError | ApiStatus::BadRequest => StatusCode::BAD_REQUEST,
            ApiStatus::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiStatus::NotFound => StatusCode::NOT_FOUND,
            ApiStatus::UniqueConstraintError => StatusCode::CONFLICT,
            ApiStatus::ConfigurationError | ApiStatus::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ApiStatus::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        };

        // Record HTTP response using enhanced helper
        record_response_by_status(status.as_u16(), determine_endpoint_group());

        // Serialize the error to JSON, with fallback for serialization errors
        let body = serde_json::to_string(&self).unwrap_or_else(|e| {
            Log::event(
                "ERROR",
                "API Error",
                &format!("Error serializing error response: {}", e),
                "serialization_failure",
                "ApiError::into_response"
            );
            "{\"status\":\"internal_error\",\"message\":\"Error serializing the error message.\"}".to_string()
        });

        // Build response with custom headers support
        let mut response_builder = axum::response::Response::builder()
            .status(status)
            .header("Content-Type", "application/json");

        // Add custom headers (e.g., Retry-After for rate limiting)
        for (name, value) in &self.headers {
            response_builder = response_builder.header(name, value);
        }

        response_builder
            .body(axum::body::boxed(axum::body::Body::from(body)))
            .unwrap_or_else(|_| {
                Log::event(
                    "ERROR",
                    "API Error",
                    "Failed to build HTTP response",
                    "response_construction_failure",
                    "ApiError::into_response"
                );
                
                // Use helper function for fallback response
                record_response_by_status(500, endpoint_groups::UNKNOWN);
                
                axum::response::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::boxed(axum::body::Body::from(
                        "{\"status\":\"internal_error\",\"message\":\"Failed to build the response\"}",
                    )))
                    .unwrap()
            })
    }
}