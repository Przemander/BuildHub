//! Error handling utilities for the BuildHub Auth Service.
//!
//! This module implements a comprehensive, type-safe error handling system with:
//! - Domain-specific error hierarchies with rich context
//! - Automatic error conversions with [`thiserror`]
//! - Structured API responses with consistent patterns
//! - Integration with logging and tracing systems
//! - Performance optimizations for error handling hot paths
//!
//! # Architecture
//!
//! The error system uses a layered approach:
//! - Domain-specific errors (DatabaseError, JwtError, etc.)
//! - ServiceError as a unified error type for business logic
//! - ApiError for HTTP API responses with appropriate status codes
//!
//! # Usage Examples
//!
//! ```ignore
//! // Handle domain errors
//! fn validate_user(user: &User) -> Result<(), ValidationError> {
//!     if user.username.is_empty() {
//!         return Err(ValidationError::InvalidValue("username".into(), "cannot be empty".into()));
//!     }
//!     Ok(())
//! }
//!
//! // Convert to ServiceError (happens automatically with From implementations)
//! let result: Result<(), ServiceError> = validate_user(&user);
//!
//! // Convert to API response (in request handler)
//! async fn handler() -> Result<impl IntoResponse, ApiError> {
//!     // ...
//! }
//! ```

use crate::{log_debug, log_error, log_info, log_warn};
use axum::{http::StatusCode, response::IntoResponse};
use diesel::result::Error as DieselError;
use serde::Serialize;
use std::error::Error as StdError;
use std::fmt;
use tracing_error::SpanTrace;

// --------------------------------------------------------------------------
// API Error Types (for REST API responses)
// --------------------------------------------------------------------------

/// Enum for API error status codes with compile-time type safety.
///
/// Each variant corresponds to a specific error category that maps to an HTTP status code.
/// Serializes as snake_case for API consistency.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    /// Input validation failed (400 Bad Request)
    ValidationError,
    /// Resource already exists with unique constraint (409 Conflict)
    UniqueConstraintError,
    /// Server-side error (500 Internal Server Error)
    InternalError,
    /// Authentication or authorization failed (401 Unauthorized)
    Unauthorized,
    /// Requested resource not found (404 Not Found)
    NotFound,
    /// Service configuration error (500 Internal Server Error)
    ConfigurationError,
    /// Generic bad request (400 Bad Request)
    BadRequest,
    /// Service temporarily unavailable (503 Service Unavailable)
    ServiceUnavailable,
}

impl fmt::Display for ApiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use debug representation for a cleaner string
        write!(f, "{:?}", self)
    }
}

/// API error response structure for consistent JSON error responses.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Machine-readable error code
    pub status: ApiStatus,
    /// Human-readable error message
    pub message: String,
}

impl ApiError {
    /// Create a new API error with appropriate logging based on severity.
    ///
    /// # Arguments
    /// * `status` - The API status code
    /// * `msg` - The error message (anything that can be converted to String)
    ///
    /// # Examples
    /// ```
    /// let error = ApiError::new(ApiStatus::NotFound, "User profile not found");
    /// ```
    #[inline]
    pub fn new(status: ApiStatus, msg: impl Into<String>) -> Self {
        let msg_str: String = msg.into();
        
        // Log based on error severity
        match status {
            ApiStatus::InternalError | ApiStatus::ConfigurationError => {
                // Critical errors that need immediate attention
                log_error!("ApiError", &msg_str, &format!("{:?}", status));
            }
            ApiStatus::Unauthorized | ApiStatus::ServiceUnavailable => {
                // Important but not necessarily bugs
                log_warn!("ApiError", &msg_str, &format!("{:?}", status));
            }
            ApiStatus::NotFound | ApiStatus::UniqueConstraintError => {
                // Normal operational events worth noting
                log_info!("ApiError", &msg_str, &format!("{:?}", status));
            }
            _ => {
                // Common client-side issues
                log_debug!("ApiError", &msg_str, &format!("{:?}", status));
            }
        }
        
        ApiError {
            status,
            message: msg_str,
        }
    }

    // --------------------------------------------------------------------------
    // Convenience constructors for common error patterns
    // --------------------------------------------------------------------------
    
    /// Create a validation error with field name and message.
    ///
    /// # Arguments
    /// * `field` - Name of the field that failed validation
    /// * `msg` - Description of the validation error
    ///
    /// # Examples
    /// ```
    /// let error = ApiError::validation("email", "invalid format");
    /// ```
    #[inline]
    pub fn validation(field: &str, msg: &str) -> Self {
        Self::new(ApiStatus::ValidationError, format!("{}: {}", field, msg))
    }
    
    /// Create a unique constraint violation error.
    ///
    /// # Arguments
    /// * `field` - Name of the field with uniqueness constraint
    /// * `msg` - Description of the conflict
    #[inline]
    pub fn unique_constraint(field: &str, msg: &str) -> Self {
        Self::new(
            ApiStatus::UniqueConstraintError,
            format!("{}: {}", field, msg),
        )
    }
    
    /// Create an internal server error.
    ///
    /// # Arguments
    /// * `msg` - Description of the internal error
    #[inline]
    pub fn internal<M: Into<String>>(msg: M) -> Self {
        Self::new(ApiStatus::InternalError, msg)
    }
    
    /// Create an unauthorized error.
    ///
    /// # Arguments
    /// * `msg` - Description of the authentication/authorization failure
    #[inline]
    pub fn unauthorized<M: Into<String>>(msg: M) -> Self {
        Self::new(ApiStatus::Unauthorized, msg)
    }
    
    /// Create a not found error.
    ///
    /// # Arguments
    /// * `resource` - Name of the resource that wasn't found
    #[inline]
    pub fn not_found(resource: &str) -> Self {
        Self::new(ApiStatus::NotFound, format!("{} not found", resource))
    }
    
    /// Create a configuration error.
    ///
    /// # Arguments
    /// * `msg` - Description of the configuration issue
    #[inline]
    pub fn configuration(msg: &str) -> Self {
        Self::new(ApiStatus::ConfigurationError, msg)
    }
    
    /// Create a bad request error.
    ///
    /// # Arguments
    /// * `msg` - Description of the request issue
    #[inline]
    pub fn bad_request(msg: &str) -> Self {
        Self::new(ApiStatus::BadRequest, msg)
    }
    
    /// Create a service unavailable error.
    ///
    /// # Arguments
    /// * `msg` - Description of the service issue
    #[inline]
    pub fn service_unavailable(msg: &str) -> Self {
        Self::new(ApiStatus::ServiceUnavailable, msg)
    }
    
    // Create a rate limit exceeded error.
    //
    // Currently commented out as unused, but shows extensibility.
    // #[inline]
    // pub fn rate_limit<M: Into<String>>(msg: M) -> Self {
    //     Self::new(ApiStatus::RateLimitExceeded, msg)
    // }
}

// --------------------------------------------------------------------------
// Domain-Specific Error Types
// --------------------------------------------------------------------------

/// Database-related errors with detailed context.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    /// Failed to connect to database
    #[error("Database connection error: {source}\n{span:?}")]
    Connection {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    
    /// Database migration failures
    #[error("Database migration error: {source}\n{span:?}")]
    Migration {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    
    /// Query execution failures
    #[error("Database query error: {source}\n{span:?}")]
    Query {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    
    /// Record not found in database
    #[error("Record not found")]
    NotFound,
}

impl From<DieselError> for DatabaseError {
    fn from(err: DieselError) -> Self {
        match err {
            DieselError::NotFound => DatabaseError::NotFound,
            _ => DatabaseError::Query {
                source: Box::new(err),
                span: SpanTrace::capture(),
            },
        }
    }
}

/// Cache (Redis) related errors with context.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// Connection to Redis failed
    #[error("Redis connection error: {source}\n{span:?}")]
    Connection {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    
    /// Redis operation failed
    #[error("Redis operation error: {source}\n{span:?}")]
    Operation {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
}

impl From<redis::RedisError> for CacheError {
    fn from(err: redis::RedisError) -> Self {
        if err.is_io_error() {
            CacheError::Connection {
                source: Box::new(err),
                span: SpanTrace::capture(),
            }
        } else {
            CacheError::Operation {
                source: Box::new(err),
                span: SpanTrace::capture(),
            }
        }
    }
}

/// Input validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// Value didn't meet validation criteria
    #[error("The value for field '{0}' is invalid: {1}")]
    InvalidValue(String, String),
}

/// JWT-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// JWT configuration issues (missing secret, etc.)
    #[error("JWT configuration error: {0}")]
    Configuration(String),
    
    /// Token has expired
    #[error("JWT token is expired")]
    Expired,
    
    /// Token format is invalid
    #[error("JWT token is invalid")]
    Invalid,
    
    /// Token signature verification failed
    #[error("JWT token has invalid signature")]
    InvalidSignature,
    
    /// Token has been explicitly revoked
    #[error("JWT token is revoked")]
    Revoked,
    
    /// Token issue time is in the future (clock skew)
    #[error("JWT token has invalid issued-at time")]
    InvalidIat,
    
    /// Other JWT-related errors
    #[error("JWT internal error: {0}")]
    Internal(String),
}

/// Email service related errors.
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    /// Email configuration issues
    #[error("Email configuration error: {0}")]
    Configuration(String),
    
    /// Email sending or processing failures
    #[error("Email internal error: {0}")]
    Internal(String),
    
    /// Activation code validation failures
    #[error("Invalid or expired activation code: {0}")]
    InvalidCode(String),
}

/// User management errors.
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    /// Database operations on users failed
    #[error("Database error: {source}\n{span:?}")]
    Database {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    
    /// User not found
    #[error("User not found: {0}")]
    NotFound(String),
    
    /// User already exists
    #[error("User already exists: {0}")]
    AlreadyExists(String),
    
    /// Password hashing or verification failed
    #[error("Password error: {source}\n{span:?}")]
    Password {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
}

// Specialized conversions for domain objects

impl From<diesel::result::Error> for UserError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => {
                UserError::NotFound("User record not found".to_string())
            }
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => UserError::AlreadyExists("Username or email already exists".to_string()),
            _ => UserError::Database {
                source: Box::new(err),
                span: SpanTrace::capture(),
            },
        }
    }
}

// Wrapper for argon2 errors to implement StdError trait
#[derive(Debug)]
struct Argon2ErrorWrapper(argon2::password_hash::Error);

impl fmt::Display for Argon2ErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Password hash error: {}", self.0)
    }
}

impl StdError for Argon2ErrorWrapper {}

impl From<argon2::password_hash::Error> for UserError {
    fn from(err: argon2::password_hash::Error) -> Self {
        UserError::Password {
            source: Box::new(Argon2ErrorWrapper(err)),
            span: SpanTrace::capture(),
        }
    }
}

// --------------------------------------------------------------------------
// Service Error (unified error type for business logic)
// --------------------------------------------------------------------------

/// Unified error type that encompasses all possible errors in the service.
///
/// This allows centralizing error handling logic while maintaining
/// rich context about the specific error type.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Database-related errors
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    
    /// Cache (Redis) errors
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),
    
    /// User management errors
    #[error("User error: {0}")]
    User(#[from] UserError),
    
    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    
    /// JWT-specific errors
    #[error("JWT error: {0}")]
    Jwt(#[from] JwtError),
    
    /// Email service errors
    #[error("Email error: {0}")]
    Email(#[from] EmailError),
}

// --------------------------------------------------------------------------
// Error Conversion Layer (to API responses)
// --------------------------------------------------------------------------

impl From<DatabaseError> for ApiError {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::Connection { .. } => {
                ApiError::service_unavailable("Database service unavailable")
            }
            DatabaseError::Migration { .. } => ApiError::internal("Database setup error"),
            DatabaseError::Query { source, .. } => {
                // Special handling for uniqueness constraints
                if let Some(diesel_err) = source.downcast_ref::<DieselError>() {
                    if let DieselError::DatabaseError(
                        diesel::result::DatabaseErrorKind::UniqueViolation,
                        _,
                    ) = diesel_err
                    {
                        return ApiError::unique_constraint("record", "already exists");
                    }
                }
                ApiError::internal("Database operation failed")
            }
            DatabaseError::NotFound => ApiError::not_found("Record"),
        }
    }
}

impl From<CacheError> for ApiError {
    fn from(err: CacheError) -> Self {
        match err {
            CacheError::Connection { .. } => {
                ApiError::service_unavailable("Cache service unavailable")
            }
            CacheError::Operation { .. } => ApiError::internal("Cache operation failed"),
        }
    }
}

impl From<ServiceError> for ApiError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::Database(db_err) => db_err.into(),
            ServiceError::Cache(cache_err) => cache_err.into(),
            ServiceError::User(user_err) => match user_err {
                UserError::NotFound(msg) => ApiError::not_found(&msg),
                UserError::AlreadyExists(msg) => ApiError::unique_constraint("user", &msg),
                UserError::Password { .. } => ApiError::internal("Password processing error"),
                UserError::Database { .. } => ApiError::internal("Database operation failed"),
            },
            ServiceError::Validation(val_err) => match val_err {
                ValidationError::InvalidValue(field, msg) => ApiError::validation(&field, &msg),
            },
            ServiceError::Jwt(jwt_err) => match jwt_err {
                JwtError::Configuration(msg) => ApiError::configuration(&msg),
                JwtError::Expired => ApiError::unauthorized("JWT token has expired"),
                JwtError::Invalid => ApiError::unauthorized("JWT token is invalid"),
                JwtError::InvalidSignature => {
                    ApiError::unauthorized("JWT token has invalid signature")
                }
                JwtError::Revoked => ApiError::unauthorized("JWT token has been revoked"),
                JwtError::InvalidIat => {
                    ApiError::unauthorized("JWT token has invalid issued-at time")
                }
                JwtError::Internal(msg) => ApiError::internal(&msg),
            },
            ServiceError::Email(email_error) => match email_error {
                EmailError::Configuration(msg) => ApiError::configuration(&msg),
                EmailError::Internal(msg) => ApiError::internal(&msg),
                EmailError::InvalidCode(msg) => ApiError::bad_request(&msg),
            },
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.status, self.message)
    }
}

// --------------------------------------------------------------------------
// API Integration (for Axum web framework)
// --------------------------------------------------------------------------

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        // Map API error statuses to HTTP status codes
        let status = match self.status {
            ApiStatus::ValidationError | ApiStatus::BadRequest => StatusCode::BAD_REQUEST,
            ApiStatus::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiStatus::NotFound => StatusCode::NOT_FOUND,
            ApiStatus::UniqueConstraintError => StatusCode::CONFLICT,
            ApiStatus::ConfigurationError | ApiStatus::InternalError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        };

        // Serialize to JSON with fallback for serialization errors
        let body = serde_json::to_string(&self).unwrap_or_else(|e| {
            log_error!("ApiError", &format!("Error serializing error: {}", e), "failure");
            "{\"status\": \"internal_error\", \"message\": \"Error serializing error message.\"}".to_string()
        });

        // Build HTTP response
        axum::response::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(axum::body::boxed(axum::body::Body::from(body)))
            .unwrap_or_else(|_| {
                // This should never happen, but provide a fallback just in case
                axum::response::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::boxed(axum::body::Body::from(
                        "{\"status\":\"internal_error\",\"message\":\"Failed to construct response\"}",
                    )))
                    .unwrap()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    
    #[test]
    fn api_error_formats_correctly() {
        let err = ApiError::validation("email", "invalid format");
        assert_eq!(format!("{}", err), "ValidationError: email: invalid format");
    }
    
    #[test]
    fn api_error_serializes_correctly() {
        let err = ApiError::not_found("User");
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "{\"status\":\"not_found\",\"message\":\"User not found\"}");
    }
    
    #[test]
    fn api_error_into_response_sets_correct_status_code() {
        let test_cases = vec![
            (ApiError::validation("test", "error"), StatusCode::BAD_REQUEST),
            (ApiError::unauthorized("test"), StatusCode::UNAUTHORIZED),
            (ApiError::not_found("test"), StatusCode::NOT_FOUND),
            (ApiError::unique_constraint("test", "error"), StatusCode::CONFLICT),
            (ApiError::internal("test"), StatusCode::INTERNAL_SERVER_ERROR),
            (ApiError::service_unavailable("test"), StatusCode::SERVICE_UNAVAILABLE),
        ];
        
        for (err, expected_status) in test_cases {
            let response = err.into_response();
            assert_eq!(response.status(), expected_status);
        }
    }
    
    #[test]
    fn service_error_converts_to_appropriate_api_error() {
        // JWT expiry error should map to unauthorized API error
        let jwt_err = ServiceError::Jwt(JwtError::Expired);
        let api_err: ApiError = jwt_err.into();
        assert_eq!(api_err.status, ApiStatus::Unauthorized);
        
        // ValidationError should map to validation API error
        let val_err = ServiceError::Validation(ValidationError::InvalidValue(
            "email".to_string(), 
            "invalid format".to_string()
        ));
        let api_err: ApiError = val_err.into();
        assert_eq!(api_err.status, ApiStatus::ValidationError);
        assert!(api_err.message.contains("email"));
    }
    
    #[test]
    fn database_error_maps_to_appropriate_api_error() {
        // NotFound -> NotFound
        let db_err = DatabaseError::NotFound;
        let api_err: ApiError = db_err.into();
        assert_eq!(api_err.status, ApiStatus::NotFound);
        
        // Connection -> ServiceUnavailable
        let conn_err = DatabaseError::Connection {
            source: Box::new(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test")),
            span: SpanTrace::capture(),
        };
        let api_err: ApiError = conn_err.into();
        assert_eq!(api_err.status, ApiStatus::ServiceUnavailable);
    }
}