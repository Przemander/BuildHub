//! Error handling for the auth service.
//!
//! Provides a clean two-layer error system: internal errors with context
//! and public API errors for client responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use tracing::{error, warn};
use tracing_error::SpanTrace;

use crate::utils::metrics;  // Fixed: correct import path

// =============================================================================
// PUBLIC API ERRORS
// =============================================================================

/// API error response structure.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: &'static str,
    pub message: String,
    #[serde(skip)]
    pub code: StatusCode,
}

impl ApiError {
    pub fn new(code: StatusCode, status: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
            code,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.code;
        (code, Json(self)).into_response()
    }
}

// =============================================================================
// CACHE ERRORS
// =============================================================================

/// Redis cache operation errors.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Redis connection error")]
    Connection {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        span: SpanTrace,
    },

    #[error("Redis operation error")]
    Operation {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        span: SpanTrace,
    },

    #[error("Cache key not found: {key}")]
    KeyNotFound { key: String, span: SpanTrace },
}

impl From<redis::RedisError> for CacheError {
    fn from(err: redis::RedisError) -> Self {
        match err.kind() {
            redis::ErrorKind::IoError => CacheError::Connection {
                source: Box::new(err),
                span: SpanTrace::capture(),
            },
            _ => CacheError::Operation {
                source: Box::new(err),
                span: SpanTrace::capture(),
            },
        }
    }
}

// =============================================================================
// MAIN SERVICE ERROR
// =============================================================================

/// Main error type for the auth service.
#[derive(Debug, Error)]
pub enum AuthServiceError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    #[error("Validation error: {field}: {message}")]
    Validation { field: String, message: String },

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("External service error: {0}")]
    External(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

// Helper constructors
impl AuthServiceError {
    pub fn configuration(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        error!("Configuration error: {}", msg);
        metrics::errors::configuration();
        AuthServiceError::Configuration(msg)
    }

    pub fn database(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        error!("Database error: {}", msg);
        metrics::errors::database();
        AuthServiceError::Database(msg)
    }

    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        let field = field.into();
        let message = message.into();
        warn!("Validation error for {}: {}", field, message);
        metrics::errors::validation();
        AuthServiceError::Validation { field, message }
    }

    pub fn authentication(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        warn!("Authentication error: {}", msg);
        metrics::errors::authentication();
        AuthServiceError::Authentication(msg)
    }

    pub fn external(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        error!("External service error: {}", msg);
        metrics::errors::external();
        AuthServiceError::External(msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        error!("Internal error: {}", msg);
        metrics::errors::internal();
        AuthServiceError::Internal(msg)
    }
}

// Convert internal errors to API responses
impl IntoResponse for AuthServiceError {
    fn into_response(self) -> Response {
        let (status_code, status_str, message) = match &self {
            AuthServiceError::Configuration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                "Service temporarily unavailable",
            ),
            AuthServiceError::Database(msg) => {
                if msg.contains("not found") || msg.contains("Not found") {
                    (StatusCode::NOT_FOUND, "not_found", "Resource not found")
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "database_error",
                        "Database operation failed",
                    )
                }
            }
            AuthServiceError::Cache(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "cache_error",
                "Service temporarily unavailable",
            ),
            AuthServiceError::Validation { field, message } => {
                // Include the actual validation error for the client
                return ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "validation_error",
                    format!("{}: {}", field, message),
                )
                .into_response();
            }
            AuthServiceError::Authentication(msg) => {
                // Include auth error for better UX
                return ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", msg.clone())
                    .into_response();
            }
            AuthServiceError::External(_) => (
                StatusCode::BAD_GATEWAY,
                "external_error",
                "External service error",
            ),
            AuthServiceError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An internal error occurred",
            ),
        };

        ApiError::new(status_code, status_str, message).into_response()
    }
}

// Database error conversions
impl From<diesel::result::Error> for AuthServiceError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => {
                AuthServiceError::database("Resource not found")
            }
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                info,
            ) => {
                let field = info
                    .constraint_name()
                    .and_then(|name| {
                        if name.contains("email") {
                            Some("email")
                        } else if name.contains("username") {
                            Some("username")
                        } else {
                            None
                        }
                    })
                    .unwrap_or("field");

                AuthServiceError::validation(field, "Already exists")
            }
            _ => AuthServiceError::database(format!("Database error: {}", err)),
        }
    }
}

impl From<r2d2::Error> for AuthServiceError {
    fn from(err: r2d2::Error) -> Self {
        AuthServiceError::database(format!("Connection pool error: {}", err))
    }
}

impl From<redis::RedisError> for AuthServiceError {
    fn from(err: redis::RedisError) -> Self {
        AuthServiceError::Cache(CacheError::from(err))
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    use std::fmt;

    // Mock for diesel::result::DatabaseErrorInformation
    #[derive(Debug)]
    struct MockDbError {
        constraint: Option<String>,
    }

    impl fmt::Display for MockDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Mock DB Error")
        }
    }

    impl std::error::Error for MockDbError {}

    impl diesel::result::DatabaseErrorInformation for MockDbError {
        fn message(&self) -> &str {
            "mock error"
        }
        fn details(&self) -> Option<&str> {
            None
        }
        fn hint(&self) -> Option<&str> {
            None
        }
        fn table_name(&self) -> Option<&str> {
            None
        }
        fn column_name(&self) -> Option<&str> {
            None
        }
        fn constraint_name(&self) -> Option<&str> {
            self.constraint.as_deref()
        }
        fn statement_position(&self) -> Option<i32> {
            None
        }
    }

    #[test]
    fn test_api_error_creation() {
        let error = ApiError::new(StatusCode::BAD_REQUEST, "validation_error", "Invalid input");
        assert_eq!(error.status, "validation_error");
        assert_eq!(error.message, "Invalid input");
        assert_eq!(error.code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_api_error_with_string_message() {
        let message = String::from("Dynamic error message");
        let error = ApiError::new(StatusCode::NOT_FOUND, "not_found", message);
        assert_eq!(error.message, "Dynamic error message");
    }

    #[test]
    fn test_auth_service_error_constructors() {
        let err = AuthServiceError::configuration("Missing env var");
        assert!(matches!(err, AuthServiceError::Configuration(_)));

        let err = AuthServiceError::database("Connection failed");
        assert!(matches!(err, AuthServiceError::Database(_)));

        let err = AuthServiceError::validation("email", "Invalid format");
        assert!(matches!(err, AuthServiceError::Validation { .. }));

        let err = AuthServiceError::authentication("Bad token");
        assert!(matches!(err, AuthServiceError::Authentication(_)));

        let err = AuthServiceError::external("API down");
        assert!(matches!(err, AuthServiceError::External(_)));

        let err = AuthServiceError::internal("Panic");
        assert!(matches!(err, AuthServiceError::Internal(_)));
    }

    #[test]
    fn test_cache_error_key_not_found() {
        let err = CacheError::KeyNotFound {
            key: "session:123".to_string(),
            span: SpanTrace::capture(),
        };
        let err_str = format!("{}", err);
        assert!(err_str.contains("Cache key not found"));
        assert!(err_str.contains("session:123"));
    }

    #[test]
    fn test_error_conversion_to_response() {
        let err = AuthServiceError::validation("username", "Too short");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_diesel_not_found_conversion() {
        let diesel_err = DieselError::NotFound;
        let auth_err: AuthServiceError = diesel_err.into();
        match auth_err {
            AuthServiceError::Database(msg) => assert!(msg.contains("not found")),
            _ => panic!("Expected Database error"),
        }
    }

    #[test]
    fn test_diesel_unique_violation_email() {
        let info = Box::new(MockDbError {
            constraint: Some("users_email_key".to_string()),
        });
        let diesel_err = DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info);
        let auth_err: AuthServiceError = diesel_err.into();
        
        match auth_err {
            AuthServiceError::Validation { field, message } => {
                assert_eq!(field, "email");
                assert_eq!(message, "Already exists");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_diesel_unique_violation_username() {
        let info = Box::new(MockDbError {
            constraint: Some("users_username_key".to_string()),
        });
        let diesel_err = DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info);
        let auth_err: AuthServiceError = diesel_err.into();
        
        match auth_err {
            AuthServiceError::Validation { field, message } => {
                assert_eq!(field, "username");
                assert_eq!(message, "Already exists");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_diesel_unique_violation_unknown_field() {
        let info = Box::new(MockDbError {
            constraint: Some("unknown_constraint".to_string()),
        });
        let diesel_err = DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info);
        let auth_err: AuthServiceError = diesel_err.into();
        
        match auth_err {
            AuthServiceError::Validation { field, message } => {
                assert_eq!(field, "field"); // Falls back to generic "field"
                assert_eq!(message, "Already exists");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_diesel_other_database_errors() {
        let info = Box::new(MockDbError { constraint: None });
        let diesel_err = DieselError::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, info);
        let auth_err: AuthServiceError = diesel_err.into();
        assert!(matches!(auth_err, AuthServiceError::Database(_)));
    }

    #[test]
    fn test_cache_error_from_redis_io() {
        let redis_err = redis::RedisError::from((
            redis::ErrorKind::IoError,
            "Connection refused",
        ));
        let cache_err: CacheError = redis_err.into();
        assert!(matches!(cache_err, CacheError::Connection { .. }));
    }

    #[test]
    fn test_cache_error_from_redis_type_error() {
        let redis_err = redis::RedisError::from((
            redis::ErrorKind::TypeError,
            "Wrong type",
        ));
        let cache_err: CacheError = redis_err.into();
        assert!(matches!(cache_err, CacheError::Operation { .. }));
    }

    #[test]
    fn test_auth_service_error_from_redis() {
        let redis_err = redis::RedisError::from((
            redis::ErrorKind::IoError,
            "Connection refused",
        ));
        let auth_err: AuthServiceError = redis_err.into();
        assert!(matches!(auth_err, AuthServiceError::Cache(_)));
    }

    #[test]
    fn test_configuration_error_response_status() {
        let err = AuthServiceError::configuration("DATABASE_URL missing");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_validation_error_response_status() {
        let err = AuthServiceError::validation("password", "Must be at least 8 characters");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_authentication_error_response_status() {
        let err = AuthServiceError::authentication("Invalid credentials");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_database_error_response_status() {
        let err = AuthServiceError::database("Connection failed");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_database_not_found_error_response_status() {
        let err = AuthServiceError::database("User not found");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_database_error_with_not_found_lowercase() {
        let err = AuthServiceError::database("Resource Not found");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_cache_error_response_status() {
        let redis_err = redis::RedisError::from((
            redis::ErrorKind::IoError,
            "Connection refused",
        ));
        let err = AuthServiceError::from(redis_err);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_external_error_response_status() {
        let err = AuthServiceError::external("Email service unavailable");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_internal_error_response_status() {
        let err = AuthServiceError::internal("Unexpected error");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_display_messages() {
        let err = AuthServiceError::Configuration("test".to_string());
        assert_eq!(format!("{}", err), "Configuration error: test");

        let err = AuthServiceError::Database("test".to_string());
        assert_eq!(format!("{}", err), "Database error: test");

        let err = AuthServiceError::Validation {
            field: "email".to_string(),
            message: "invalid".to_string(),
        };
        assert_eq!(format!("{}", err), "Validation error: email: invalid");

        let err = AuthServiceError::Authentication("test".to_string());
        assert_eq!(format!("{}", err), "Authentication error: test");

        let err = AuthServiceError::External("test".to_string());
        assert_eq!(format!("{}", err), "External service error: test");

        let err = AuthServiceError::Internal("test".to_string());
        assert_eq!(format!("{}", err), "Internal error: test");
    }
}
