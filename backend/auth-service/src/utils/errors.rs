//! Error handling utilities for the API.
//!
//! This module provides a unified approach to error handling across the application,
//! with consistent error responses, status codes, and serialization formats.
//!
//! Additionally, it logs error creation and (optionally) increments error metrics.

use axum::{response::IntoResponse, http::StatusCode};
use serde::Serialize;
use std::fmt;
use crate::{log_error, log_debug};
use tracing_error::SpanTrace;
use diesel::result::Error as DieselError;
use std::error::Error as StdError;

/// API error response structure.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: String,
    pub message: String,
}

impl ApiError {
    pub fn validation_error(field: &str, msg: &str) -> Self {
        log_debug!("ApiError", &format!("Validation error on {}: {}", field, msg), "created");
        ApiError {
            status: "validation_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }
    pub fn unique_constraint_error(field: &str, msg: &str) -> Self {
        log_debug!("ApiError", &format!("Unique constraint error on {}: {}", field, msg), "created");
        ApiError {
            status: "unique_constraint_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }
    pub fn internal_error(msg: &str) -> Self {
        log_error!("ApiError", msg, "internal error created");
        ApiError { 
            status: "internal_error".to_string(), 
            message: msg.to_string() 
        }
    }
    pub fn unauthorized_error(msg: &str) -> Self {
        log_error!("ApiError", msg, "unauthorized error created");
        ApiError { 
            status: "unauthorized".to_string(), 
            message: msg.to_string() 
        }
    }
    pub fn not_found_error(resource: &str) -> Self {
        log_debug!("ApiError", &format!("{} not found", resource), "not found error created");
        ApiError {
            status: "not_found".to_string(),
            message: format!("{} not found", resource),
        }
    }
    pub fn configuration_error(msg: &str) -> Self {
        log_error!("ApiError", msg, "configuration error created");
        ApiError {
            status: "configuration_error".to_string(),
            message: msg.to_string(),
        }
    }
    pub fn bad_request_error(msg: &str) -> Self {
        log_debug!("ApiError", msg, "bad request error created");
        ApiError {
            status: "bad_request".to_string(),
            message: msg.to_string(),
        }
    }
    pub fn service_unavailable_error(msg: &str) -> Self {
        log_error!("ApiError", msg, "service unavailable error created");
        ApiError {
            status: "service_unavailable".to_string(),
            message: msg.to_string(),
        }
    }
}

/// Database-related errors
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Database connection error: {source}\n{span:?}")]
    Connection {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    #[error("Database migration error: {source}\n{span:?}")]
    Migration {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    #[error("Database query error: {source}\n{span:?}")]
    Query {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
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
            }
        }
    }
}

impl From<DatabaseError> for ApiError {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::Connection { .. } => {
                log_error!("Database", "Connection failed", "failure");
                ApiError::service_unavailable_error("Database service unavailable")
            },
            DatabaseError::Migration { .. } => {
                log_error!("Database", "Migration failed", "failure");
                ApiError::internal_error("Database setup error")
            },
            DatabaseError::Query { source, .. } => {
                if let Some(diesel_err) = source.downcast_ref::<DieselError>() {
                    if let DieselError::DatabaseError(
                        diesel::result::DatabaseErrorKind::UniqueViolation, _
                    ) = diesel_err {
                        return ApiError::unique_constraint_error("record", "already exists");
                    }
                }
                log_error!("Database", "Query failed", "failure");
                ApiError::internal_error("Database operation failed")
            },
            DatabaseError::NotFound => {
                ApiError::not_found_error("Record")
            },
        }
    }
}

/// Cache (Redis) related errors
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis connection error: {source}\n{span:?}")]
    Connection {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    #[error("Redis operation failed: {source}\n{span:?}")]
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

impl From<CacheError> for ApiError {
    fn from(err: CacheError) -> Self {
        match err {
            CacheError::Connection { .. } => {
                log_error!("Redis", "Connection failed", "failure");
                ApiError::service_unavailable_error("Cache service unavailable")
            },
            CacheError::Operation { .. } => {
                log_error!("Redis", "Operation failed", "failure");
                ApiError::internal_error("Cache operation failed")
            },
        }
    }
}

/// Validation error types
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("The value for field '{0}' is invalid: {1}")]
    InvalidValue(String, String),
    #[error("{0} already exists")]
    AlreadyExists(String),
}

/// Authentication related errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Account not activated")]
    AccountNotActivated,
    #[error("Token error: {0}")]
    TokenError(String),
}

/// JWT-specific errors for token operations.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("JWT secret is not configured")]
    Configuration(String),
    #[error("JWT token is expired")]
    Expired,
    #[error("JWT token is invalid")]
    Invalid,
    #[error("JWT token has invalid signature")]
    InvalidSignature,
    #[error("JWT token is revoked")]
    Revoked,
    #[error("JWT token has invalid issued-at time")]
    InvalidIat,
    #[error("JWT internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Email configuration error: {0}")]
    Configuration(String),
    #[error("Email internal error: {0}")]
    Internal(String),
    #[error("Invalid or expired activation code: {0}")]
    InvalidCode(String),
}

/// User management errors
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("Database error: {source}\n{span:?}")]
    Database {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
    #[error("User not found: {0}")]
    NotFound(String),
    #[error("User already exists: {0}")]
    AlreadyExists(String),
    #[error("Password error: {source}\n{span:?}")]
    Password {
        source: Box<dyn StdError + Send + Sync>,
        span: SpanTrace,
    },
}

/// Service-level errors that can be converted to ApiErrors
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),
    #[error("User error: {0}")]
    User(#[from] UserError),
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("JWT error: {0}")]
    Jwt(#[from] JwtError),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Email error: {0}")]
    Email(#[from] EmailError),
    #[error("Not found: {0}")]
    NotFound(String),
}

impl From<diesel::result::Error> for UserError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => {
                UserError::NotFound("User record not found".to_string())
            },
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation, _
            ) => {
                UserError::AlreadyExists("Username or email already exists".to_string())
            },
            _ => UserError::Database {
                source: Box::new(err),
                span: SpanTrace::capture(),
            }
        }
    }
}

// Wrapper for argon2 errors that implements std::error::Error
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

// ServiceError to ApiError conversion
impl From<ServiceError> for ApiError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::Database(db_err) => db_err.into(),
            ServiceError::Cache(cache_err) => cache_err.into(),
            ServiceError::User(user_err) => {
                match user_err {
                    UserError::NotFound(msg) => ApiError::not_found_error(&msg),
                    UserError::AlreadyExists(msg) => ApiError::unique_constraint_error("user", &msg),
                    UserError::Password { .. } => ApiError::internal_error("Password processing error"),
                    UserError::Database { .. } => ApiError::internal_error("Database operation failed"),
                }
            },
            ServiceError::Auth(auth_err) => {
                match auth_err {
                    AuthError::InvalidCredentials => ApiError::unauthorized_error("Invalid credentials"),
                    AuthError::AccountNotActivated => ApiError::unauthorized_error("Account not activated"),
                    AuthError::TokenError(msg) => ApiError::unauthorized_error(&msg),
                }
            },
            ServiceError::Validation(val_err) => {
                match val_err {
                    ValidationError::InvalidValue(field, msg) => ApiError::validation_error(&field, &msg),
                    ValidationError::AlreadyExists(msg) => ApiError::unique_constraint_error("validation", &msg),
                }
            },
            ServiceError::Jwt(jwt_err) => {
                match jwt_err {
                    JwtError::Configuration(msg) => ApiError::configuration_error(&msg),
                    JwtError::Expired => ApiError::unauthorized_error("JWT token is expired"),
                    JwtError::Invalid => ApiError::unauthorized_error("JWT token is invalid"),
                    JwtError::InvalidSignature => ApiError::unauthorized_error("JWT token has invalid signature"),
                    JwtError::Revoked => ApiError::unauthorized_error("JWT token is revoked"),
                    JwtError::InvalidIat => ApiError::unauthorized_error("JWT token has invalid issued-at time"),
                    JwtError::Internal(msg) => ApiError::internal_error(&msg),
                }
            },
            ServiceError::Internal(msg) => ApiError::internal_error(&msg),
            ServiceError::NotFound(msg) => ApiError::not_found_error(&msg),
            ServiceError::Email(email_error) => {
                match email_error {
                    EmailError::Configuration(msg) => ApiError::configuration_error(&msg),
                    EmailError::Internal(msg) => ApiError::internal_error(&msg),
                    EmailError::InvalidCode(msg) => ApiError::bad_request_error(&msg),
                }
            }
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.status.as_str() {
            "validation_error" | "bad_request" => StatusCode::BAD_REQUEST,
            "unauthorized" => StatusCode::UNAUTHORIZED,
            "forbidden" => StatusCode::FORBIDDEN,
            "not_found" => StatusCode::NOT_FOUND,
            "unique_constraint_error" => StatusCode::CONFLICT,
            "rate_limit_exceeded" => StatusCode::TOO_MANY_REQUESTS,
            "configuration_error" | "internal_error" => StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = serde_json::to_string(&self).unwrap_or_else(|_| {
            "{\"status\": \"internal_error\", \"message\": \"Error serializing error message.\"}".to_string()
        });

        axum::response::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(axum::body::boxed(axum::body::Body::from(body)))
            .unwrap()
    }
}