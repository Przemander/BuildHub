//! Error handling utilities for the API.
//!
//! Provides unified error types, conversions, and consistent API error responses.

use crate::{log_debug, log_error};
use axum::{http::StatusCode, response::IntoResponse};
use diesel::result::Error as DieselError;
use serde::Serialize;
use std::error::Error as StdError;
use std::fmt;
use tracing_error::SpanTrace;

/// Enum for API error status codes (compile-time safety, serializes as snake_case).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    ValidationError,
    UniqueConstraintError,
    InternalError,
    Unauthorized,
    NotFound,
    ConfigurationError,
    BadRequest,
    ServiceUnavailable,
    // RateLimitExceeded, // Removed as unused
}

impl fmt::Display for ApiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// API error response structure.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: ApiStatus,
    pub message: String,
}

impl ApiError {
    pub fn new(status: ApiStatus, msg: impl Into<String>) -> Self {
        let msg_str: String = msg.into();
        match status {
            ApiStatus::InternalError
            | ApiStatus::Unauthorized
            | ApiStatus::ServiceUnavailable
            | ApiStatus::ConfigurationError => {
                log_error!("ApiError", &msg_str, &format!("{:?} error created", status));
            }
            _ => {
                log_debug!("ApiError", &msg_str, &format!("{:?} error created", status));
            }
        }
        ApiError {
            status,
            message: msg_str,
        }
    }
    // Convenience constructors
    pub fn validation(field: &str, msg: &str) -> Self {
        Self::new(ApiStatus::ValidationError, format!("{}: {}", field, msg))
    }
    pub fn unique_constraint(field: &str, msg: &str) -> Self {
        Self::new(
            ApiStatus::UniqueConstraintError,
            format!("{}: {}", field, msg),
        )
    }
    pub fn internal<M: Into<String>>(msg: M) -> Self {
        Self::new(ApiStatus::InternalError, msg)
    }
    pub fn unauthorized<M: Into<String>>(msg: M) -> Self {
        Self::new(ApiStatus::Unauthorized, msg)
    }
    pub fn not_found(resource: &str) -> Self {
        Self::new(ApiStatus::NotFound, format!("{} not found", resource))
    }
    pub fn configuration(msg: &str) -> Self {
        Self::new(ApiStatus::ConfigurationError, msg)
    }
    pub fn bad_request(msg: &str) -> Self {
        Self::new(ApiStatus::BadRequest, msg)
    }
    pub fn service_unavailable(msg: &str) -> Self {
        Self::new(ApiStatus::ServiceUnavailable, msg)
    }
    // pub fn rate_limit<M: Into<String>>(msg: M) -> Self {
    //     Self::new(ApiStatus::RateLimitExceeded, msg)
    // }
}

// --- Database Error ---
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
            },
        }
    }
}

impl From<DatabaseError> for ApiError {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::Connection { .. } => {
                ApiError::service_unavailable("Database service unavailable")
            }
            DatabaseError::Migration { .. } => ApiError::internal("Database setup error"),
            DatabaseError::Query { source, .. } => {
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

// --- Cache (Redis) Error ---
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
                ApiError::service_unavailable("Cache service unavailable")
            }
            CacheError::Operation { .. } => ApiError::internal("Cache operation failed"),
        }
    }
}

// --- Validation Error ---
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("The value for field '{0}' is invalid: {1}")]
    InvalidValue(String, String),
    #[allow(dead_code)]
    #[error("{0} already exists")]
    AlreadyExists(String),
}

// --- Authentication Error ---
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[allow(dead_code)]
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[allow(dead_code)]
    #[error("Account not activated")]
    AccountNotActivated,
    #[allow(dead_code)]
    #[error("Token error: {0}")]
    TokenError(String),
}

// --- JWT Error ---
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

// --- Email Error ---
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Email configuration error: {0}")]
    Configuration(String),
    #[error("Email internal error: {0}")]
    Internal(String),
    #[error("Invalid or expired activation code: {0}")]
    InvalidCode(String),
}

// --- User Error ---
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

// --- ServiceError ---
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
    #[allow(dead_code)]
    #[error("Internal error: {0}")]
    Internal(String),
    #[allow(dead_code)]
    #[error("Email error: {0}")]
    Email(#[from] EmailError),
    #[allow(dead_code)]
    #[error("Not found: {0}")]
    NotFound(String),
}

// --- ServiceError to ApiError conversion ---
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
            ServiceError::Auth(auth_err) => match auth_err {
                AuthError::InvalidCredentials => ApiError::unauthorized("Invalid credentials"),
                AuthError::AccountNotActivated => ApiError::unauthorized("Account not activated"),
                AuthError::TokenError(msg) => ApiError::unauthorized(&msg),
            },
            ServiceError::Validation(val_err) => match val_err {
                ValidationError::InvalidValue(field, msg) => ApiError::validation(&field, &msg),
                ValidationError::AlreadyExists(msg) => {
                    ApiError::unique_constraint("validation", &msg)
                }
            },
            ServiceError::Jwt(jwt_err) => match jwt_err {
                JwtError::Configuration(msg) => ApiError::configuration(&msg),
                JwtError::Expired => ApiError::unauthorized("JWT token is expired"),
                JwtError::Invalid => ApiError::unauthorized("JWT token is invalid"),
                JwtError::InvalidSignature => {
                    ApiError::unauthorized("JWT token has invalid signature")
                }
                JwtError::Revoked => ApiError::unauthorized("JWT token is revoked"),
                JwtError::InvalidIat => {
                    ApiError::unauthorized("JWT token has invalid issued-at time")
                }
                JwtError::Internal(msg) => ApiError::internal(&msg),
            },
            ServiceError::Internal(msg) => ApiError::internal(&msg),
            ServiceError::NotFound(msg) => ApiError::not_found(&msg),
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

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.status {
            ApiStatus::ValidationError | ApiStatus::BadRequest => StatusCode::BAD_REQUEST,
            ApiStatus::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiStatus::NotFound => StatusCode::NOT_FOUND,
            ApiStatus::UniqueConstraintError => StatusCode::CONFLICT,
            // ApiStatus::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS, // Removed as unused
            ApiStatus::ConfigurationError | ApiStatus::InternalError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
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

