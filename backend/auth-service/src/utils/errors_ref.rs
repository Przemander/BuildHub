//! Error handling utilities for the BuildHub Auth API.
//!
//! Provides unified domain error types and conversions into HTTP responses with consistent logging.

use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;
use tracing::{debug, error};
use thiserror::Error;
use diesel::result::Error as DieselError;
use tracing_error::SpanTrace;
use std::{error::Error as StdError, fmt};

// === API ERROR TYPES ===

/// Categories of API errors, serialized as snake_case.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    ValidationError,
    UniqueConstraintError,
    BadRequest,
    Unauthorized,
    NotFound,
    InternalError,
    ConfigurationError,
    ServiceUnavailable,
}

/// Structured API error for client responses.
#[derive(Debug, Serialize, Error)]
#[error("{status:?}: {message}")]
pub struct ApiError {
    pub status: ApiStatus,
    pub message: String,
}

impl ApiError {
    /// Create a new `ApiError`, logging at appropriate level.
    pub fn new(status: ApiStatus, message: impl Into<String>) -> Self {
        let message = message.into();
        match status {
            ApiStatus::InternalError
            | ApiStatus::ConfigurationError
            | ApiStatus::ServiceUnavailable
            | ApiStatus::Unauthorized => error!("{:?}: {}", status, message),
            _ => debug!("{:?}: {}", status, message),
        }
        ApiError { status, message }
    }

    pub fn validation(field: &str, msg: &str) -> Self {
        Self::new(ApiStatus::ValidationError, format!("{}: {}", field, msg))
    }
    pub fn unique(field: &str, msg: &str) -> Self {
        Self::new(ApiStatus::UniqueConstraintError, format!("{}: {}", field, msg))
    }
    pub fn bad_request(msg: &str) -> Self {
        Self::new(ApiStatus::BadRequest, msg)
    }
    pub fn unauthorized(msg: &str) -> Self {
        Self::new(ApiStatus::Unauthorized, msg)
    }
    pub fn not_found(resource: &str) -> Self {
        Self::new(ApiStatus::NotFound, format!("{} not found", resource))
    }
    pub fn config_error(msg: &str) -> Self {
        Self::new(ApiStatus::ConfigurationError, msg)
    }
    pub fn internal(msg: &str) -> Self {
        Self::new(ApiStatus::InternalError, msg)
    }
    pub fn service_unavailable(msg: &str) -> Self {
        Self::new(ApiStatus::ServiceUnavailable, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let code = match self.status {
            ApiStatus::ValidationError | ApiStatus::BadRequest => StatusCode::BAD_REQUEST,
            ApiStatus::UniqueConstraintError => StatusCode::CONFLICT,
            ApiStatus::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiStatus::NotFound => StatusCode::NOT_FOUND,
            ApiStatus::ConfigurationError | ApiStatus::InternalError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        let body = serde_json::to_string(&self).unwrap_or_else(|_| {
            "{\"status\":\"internal_error\",\"message\":\"Response serialization failed\"}".to_string()
        });
        axum::response::Response::builder()
            .status(code)
            .header("Content-Type", "application/json")
            .body(body.into())
            .unwrap()
    }
}

// === DOMAIN ERROR TYPES ===

/// Errors originating from database operations.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}\n{1:?}")]
    Connection(Box<dyn StdError + Send + Sync>, SpanTrace),
    #[error("Migration error: {0}\n{1:?}")]
    Migration(Box<dyn StdError + Send + Sync>, SpanTrace),
    #[error("Query error: {0}\n{1:?}")]
    Query(Box<dyn StdError + Send + Sync>, SpanTrace),
    #[error("Record not found")] NotFound,
}

impl From<DieselError> for DatabaseError {
    fn from(err: DieselError) -> Self {
        match err {
            DieselError::NotFound => DatabaseError::NotFound,
            _ => DatabaseError::Query(Box::new(err), SpanTrace::capture()),
        }
    }
}

impl From<DatabaseError> for ApiError {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::Connection(_, _) =>
                ApiError::service_unavailable("Database service unavailable"),
            DatabaseError::Migration(_, _) => ApiError::internal("Database migration failed"),
            DatabaseError::Query(source, _) => {
                if let Some(DieselError::DatabaseError(kind, _)) = source.downcast_ref::<DieselError>() {
                    if let diesel::result::DatabaseErrorKind::UniqueViolation = kind {
                        return ApiError::unique("record", "already exists");
                    }
                }
                ApiError::internal("Database query failed")
            }
            DatabaseError::NotFound => ApiError::not_found("Record"),
        }
    }
}

/// Errors from Redis (cache) operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Redis connection error: {0}\n{1:?}")]
    Connection(Box<dyn StdError + Send + Sync>, SpanTrace),
    #[error("Redis operation failed: {0}\n{1:?}")]
    Operation(Box<dyn StdError + Send + Sync>, SpanTrace),
}

impl From<redis::RedisError> for CacheError {
    fn from(err: redis::RedisError) -> Self {
        let span = SpanTrace::capture();
        if err.is_io_error() {
            CacheError::Connection(Box::new(err), span)
        } else {
            CacheError::Operation(Box::new(err), span)
        }
    }
}

impl From<CacheError> for ApiError {
    fn from(err: CacheError) -> Self {
        match err {
            CacheError::Connection(_, _) => ApiError::service_unavailable("Cache unavailable"),
            CacheError::Operation(_, _) => ApiError::internal("Cache operation failed"),
        }
    }
}

/// Validation errors for user input.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid value for '{0}': {1}")]
    InvalidValue(String, String),
    #[error("{0} already exists")] AlreadyExists(String),
}

/// Authentication-related errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")] InvalidCredentials,
    #[error("Account not activated")] AccountNotActivated,
    #[error("Token error: {0}")] TokenError(String),
}

/// JWT-specific errors.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT not configured: {0}")] Configuration(String),
    #[error("JWT expired")] Expired,
    #[error("JWT invalid")] Invalid,
    #[error("JWT invalid signature")] InvalidSignature,
    #[error("JWT revoked")] Revoked,
    #[error("JWT invalid issued-at time")] InvalidIat,
    #[error("JWT internal error: {0}")] Internal(String),
}

/// Email service errors.
#[derive(Debug, Error)]
pub enum EmailError {
    #[error("Email configuration error: {0}")] Configuration(String),
    #[error("Email internal error: {0}")] Internal(String),
    #[error("Invalid or expired activation code: {0}")] InvalidCode(String),
}

/// User domain errors.
#[derive(Debug, Error)]
pub enum UserError {
    #[error("Database error: {0}\n{1:?}")]
    Database(Box<dyn StdError + Send + Sync>, SpanTrace),
    #[error("User not found: {0}")] NotFound(String),
    #[error("User already exists: {0}")] AlreadyExists(String),
    #[error("Password error: {0}\n{1:?}")]
    Password(Box<dyn StdError + Send + Sync>, SpanTrace),
}

impl From<diesel::result::Error> for UserError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => UserError::NotFound("User record not found".into()),
            diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _) =>
                UserError::AlreadyExists("Username or email exists".into()),
            _ => UserError::Database(Box::new(err), SpanTrace::capture()),
        }
    }
}

/// Wrapper for Argon2 errors to implement StdError.
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
        UserError::Password(Box::new(Argon2ErrorWrapper(err)), SpanTrace::capture())
    }
}

/// Top-level service errors encapsulating all domain errors.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)] Database(#[from] DatabaseError),
    #[error(transparent)] Cache(#[from] CacheError),
    #[error(transparent)] User(#[from] UserError),
    #[error(transparent)] Auth(#[from] AuthError),
    #[error(transparent)] Jwt(#[from] JwtError),
    #[error(transparent)] Validation(#[from] ValidationError),
    #[error(transparent)] Email(#[from] EmailError),
    #[error("Internal error: {0}")] Internal(String),
    #[error("Not found: {0}")] NotFound(String),
}

impl From<ServiceError> for ApiError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::Database(db) => db.into(),
            ServiceError::Cache(c) => c.into(),
            ServiceError::User(u) => match u {
                UserError::NotFound(msg) => ApiError::not_found(&msg),
                UserError::AlreadyExists(msg) => ApiError::unique("user", &msg),
                _ => ApiError::internal("User service error"),
            },
            ServiceError::Auth(a) => match a {
                AuthError::InvalidCredentials => ApiError::unauthorized("Invalid credentials"),
                AuthError::AccountNotActivated => ApiError::unauthorized("Account not activated"),
                AuthError::TokenError(msg) => ApiError::unauthorized(&msg),
            },
            ServiceError::Jwt(j) => match j {
                JwtError::Configuration(msg) => ApiError::config_error(&msg),
                JwtError::Expired => ApiError::unauthorized("JWT expired"),
                _ => ApiError::unauthorized("JWT error"),
            },
            ServiceError::Validation(v) => match v {
                ValidationError::InvalidValue(f,m) => ApiError::validation(&f,&m),
                ValidationError::AlreadyExists(m) => ApiError::unique("validation", &m),
            },
            ServiceError::Email(e) => match e {
                EmailError::Configuration(msg) => ApiError::config_error(&msg),
                EmailError::InvalidCode(msg) => ApiError::bad_request(&msg),
                _ => ApiError::internal("Email service error"),
            },
            ServiceError::Internal(msg) => ApiError::internal(&msg),
            ServiceError::NotFound(msg) => ApiError::not_found(&msg),
        }
    }
}
