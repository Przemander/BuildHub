//! Error handling utilities for the API.
//!
//! This module provides a unified approach to error handling across the application,
//! with consistent error responses, status codes, and serialization formats.

use axum::{response::IntoResponse, http::StatusCode};
use serde::Serialize;
use std::fmt;

/// API error response structure.
///
/// This struct represents the standardized error format returned by the API.
/// It includes a status code identifier and a descriptive message.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// The error status code identifier (e.g., "validation_error")
    pub status: String,
    /// The human-readable error message
    pub message: String,
}

impl ApiError {
    /// Creates a validation error for a specific field.
    ///
    /// # Arguments
    /// * `field` - The name of the field that failed validation
    /// * `msg` - The validation error message
    ///
    /// # Returns
    /// An ApiError with validation error status (400 Bad Request)
    pub fn validation_error(field: &str, msg: &str) -> Self {
        ApiError {
            status: "validation_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }
    
    /// Creates a unique constraint violation error.
    ///
    /// # Arguments
    /// * `field` - The field with the unique constraint violation
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with unique constraint error status (409 Conflict)
    pub fn unique_constraint_error(field: &str, msg: &str) -> Self {
        ApiError {
            status: "unique_constraint_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }

    /// Creates an internal server error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with internal error status (500 Internal Server Error)
    pub fn internal_error(msg: &str) -> Self {
        ApiError {
            status: "internal_error".to_string(),
            message: msg.to_string(),
        }
    }

    /// Creates an unauthorized error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with unauthorized error status (401 Unauthorized)
    pub fn unauthorized_error(msg: &str) -> Self {
        ApiError {
            status: "unauthorized".to_string(),
            message: msg.to_string(),
        }
    }

    /// Creates a forbidden error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with forbidden error status (403 Forbidden)
    pub fn forbidden_error(msg: &str) -> Self {
        ApiError {
            status: "forbidden".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a not found error.
    ///
    /// # Arguments
    /// * `resource` - The type of resource that wasn't found
    ///
    /// # Returns
    /// An ApiError with not found error status (404 Not Found)
    pub fn not_found_error(resource: &str) -> Self {
        ApiError {
            status: "not_found".to_string(),
            message: format!("{} not found", resource),
        }
    }
    
    /// Creates a configuration error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with configuration error status (500 Internal Server Error)
    pub fn configuration_error(msg: &str) -> Self {
        ApiError {
            status: "configuration_error".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a rate limit exceeded error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with rate limit exceeded status (429 Too Many Requests)
    pub fn rate_limit_error(msg: &str) -> Self {
        ApiError {
            status: "rate_limit_exceeded".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a bad request error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with bad request status (400 Bad Request)
    pub fn bad_request_error(msg: &str) -> Self {
        ApiError {
            status: "bad_request".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a service unavailable error.
    ///
    /// # Arguments
    /// * `msg` - The error message
    ///
    /// # Returns
    /// An ApiError with service unavailable status (503 Service Unavailable)
    pub fn service_unavailable_error(msg: &str) -> Self {
        ApiError {
            status: "service_unavailable".to_string(),
            message: msg.to_string(),
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
        // Map error types to appropriate status codes
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
        
        let body = serde_json::to_string(&self).unwrap();
        axum::response::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(axum::body::boxed(axum::body::Body::from(body)))
            .unwrap()
    }
}