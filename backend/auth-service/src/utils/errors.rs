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
// If you have defined an API_ERRORS metric, you can uncomment the following line:
// use crate::utils::metrics::API_ERRORS;

/// API error response structure.
///
/// This struct represents the standardized error format returned by the API.
/// It includes a status code identifier and a descriptive message.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// The error status code identifier (e.g., "validation_error")
    pub status: String,
    /// The human-readable error message.
    pub message: String,
}

impl ApiError {
    /// Creates a validation error for a specific field.
    ///
    /// # Arguments
    /// * `field` - The name of the field that failed validation.
    /// * `msg` - The validation error message.
    ///
    /// # Returns
    /// An ApiError with a `"validation_error"` status.
    pub fn validation_error(field: &str, msg: &str) -> Self {
        // Optionally, increment a metric:
        // API_ERRORS.with_label_values(&["validation_error"]).inc();
        log_debug!("ApiError", &format!("Validation error on {}: {}", field, msg), "created");
        ApiError {
            status: "validation_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }
    
    /// Creates a unique constraint violation error.
    ///
    /// # Arguments
    /// * `field` - The field with the unique constraint violation.
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with a `"unique_constraint_error"` status.
    pub fn unique_constraint_error(field: &str, msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["unique_constraint_error"]).inc();
        log_debug!("ApiError", &format!("Unique constraint error on {}: {}", field, msg), "created");
        ApiError {
            status: "unique_constraint_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }

    /// Creates an internal server error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with an `"internal_error"` status.
    pub fn internal_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["internal_error"]).inc();
        log_error!("ApiError", msg, "internal error created");
        ApiError { 
            status: "internal_error".to_string(), 
            message: msg.to_string() 
        }
    }

    /// Creates an unauthorized error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with an `"unauthorized"` status.
    pub fn unauthorized_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["unauthorized"]).inc();
        log_error!("ApiError", msg, "unauthorized error created");
        ApiError { 
            status: "unauthorized".to_string(), 
            message: msg.to_string() 
        }
    }

    /// Creates a forbidden error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with a `"forbidden"` status.
    pub fn forbidden_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["forbidden"]).inc();
        log_error!("ApiError", msg, "forbidden error created");
        ApiError { 
            status: "forbidden".to_string(), 
            message: msg.to_string() 
        }
    }
    
    /// Creates a not found error.
    ///
    /// # Arguments
    /// * `resource` - The type of resource that wasn't found.
    ///
    /// # Returns
    /// An ApiError with a `"not_found"` status.
    pub fn not_found_error(resource: &str) -> Self {
        // API_ERRORS.with_label_values(&["not_found"]).inc();
        log_debug!("ApiError", &format!("{} not found", resource), "not found error created");
        ApiError {
            status: "not_found".to_string(),
            message: format!("{} not found", resource),
        }
    }
    
    /// Creates a configuration error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with a `"configuration_error"` status.
    pub fn configuration_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["configuration_error"]).inc();
        log_error!("ApiError", msg, "configuration error created");
        ApiError {
            status: "configuration_error".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a rate limit exceeded error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with a `"rate_limit_exceeded"` status.
    pub fn rate_limit_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["rate_limit_exceeded"]).inc();
        log_error!("ApiError", msg, "rate limit error created");
        ApiError {
            status: "rate_limit_exceeded".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a bad request error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with a `"bad_request"` status.
    pub fn bad_request_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["bad_request"]).inc();
        log_debug!("ApiError", msg, "bad request error created");
        ApiError {
            status: "bad_request".to_string(),
            message: msg.to_string(),
        }
    }
    
    /// Creates a service unavailable error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// An ApiError with a `"service_unavailable"` status.
    pub fn service_unavailable_error(msg: &str) -> Self {
        // API_ERRORS.with_label_values(&["service_unavailable"]).inc();
        log_error!("ApiError", msg, "service unavailable error created");
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
        // Map error statuses to corresponding HTTP status codes.
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
            // Fallback if serialization fails.
            "{\"status\": \"internal_error\", \"message\": \"Error serializing error message.\"}".to_string()
        });

        axum::response::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(axum::body::boxed(axum::body::Body::from(body)))
            .unwrap()
    }
}