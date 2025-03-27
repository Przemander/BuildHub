use axum::{response::IntoResponse, http::StatusCode};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: String,
    pub message: String,
}

impl ApiError {
    // Validation errors (400 Bad Request)
    pub fn validation_error(field: &str, msg: &str) -> Self {
        ApiError {
            status: "validation_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }
    
    // Unique constraint violations (409 Conflict)
    pub fn unique_constraint_error(field: &str, msg: &str) -> Self {
        ApiError {
            status: "unique_constraint_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }

    // Internal server errors (500 Internal Server Error)
    pub fn internal_error(msg: &str) -> Self {
        ApiError {
            status: "internal_error".to_string(),
            message: msg.to_string(),
        }
    }

    // Authentication errors (401 Unauthorized)
    pub fn unauthorized_error(msg: &str) -> Self {
        ApiError {
            status: "unauthorized".to_string(),
            message: msg.to_string(),
        }
    }

    // Permission errors (403 Forbidden)
    pub fn forbidden_error(msg: &str) -> Self {
        ApiError {
            status: "forbidden".to_string(),
            message: msg.to_string(),
        }
    }
    
    // Resource not found errors (404 Not Found)
    pub fn not_found_error(resource: &str) -> Self {
        ApiError {
            status: "not_found".to_string(),
            message: format!("{} not found", resource),
        }
    }
    
    // Configuration errors (500 Internal Server Error)
    pub fn configuration_error(msg: &str) -> Self {
        ApiError {
            status: "configuration_error".to_string(),
            message: msg.to_string(),
        }
    }
    
    // Rate limit exceeded (429 Too Many Requests)
    pub fn rate_limit_error(msg: &str) -> Self {
        ApiError {
            status: "rate_limit_exceeded".to_string(),
            message: msg.to_string(),
        }
    }
    
    // Bad request errors (400 Bad Request)
    pub fn bad_request_error(msg: &str) -> Self {
        ApiError {
            status: "bad_request".to_string(),
            message: msg.to_string(),
        }
    }
    
    // Service unavailable errors (503 Service Unavailable)
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