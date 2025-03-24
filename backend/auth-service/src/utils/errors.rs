use axum::{response::IntoResponse, http::StatusCode};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: String,
    pub message: String,
}

impl ApiError {
    pub fn validation_error(field: &str, msg: &str) -> Self {
        ApiError {
            status: "validation_error".to_string(),
            message: format!("{}: {}", field, msg),
        }
    }
    
    pub fn unique_constraint_error(field: &str, msg: &str) -> Self {
        ApiError {
            status: "unique_constraint_error".to_string(),
            message: format!("{}: {}", field, msg),
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
        let body = serde_json::to_string(&self).unwrap();
        axum::response::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(axum::body::boxed(axum::body::Body::from(body)))
            .unwrap()
    }
}