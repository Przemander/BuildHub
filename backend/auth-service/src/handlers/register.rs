//! # HTTP Handler for User Registration
//!
//! Provides the REST API interface for the user registration endpoint. This module
//! acts as a thin controller layer, responsible for:
//! - Deserializing the incoming HTTP request.
//! - Initiating observability (tracing spans, metrics).
//! - Delegating the core logic to the `process_registration` function.
//! - Mapping the business logic result (`Ok` or `Err`) to an appropriate
//!   HTTP response.

use crate::{
    app::AppState,
    handlers::register_logic::process_registration,
    utils::errors::AuthServiceError,
};
use axum::{extract::State, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

/// Request payload for user registration.
/// This is the definitive structure for the /auth/register endpoint.
#[derive(Deserialize, Clone)]
pub struct RegisterData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Handles POST /auth/register requests.
///
/// This function is the entry point for the registration API. It validates the
/// incoming JSON payload, orchestrates the registration process, and returns a
/// structured HTTP response.
///
/// # Request Format
/// ```json
/// {
///   "username": "john_doe",
///   "email": "john@example.com",
///   "password": "SecurePass123!"
/// }
/// ```
///
/// # Response Codes
/// - `201 Created`: Registration was successful.
/// - `400 Bad Request`: Validation failed (e.g., weak password, duplicate user).
/// - `422 Unprocessable Entity`: The request body is malformed or missing fields.
/// - `500 Internal Server Error`: An unexpected server-side error occurred.
pub async fn register_handler(
    State(app_state): State<Arc<AppState>>,
    Json(data): Json<RegisterData>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "user_registration",
        username = %data.username,
        email_domain = data.email.split('@').nth(1).unwrap_or("unknown")
    );

    async move {
        info!("Received registration request.");

        let result = process_registration(&app_state, data).await;

        match result {
            Ok(response) => {
                info!("Registration process completed successfully.");
                Ok(response)
            }
            Err(e) => {
                error!(error = ?e, "Registration process failed.");
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
}