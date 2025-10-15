//! # HTTP Handler for Account Activation
//!
//! Provides the REST API endpoint for activating a user's account using a
//! single-use code.
//!
//! ## Endpoint
//! - `GET /auth/activate?code=...`: Activates an account.
//!
//! ## Design
//! - **Thin Controller**: This handler is responsible only for HTTP concerns. It
//!   extracts the activation code from the URL query parameters, delegates all
//!   business logic to the `activation_logic` module, and maps the result to an
//!   HTTP response.
//! - **Observability**: Each request is wrapped in a `tracing` span and measured
//!   with Prometheus metrics, including the final HTTP status code.

use crate::{
    app::AppState,
    handlers::activation_logic::process_activation,
    utils::errors::AuthServiceError,
};
use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

/// Defines the query parameter structure for activation.
/// Expects a URL like `/auth/activate?code=...`
#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    code: String,
}

/// Handles `GET /auth/activate?code=...`.
///
/// This function is the entry point for the account activation API. It takes an
/// activation code from the URL query parameters and attempts to activate the associated user account.
///
/// # Response Codes
/// - `200 OK`: Activation was successful, or the account was already active (idempotent).
/// - `400 Bad Request`: The activation code is invalid or has expired.
/// - `500 Internal Server Error`: An unexpected server-side error occurred.
pub async fn activation_handler(
    State(app_state): State<Arc<AppState>>,
    Query(params): Query<ActivationParams>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "account_activation",
        code_length = params.code.len()
    );

    async move {
        info!("Received account activation request.");

        let result = process_activation(&app_state, &params.code).await;

        match result {
            Ok(response) => {
                info!("Activation process completed successfully.");
                Ok(response)
            }
            Err(e) => {
                error!(error = ?e, "Activation process failed.");
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
}