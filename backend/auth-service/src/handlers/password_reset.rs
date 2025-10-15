//! # Password Reset HTTP Handlers
//!
//! This module provides the REST API endpoints for the secure, two-step password
//! reset flow. It acts as a thin controller layer, delegating all business logic
//! to the `password_reset_logic` module.
//!
//! ## Endpoints
//! - `POST /auth/password-reset/request`: Initiates the reset process.
//! - `POST /auth/password-reset/confirm`: Confirms the reset with a token.
//!
//! ## Design
//! - **Thin Controller**: Handlers are responsible only for HTTP concerns like
//!   deserialization, observability setup, and response mapping.
//! - **Security-First**: The request handler always returns `200 OK` to prevent
//!   user enumeration, a critical security best practice.
//! - **Observability**: Each request is wrapped in a `tracing` span and measured
//!   with Prometheus metrics.

use crate::{
    app::AppState,
    handlers::password_reset_logic::{
        process_password_reset_confirm, process_password_reset_request,
    },
    utils::errors::AuthServiceError,
};
use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

/// Request payload for initiating a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// Request payload for confirming a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    pub token: String,
    pub new_password: String,
}

/// Handles `POST /auth/password-reset/request`.
///
/// This handler initiates the password reset flow. For security reasons (to prevent
/// user enumeration attacks), it **always returns a 200 OK response** with a
/// generic message, regardless of whether the email exists in the database or if an
/// internal error occurred. All errors are logged internally for monitoring.
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Response {
    let span = span!(Level::INFO, "password_reset_request",
        email_domain = req.email.split('@').nth(1).unwrap_or("unknown")
    );

    async move {
        info!("Received password reset request");

        // The business logic is called, but any error is only logged internally.
        // This is a security measure to prevent user enumeration.
        if let Err(e) = process_password_reset_request(&app_state, &req.email).await {
            error!("Internal error during password reset request: {}", e);
        }

        // Always return a generic success response.
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "message": "If an account with that email exists, a password reset link has been sent."
            })),
        )
        .into_response()
    }
    .instrument(span)
    .await
}

/// Handles `POST /auth/password-reset/confirm`.
///
/// This handler completes the password reset flow. It returns specific error codes
/// for invalid tokens or weak passwords, as the user is already authenticated
/// by possessing the token.
pub async fn password_reset_confirm_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetConfirm>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "password_reset_confirm",
        token_length = req.token.len()
    );

    async move {
        info!("Received password reset confirmation");

        let result =
            process_password_reset_confirm(&app_state, &req.token, &req.new_password).await;

        match result {
            Ok(response) => {
                info!("Password reset confirmation successful.");
                Ok(response)
            }
            Err(e) => {
                error!(error = ?e, "Password reset confirmation failed.");
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
}