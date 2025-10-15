//! HTTP handler for user logout endpoint.
//!
//! Provides the REST API interface for token-based logout with
//! proper request validation, error handling, and observability.

use crate::{
    app::AppState,
    handlers::logout_logic::process_logout,
    utils::errors::AuthServiceError,
};
use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

/// Request payload for logout operations.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handles POST /auth/logout requests.
///
/// # Security
/// - Idempotent operation (safe to call multiple times).
/// - Revokes even invalid tokens (defense in depth).
pub async fn logout_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "user_logout",
        token_length = req.token.len()
    );

    async move {
        info!("Received logout request");

        if req.token.is_empty() {
            return Err(AuthServiceError::validation("token", "Token is required"));
        }

        let result = process_logout(&app_state, &req.token).await;

        match result {
            Ok(response) => {
                info!("Logout process completed successfully.");
                Ok(response)
            }
            Err(e) => {
                error!(error = ?e, "Logout process failed.");
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
}