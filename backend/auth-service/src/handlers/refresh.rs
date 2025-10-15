//! HTTP handler for JWT token refresh endpoint.
//!
//! Provides the REST API interface for token refresh with
//! proper request validation, error handling, and observability.

use crate::{
    app::AppState,
    handlers::refresh_logic::process_token_refresh,
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

/// Request payload for token refresh.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handles POST /auth/refresh requests.
///
/// # Response Codes
/// - `200 OK`: New token pair returned.
/// - `400 Bad Request`: Invalid token type or validation error.
/// - `401 Unauthorized`: Token expired, invalid signature, or revoked.
/// - `500 Internal Server Error`: Server configuration issues.
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "token_refresh",
        token_length = req.token.len()
    );

    async move {
        info!("Received token refresh request");

        if req.token.is_empty() {
            return Err(AuthServiceError::validation("token", "Token is required"));
        }

        let result = process_token_refresh(&app_state, &req.token).await;

        match result {
            Ok(response) => {
                info!("Token refresh completed successfully.");
                Ok(response)
            }
            Err(e) => {
                error!(error = ?e, "Token refresh failed.");
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
}