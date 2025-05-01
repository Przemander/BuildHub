//! Token refresh HTTP handler.
//!
//! POST /auth/refresh

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::refresh_logic::process_token_refresh;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handles token refresh requests.
///
/// Validates a refresh token, revokes it, and issues new tokens.
#[instrument(
    level = "info",
    skip(app_state, refresh_request),
    fields(path = "/auth/refresh", method = "POST")
)]
pub async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(refresh_request): Json<TokenRequest>,
) -> impl IntoResponse {
    let (status, body) = process_token_refresh(&app_state, &refresh_request.token).await;
    (status, AxumJson(body)).into_response()
}