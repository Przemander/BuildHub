//! User logout HTTP handler.
//!
//! POST /auth/logout

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::logout_logic::process_logout;

/// Request body for logout.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

/// Handles user logout requests.
///
/// Invalidates a JWT by adding it to the revocation list in Redis.
#[instrument(
    level = "info",
    skip(app_state, logout_request),
    fields(path = "/auth/logout", method = "POST")
)]
pub async fn logout_handler(
    State(app_state): State<Arc<AppState>>,
    Json(logout_request): Json<TokenRequest>,
) -> impl IntoResponse {
    let (status, body) = process_logout(&app_state, &logout_request.token).await;
    (status, AxumJson(body)).into_response()
}