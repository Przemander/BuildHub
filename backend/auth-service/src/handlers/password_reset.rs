//! Password reset endpoints for BuildHub Auth Service.
//!
//! - POST /auth/password-reset/request: Request a password reset link.
//! - POST /auth/password-reset/confirm: Reset password using a token.

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::password_reset_logic::{
    process_password_reset_confirm, process_password_reset_request,
};

#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    pub token: String,
    pub new_password: String,
}

/// Handles password reset link requests.
#[instrument(
    level = "info",
    skip(app_state, req),
    fields(path = "/auth/password-reset/request", method = "POST")
)]
pub async fn password_reset_request_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> impl IntoResponse {
    let (status, body) = process_password_reset_request(&app_state, &req.email).await;
    (status, AxumJson(body)).into_response()
}

/// Handles password reset confirmations.
#[instrument(
    level = "info",
    skip(app_state, req),
    fields(path = "/auth/password-reset/confirm", method = "POST")
)]
pub async fn password_reset_confirm_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetConfirm>,
) -> impl IntoResponse {
    let (status, body) = process_password_reset_confirm(&app_state, &req.token, &req.new_password).await;
    (status, AxumJson(body)).into_response()
}