//! User registration HTTP handler with email activation.

use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::register_logic::process_registration;
use crate::db::users::RegisterData;

/// Handles user registration requests.
///
/// Validates input, creates an inactive user, stores activation code, and sends activation email.
#[instrument(
    level = "info",
    skip(app_state, register_data),
    fields(path = "/auth/register", method = "POST")
)]
pub async fn register_handler(
    State(app_state): State<Arc<AppState>>,
    Json(register_data): Json<RegisterData>,
) -> impl IntoResponse {
    let (status, body) = process_registration(&app_state, register_data).await;
    (status, AxumJson(body)).into_response()
}