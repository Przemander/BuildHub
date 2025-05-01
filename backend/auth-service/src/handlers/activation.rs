//! Account activation HTTP handler.
//!
//! GET /auth/activate?code=<activation_code>

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use serde::Deserialize;
use tracing::instrument;

use crate::app::AppState;
use crate::handlers::activation_logic::{process_activation, ActivationLogicResult};

#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    pub code: String,
}

/// Handles account activation requests.
///
/// Renders an HTML page with the activation result.
#[instrument(
    level = "info",
    skip(app_state),
    fields(path = "/auth/activate", method = "GET")
)]
pub async fn activate_account_handler(
    Query(params): Query<ActivationParams>,
    State(app_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match process_activation(&app_state, &params.code).await {
        ActivationLogicResult::Success => Html(render_page(
            "Account Activated",
            "Your account has been successfully activated.",
        ))
        .into_response(),
        ActivationLogicResult::AlreadyActive => Html(render_page(
            "Already Activated",
            "Your account is already active.",
        ))
        .into_response(),
        ActivationLogicResult::InvalidOrExpired => Html(render_page(
            "Invalid Activation Link",
            "The activation link is invalid or has expired.",
        ))
        .into_response(),
        ActivationLogicResult::NotFound => Html(render_page(
            "Account Not Found",
            "We couldn't find an account for this activation link.",
        ))
        .into_response(),
        ActivationLogicResult::ServiceUnavailable => Html(render_page(
            "Service Unavailable",
            "Redis client not configured",
        ))
        .into_response(),
        ActivationLogicResult::DatabaseUnavailable => Html(render_page(
            "Activation Failed",
            "Database unavailable.",
        ))
        .into_response(),
        ActivationLogicResult::ActivationFailed => Html(render_page(
            "Activation Failed",
            "Could not activate your account.",
        ))
        .into_response(),
    }
}

/// Renders a simple HTML page with a title and message.
fn render_page(title: &str, message: &str) -> String {
    format!(
        "<!DOCTYPE html>
<html lang=\"en\">
  <head><meta charset=\"utf-8\"><title>{}</title></head>
  <body>
    <h1>{}</h1>
    <p>{}</p>
  </body>
</html>",
        title, title, message
    )
}