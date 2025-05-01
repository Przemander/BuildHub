use std::sync::Arc;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    Json as AxumJson,
};
use serde::Deserialize;
use tracing::instrument;

use crate::{
    app::AppState,
    handlers::login_logic::process_login,
    log_info, log_error,
};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub login: String,
    pub password: String,
}

#[instrument(
    level = "info",
    skip(app_state, login_request),
    fields(path = "/auth/login", method = "POST", user = %login_request.login)
)]
pub async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(login_request): Json<LoginRequest>,
) -> impl IntoResponse {
    log_info!("Auth", &format!("Login handler called for {}", login_request.login), "attempt");

    match process_login(&app_state.pool, &login_request).await {
        Ok((status, body)) => {
            log_info!("Auth", &format!("Login success for {}", login_request.login), "success");
            (status, AxumJson(body)).into_response()
        }
        Err(err) => {
            log_error!("Auth", &format!("Login failed for {}: {}", login_request.login, err), "failure");
            err.into_response()
        }
    }
}