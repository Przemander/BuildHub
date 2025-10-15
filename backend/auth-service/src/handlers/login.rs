//! User login HTTP handler.
//!
//! Provides the REST API interface for user authentication with
//! proper request validation, error handling, and observability.

use crate::{
    app::AppState,
    handlers::login_logic::process_login,
    utils::errors::AuthServiceError,
};
use axum::{extract::State, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, span, Instrument, Level};

/// Login request payload.
/// Accepts "login", "username", or "email" as the login identifier.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(alias = "email", alias = "username")]
    pub login: String,
    pub password: String,
}

/// Handles POST /auth/login requests.
///
/// # Response Codes
/// - `200 OK`: Login successful.
/// - `400 Bad Request`: Input validation failed (e.g., invalid email format).
/// - `401 Unauthorized`: Invalid credentials or inactive account.
/// - `422 Unprocessable Entity`: Missing fields in the request body.
/// - `500 Internal Server Error`: An unexpected server-side error occurred.
pub async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthServiceError> {
    let span = span!(Level::INFO, "user_login",
        login_domain = req.login.split('@').nth(1).unwrap_or("n/a")
    );

    async move {
        info!("Received login request");

        let result = process_login(&app_state, &req.login, &req.password).await;

        match result {
            Ok(response) => {
                info!("Login process completed successfully.");
                Ok(response)
            }
            Err(e) => {
                error!(error = ?e, "Login process failed.");
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
}