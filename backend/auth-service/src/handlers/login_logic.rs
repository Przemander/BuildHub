//! User login business logic.
//!
//! Implements secure authentication with JWT token generation,
//! rate limiting, and comprehensive observability.

use crate::{
    app::AppState,
    config::redis::{check_and_increment_rate_limit, clear_rate_limit_counter},
    db::users::User,
    utils::{
        errors::AuthServiceError,
        hashing::create_rate_limit_key, // Use centralized hashing
        jwt::{generate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
        metrics,
        validators::{validate_email, validate_username},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{info, span, warn, Instrument, Level};

/// Maximum login attempts before rate limiting.
const MAX_LOGIN_ATTEMPTS: u32 = 5;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: usize = 900; // 15 minutes

/// Redis key prefix for login rate limiting.
const RATE_LIMIT_PREFIX: &str = "ratelimit:login:";

/// Process user login request.
pub async fn process_login(
    app_state: &AppState,
    login: &str,
    password: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    let login_type = if login.contains('@') { "email" } else { "username" };
    let span = span!(Level::INFO, "user_login",
        login_type = login_type,
        domain = login.split('@').nth(1).unwrap_or("n/a")
    );

    async move {
        info!("Starting login process with {}", login_type);

        // ===== 1. INPUT VALIDATION =====
        if login.contains('@') {
            validate_email(login)?;
        } else {
            validate_username(login)?;
        }

        if password.is_empty() {
            return Err(AuthServiceError::validation("password", "Password is required"));
        }

        // ===== 2. RATE LIMITING (BEST EFFORT) =====
        if let Some(redis_client) = &app_state.redis_client {
            let rate_key = format!("{}{}", RATE_LIMIT_PREFIX, create_rate_limit_key(login));
            let rate_limit_span = span!(Level::INFO, "rate_limit_check");

            let allowed = async {
                check_and_increment_rate_limit(
                    redis_client,
                    &rate_key,
                    MAX_LOGIN_ATTEMPTS,
                    RATE_LIMIT_WINDOW_SECS,
                )
                .await
            }
            .instrument(rate_limit_span)
            .await
            .unwrap_or_else(|e| {
                warn!("Rate limit check failed, allowing request to proceed. Error: {}", e);
                true // Fail open on Redis error
            });

            if !allowed {
                warn!("Login rate limit exceeded for {}", login_type);
                metrics::security::rate_limit_blocked();
                return Err(AuthServiceError::authentication(
                    "Too many login attempts. Please try again in 15 minutes.",
                ));
            }
        }

        // ===== 3. USER LOOKUP =====
        let db_span = span!(Level::INFO, "db_lookup");
        let user_result = tokio::task::spawn_blocking({
            let pool = app_state.pool.clone();
            let login = login.to_string();
            move || {
                let mut conn = pool.get()?;
                if login.contains('@') {
                    User::find_by_email(&mut conn, &login)
                } else {
                    User::find_by_username(&mut conn, &login)
                }
            }
        })
        .instrument(db_span)
        .await
        .map_err(|e| AuthServiceError::internal(format!("Database task panicked: {}", e)))?;

        let user = match user_result {
            Ok(u) => u,
            Err(_) => {
                // This handles both "not found" and other DB errors.
                // The specific DB metric is already recorded in the `find_by_*` function.
                metrics::auth::login_failure();
                return Err(AuthServiceError::authentication("Invalid credentials."));
            }
        };

        // Use `Span::current()` to record on the active span.
        tracing::Span::current().record("user_id", &user.id.to_string());
        info!(user_id = %user.id, "User found");

        // ===== 4. PASSWORD VERIFICATION =====
        let password_span = span!(Level::INFO, "password_verification");
        let is_valid = async { user.verify_password(password) }
            .instrument(password_span)
            .await?;

        if !is_valid {
            warn!(user_id = %user.id, "Invalid password");
            metrics::auth::login_failure();
            return Err(AuthServiceError::authentication("Invalid credentials."));
        }
        info!(user_id = %user.id, "Password verified");

        // ===== 5. ACCOUNT STATUS CHECK =====
        if !user.is_active {
            warn!(user_id = %user.id, "Login attempt for inactive account");
            metrics::auth::login_failure();
            return Err(AuthServiceError::authentication(
                "Account is not activated. Please check your email.",
            ));
        }

        // ===== 6. GENERATE TOKENS =====
        let token_span = span!(Level::INFO, "token_generation");
        let (access_token, refresh_token) = async {
            let access = generate_token(&user.username, TOKEN_TYPE_ACCESS, None)?;
            let refresh = generate_token(&user.username, TOKEN_TYPE_REFRESH, None)?;
            info!(user_id = %user.id, "Tokens generated successfully");
            Ok::<_, AuthServiceError>((access, refresh))
        }
        .instrument(token_span)
        .await?;

        // ===== 7. CLEAR RATE LIMIT ON SUCCESS (FIRE-AND-FORGET) =====
        if let Some(redis_client) = &app_state.redis_client {
            let rate_key = format!("{}{}", RATE_LIMIT_PREFIX, create_rate_limit_key(login));
            let client_clone = redis_client.clone();
            // Use `async move` to move ownership of `client_clone` and `rate_key` into the task.
            tokio::spawn(async move {
                if let Err(e) = clear_rate_limit_counter(&client_clone, &rate_key).await {
                    warn!("Failed to clear rate limit counter (non-critical): {}", e);
                }
            });
        }

        // ===== 8. SUCCESS RESPONSE =====
        metrics::auth::login_success();
        info!(user_id = %user.id, "Login successful");

        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Login successful",
                "data": {
                    "user": user.to_safe_info(),
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "Bearer"
                    }
                }
            })),
        ))
    }
    .instrument(span)
    .await
}