//! # Secure Password Reset Flow Implementation
//!
//! This module implements a cryptographically secure, two-step password reset process
//! following OWASP security best practices and industry standards:
//!
//! 1. **Request**: Generate a secure token and send reset email.
//! 2. **Confirm**: Validate token and update password.
//!
//! ## Security Features
//!
//! - Cryptographically secure random tokens (256-bit entropy).
//! - Time-limited tokens (30-minute expiration).
//! - Single-use tokens (invalidated after use).
//! - Anti-enumeration protection (consistent responses).
//! - Password strength validation.
//! - Rate limiting protection against brute-force attacks.
//! - Comprehensive audit logging with PII protection.
//! - Timing attack protection with consistent processing delays.
//!
//! ## Observability
//!
//! - OpenTelemetry hierarchical spans for all operations.
//! - Prometheus metrics with detailed operation tracking.
//! - Privacy-preserving error reporting and tracing.
//!
//! ## Resilience
//!
//! - Graceful handling of infrastructure failures (e.g., Redis).
//! - Token invalidation with best-effort semantics.
//! - Database transaction support for atomic updates.

use crate::{
    app::AppState,
    config::{
        database::get_connection,
        redis::{
            check_and_increment_rate_limit, invalidate_reset_token, store_password_reset_token,
            verify_reset_token,
        },
    },
    db::users::User,
    utils::{
        email::generate_reset_token,
        errors::AuthServiceError,
        hashing::create_rate_limit_key,
        metrics,
        validators::validate_password,
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use std::time::Duration;
use tokio::{task, time::sleep};
use tracing::{error, info, span, warn, Instrument, Level};

/// Redis key prefix for reset tokens.
pub(crate) const REDIS_KEY_PREFIX: &str = "password_reset:token:";

/// Max reset requests per hour per email.
const MAX_RESET_REQUESTS_PER_HOUR: usize = 5;

/// Rate limit key prefix.
const RATE_LIMIT_PREFIX: &str = "ratelimit:password_reset:";

/// Security delay to prevent timing attacks (ms).
const SECURITY_DELAY_MS: u64 = 500;

/// Processes a user's request to reset their password.
///
/// This function orchestrates the first step of the password reset flow. It is designed
/// with a security-first approach, ensuring it does not leak any information about
/// whether an email address exists in the system.
///
/// # Flow
/// 1. **Configuration Check**: Verifies that the Redis client is available.
/// 2. **Rate Limiting**: Checks if the request is within the allowed rate limits (best-effort).
/// 3. **User Lookup**: Looks for the user in the database. This step is wrapped in `spawn_blocking`
///    to avoid blocking the async runtime. It never fails outright for a non-existent user.
/// 4. **Token Generation**: If the user exists and rate limits are not exceeded, a secure token is
///    generated and stored in Redis.
/// 5. **Email Dispatch**: A background task is spawned to send the reset email. The main flow
///    does not wait for this to complete ("fire-and-forget").
/// 6. **Consistent Response**: Always returns a `200 OK` success response with a generic message,
///    regardless of the internal outcome, to prevent user enumeration attacks.
pub async fn process_password_reset_request(
    app_state: &AppState,
    email: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Create a root span for the entire operation for observability.
    let span = span!(Level::INFO, "password_reset_request",
        email_domain = email.split('@').nth(1).unwrap_or("unknown")
    );

    async move {
        info!("Starting password reset request");

        // ===== 1. CONFIGURATION CHECK =====
        // Fail fast if Redis, which is required for token storage, is not configured.
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::password_reset_failure();
            AuthServiceError::configuration("Redis required for password reset")
        })?;

        // ===== 2. RATE LIMITING (BEST-EFFORT) =====
        // Check rate limits to prevent abuse. This is a "best-effort" check; if Redis
        // fails here, we proceed with the request but log a warning.
        let rate_key = format!("{}{}", RATE_LIMIT_PREFIX, create_rate_limit_key(email));

        // Use the centralized, generic rate limit function from the redis module.
        let should_send = match check_and_increment_rate_limit(
            redis_client,
            &rate_key,
            MAX_RESET_REQUESTS_PER_HOUR as u32,
            3600,
        )
        .await
        {
            Ok(allowed) => allowed,
            Err(e) => {
                warn!(
                    "Rate limit check failed, allowing request to proceed. Error: {}",
                    e
                );
                true // Fail open on Redis error
            }
        };

        if !should_send {
            info!("Rate limit exceeded for email");
            // Do not reveal rate limiting to the user. Instead, introduce a delay
            // to make the response time consistent with a successful path.
            sleep(Duration::from_millis(SECURITY_DELAY_MS)).await;
        }

        // ===== 3. USER LOOKUP =====
        // This synchronous database operation is offloaded to a blocking thread
        // to prevent it from stalling the async runtime.
        let db_span = span!(Level::INFO, "db_lookup");
        let pool = app_state.pool.clone();
        let email_owned = email.to_string();

        let user_opt = task::spawn_blocking(move || {
            let mut conn = get_connection(&pool)?;

            // We deliberately handle a "not found" error as a successful outcome
            // returning `None`, to prevent user enumeration.
            match User::find_by_email(&mut conn, &email_owned) {
                Ok(user) => {
                    info!("User found for reset request");
                    Ok::<Option<User>, AuthServiceError>(Some(user))
                }
                Err(_) => {
                    // Do not log error details for security.
                    info!("User not found for reset request");
                    Ok::<Option<User>, AuthServiceError>(None)
                }
            }
        })
        .instrument(db_span)
        .await
        // The double `??` handles two potential layers of errors:
        // 1. A `JoinError` if the blocking task panics.
        // 2. An `AuthServiceError` from the business logic inside the task.
        .map_err(|e| {
            error!("Database task panicked: {}", e);
            AuthServiceError::internal("Database task failed")
        })??;

        // ===== 4. GENERATE & STORE TOKEN =====
        if let Some(user) = user_opt {
            // Only proceed if the user was found AND we are not rate-limited.
            if should_send {
                let token_span = span!(Level::INFO, "token_generation");
                let token_result = async {
                    // Generate a cryptographically secure token using the centralized function.
                    let token = generate_reset_token();
                    info!("Generated secure reset token");

                    // Use a dedicated, reusable function to store the token in Redis.
                    store_password_reset_token(redis_client, &user.email, &token)
                        .await
                        .map_err(|e| {
                            error!("Failed to store reset token: {}", e);
                            AuthServiceError::internal("Failed to store reset token")
                        })?;

                    Ok::<_, AuthServiceError>(token)
                }
                .instrument(token_span)
                .await;

                // ===== 5. SEND EMAIL (ASYNC) =====
                if let Ok(token) = token_result {
                    // Spawn a background task to send the email. The main request flow
                    // does not wait for this to complete.
                    spawn_reset_email(app_state.clone(), user.email.clone(), token);
                }
            }
        } else {
            // If the user was not found, introduce an artificial delay to mitigate timing attacks.
            sleep(Duration::from_millis(SECURITY_DELAY_MS)).await;
        }

        // ===== 6. SUCCESS RESPONSE (ALWAYS) =====
        // Always return a generic success message to prevent leaking information.
        metrics::auth::password_reset_request();
        info!("Password reset request completed");

        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "If an account with that email exists, a password reset link has been sent."
            })),
        ))
    }
    .instrument(span)
    .await
}

/// Processes the confirmation step of a password reset.
///
/// # Flow
/// 1. **Configuration Check**: Verifies Redis availability.
/// 2. **Token Validation**: Validates the reset token against Redis.
/// 3. **Password Validation**: Ensures the new password meets security requirements.
/// 4. **Database Update**: Updates the user's password in the database.
/// 5. **Token Invalidation**: Removes the token from Redis to prevent reuse (best-effort).
/// 6. **Success Response**: Confirms successful password change.
pub async fn process_password_reset_confirm(
    app_state: &AppState,
    token: &str,
    new_password: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Early validation for obviously invalid tokens.
    if token.trim().is_empty() || token.len() < 16 {
        return Err(AuthServiceError::validation("token", "Invalid reset token"));
    }

    let span = span!(Level::INFO, "password_reset_confirm", token_length = token.len());

    async move {
        info!("Starting password reset confirmation");

        // ===== 1. CONFIGURATION CHECK =====
        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client not available - service misconfigured");
            metrics::auth::password_reset_failure();
            AuthServiceError::configuration("Redis required for password reset")
        })?;

        // ===== 2. TOKEN VALIDATION =====
        let validation_span = span!(Level::INFO, "token_validation");
        let email = async {
            verify_reset_token(redis_client, token).await.map_err(|e| {
                warn!("Invalid reset token: {}", e);
                metrics::auth::password_reset_failure();
                AuthServiceError::validation("token", "Invalid or expired reset token")
            })
        }
        .instrument(validation_span)
        .await?;

        info!("Token validated successfully");

        // ===== 3. PASSWORD VALIDATION =====
        validate_password(new_password).map_err(|e| {
            warn!("Password validation failed: {}", e);
            metrics::auth::password_reset_failure();
            AuthServiceError::validation("new_password", "Password does not meet requirements")
        })?;
        info!("Password validation passed");

        // ===== 4. UPDATE PASSWORD =====
        let update_span = span!(Level::INFO, "password_update");
        let pool = app_state.pool.clone();
        let email_owned = email.to_string();
        let password_owned = new_password.to_string();

        let user_id = task::spawn_blocking(move || {
            let mut conn = get_connection(&pool)?;

            // Find user
            let mut user = User::find_by_email(&mut conn, &email_owned).map_err(|e| {
                error!("User not found for valid token: {}", e);
                metrics::auth::password_reset_failure();
                AuthServiceError::validation("token", "Invalid reset token")
            })?;

            // Check account status
            if !user.is_active {
                warn!("Password reset attempted for inactive account");
                metrics::auth::password_reset_failure();
                return Err(AuthServiceError::validation(
                    "account",
                    "This account is inactive and cannot be reset",
                ));
            }

            // Update password
            user.set_password_and_update(&mut conn, &password_owned)
                .map_err(|e| {
                    error!("Failed to update password: {}", e);
                    metrics::auth::password_reset_failure();
                    AuthServiceError::database("Failed to update password")
                })?;

            info!(user_id = %user.id, "Password updated successfully");
            Ok(user.id)
        })
        .instrument(update_span)
        .await
        .map_err(|e| {
            error!("Database task panicked: {}", e);
            AuthServiceError::internal("Database task failed")
        })??;

        // ===== 5. INVALIDATE TOKEN (BEST EFFORT) =====
        let invalidate_span = span!(Level::INFO, "token_invalidation");
        async {
            if let Err(e) = invalidate_reset_token(redis_client, token).await {
                warn!("Failed to invalidate token (non-critical): {}", e);
            } else {
                info!("Token invalidated successfully");
            }
        }
        .instrument(invalidate_span)
        .await;

        // ===== 6. SUCCESS RESPONSE =====
        metrics::auth::password_reset_confirm();
        info!(user_id = %user_id, "Password reset completed successfully");

        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "message": "Password has been reset successfully."
            })),
        ))
    }
    .instrument(span)
    .await
}

/// Spawns a "fire-and-forget" background task to send the password reset email.
///
/// This function detaches the email sending process from the main request-response
/// cycle, ensuring the user receives a fast response.
fn spawn_reset_email(app_state: AppState, email: String, token: String) {
    tokio::spawn(async move {
        let span = span!(Level::INFO, "send_reset_email",
            email_domain = email.split('@').nth(1).unwrap_or("unknown")
        );
        let _enter = span.enter();

        if let Some(email_cfg) = app_state.email_config.as_ref() {
            info!("Attempting to send reset email");
            match email_cfg.send_reset_email(&email, &token).await {
                Ok(()) => info!("Background task: Reset email sent successfully"),
                Err(e) => error!("Background task: Failed to send reset email: {}", e),
            }
        } else {
            error!("Background task: Missing email configuration, cannot send email.");
        }
    });
}
