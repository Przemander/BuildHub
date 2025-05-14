//! Business logic for token refresh.

use crate::{
    app::AppState,
    utils::jwt::{generate_token, revoke_token, validate_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH},
    utils::metrics::AUTH_REFRESHES,
    log_info, log_error, log_warn,
};
use axum::http::StatusCode;
use serde_json::{json, Value};

/// Processes the token refresh logic: validates, revokes, issues new tokens, logs and increments metrics.
///
/// Returns (StatusCode, JSON body) for the handler to respond.
pub async fn process_token_refresh(
    app_state: &AppState,
    token: &str,
) -> (StatusCode, Value) {
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("Auth", "Missing Redis client", "system_error");
            AUTH_REFRESHES.with_label_values(&["system_error"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Redis unavailable"
                }),
            );
        }
    };

    // 1. Validate the refresh token
    let claims = match validate_token(token, redis_client).await {
        Ok(claims) => claims,
        Err(e) => {
            let msg = e.to_string();
            log_error!("Auth", &format!("Refresh token validation failed: {}", msg), "failure");
            let (status, label, message) = if msg.contains("expired") {
                (StatusCode::UNAUTHORIZED, "expired", "Token has expired")
            } else if msg.contains("revoked") {
                (StatusCode::UNAUTHORIZED, "revoked", "Token has been revoked")
            } else if msg.contains("signature") {
                (StatusCode::UNAUTHORIZED, "invalid_signature", "Invalid token signature")
            } else {
                (StatusCode::UNAUTHORIZED, "invalid", "Invalid token")
            };
            AUTH_REFRESHES.with_label_values(&[label]).inc();
            return (
                status,
                json!({
                    "status": "error",
                    "message": message
                }),
            );
        }
    };

    // 2. Ensure token type is refresh
    if claims.token_type != TOKEN_TYPE_REFRESH {
        log_warn!("Auth", &format!("Wrong token type: {}", claims.token_type), "wrong_type");
        AUTH_REFRESHES.with_label_values(&["wrong_type"]).inc();
        return (
            StatusCode::BAD_REQUEST,
            json!({
                "status": "error",
                "message": "Expected a refresh token"
            }),
        );
    }

    // 3. Generate new access token
    let access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) {
        Ok(token) => token,
        Err(e) => {
            log_error!("Auth", &format!("Access token generation failed: {}", e), "failure");
            AUTH_REFRESHES.with_label_values(&["failure"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Failed to generate access token"
                }),
            );
        }
    };

    // 4. Revoke old refresh token (non-fatal)
    if let Err(e) = revoke_token(token, redis_client).await {
        log_warn!("Auth", &format!("Failed to revoke old refresh token: {}", e), "revoke_failed");
        AUTH_REFRESHES.with_label_values(&["revoke_failed"]).inc();
    }

    // 5. Generate new refresh token
    let refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) {
        Ok(token) => token,
        Err(e) => {
            log_error!("Auth", &format!("Refresh token generation failed: {}", e), "failure");
            AUTH_REFRESHES.with_label_values(&["failure"]).inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "status": "error",
                    "message": "Failed to generate refresh token"
                }),
            );
        }
    };

    log_info!("Auth", "Token refresh successful", "success");
    AUTH_REFRESHES.with_label_values(&["success"]).inc();

    (
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "Tokens refreshed successfully",
            "data": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer"
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::{json, Value};
    use crate::utils::test_utils::{state_with_redis, state_no_redis};

    #[tokio::test]
    async fn missing_redis_returns_500() {
        // state_no_redis() already sets JWT_SECRET internally
        let state = state_no_redis();
        let (status, body) = process_token_refresh(&state, "whatever").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({
            "status": "error",
            "message": "Redis unavailable"
        }));
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let state = state_with_redis();
        let (status, body) = process_token_refresh(&state, "not-a-jwt").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({
            "status": "error",
            "message": "Invalid token"
        }));
    }

    #[tokio::test]
    async fn wrong_token_type_returns_400() {
        let state = state_with_redis();
        // issue an access token instead of a refresh
        let access = generate_token("user1", TOKEN_TYPE_ACCESS, None).unwrap();
        let (status, body) = process_token_refresh(&state, &access).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({
            "status": "error",
            "message": "Expected a refresh token"
        }));
    }

    #[tokio::test]
    #[ignore] // requires real Redis & JWT_SECRET
    async fn successful_refresh_returns_200_and_new_tokens() {
        let state = state_with_redis();
        // issue a real refresh token
        let refresh = generate_token("user42", TOKEN_TYPE_REFRESH, None).unwrap();
        let (status, body) = process_token_refresh(&state, &refresh).await;
        assert_eq!(status, StatusCode::OK);

        let data = body.get("data").unwrap();
        let at = data.get("access_token").and_then(Value::as_str).unwrap();
        let rt = data.get("refresh_token").and_then(Value::as_str).unwrap();
        let tt = data.get("token_type").and_then(Value::as_str).unwrap();
        assert!(!at.is_empty());
        assert!(!rt.is_empty());
        assert_eq!(tt, "Bearer");
    }
}