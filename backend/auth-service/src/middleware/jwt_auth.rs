//! JWT Authentication Middleware
//!
//! Provides secure token validation for protected routes. After successful
//! validation, it injects the user's claims into the request extensions,
//! making them available to downstream handlers.

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, span, warn, Instrument, Level};

use crate::{
    app::AppState,
    utils::{
        errors::AuthServiceError,
        jwt::{self},
        metrics,
    },
};

/// JWT authentication middleware for protected routes.
///
/// # Security Features
/// - Verifies token signature and expiration.
/// - Checks against a Redis-backed revocation list.
/// - Implements a "fail-secure" design (blocks access if Redis is unavailable).
/// - Injects `TokenClaims` into request extensions on success.
pub async fn jwt_auth_middleware<B>(
    State(state): State<Arc<AppState>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    let span = span!(Level::INFO, "jwt_auth", path = %path, method = %method);

    async move {
        let token = match extract_bearer_token(&req) {
            Some(token) => token,
            None => {
                warn!("Missing or invalid Authorization header");
                metrics::auth::jwt_validation_failure();
                return Err(unauthorized_response(
                    "Missing or invalid Authorization header",
                ));
            }
        };

        let redis_client = match &state.redis_client {
            Some(redis) => redis,
            None => {
                error!("Redis unavailable for authentication - failing secure");
                metrics::external::redis_failure("jwt_auth_check");
                return Err(service_unavailable_response(
                    "Authentication service temporarily unavailable",
                ));
            }
        };

        match jwt::validate_token(token, redis_client).await {
            Ok(claims) => {
                info!(
                    user_id = %claims.sub,
                    token_type = %claims.token_type,
                    "Authentication successful"
                );
                metrics::auth::jwt_validation_success();

                req.extensions_mut().insert(claims);

                Ok(next.run(req).await)
            }
            Err(err) => {
                let error_type = classify_jwt_error(&err);
                warn!(error_type = %error_type, error = %err, "Authentication failed");
                metrics::auth::jwt_validation_failure();

                let message = match error_type {
                    "token_expired" => "Token has expired",
                    "invalid_signature" => "Invalid token signature",
                    "token_revoked" => "Token has been revoked",
                    "malformed_token" => "Invalid token format",
                    _ => "Authentication failed",
                };

                Err(unauthorized_response(message))
            }
        }
    }
    .instrument(span)
    .await
    .or_else(|res| Ok(res))
}

/// Extracts Bearer token from the `Authorization` header.
fn extract_bearer_token<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer ").map(str::trim))
        .filter(|t| !t.is_empty())
}

/// Classifies JWT errors for better observability and client-facing messages.
fn classify_jwt_error(error: &AuthServiceError) -> &'static str {
    let msg = error.to_string().to_lowercase();

    if msg.contains("expired") {
        "token_expired"
    } else if msg.contains("signature") || msg.contains("verify") {
        "invalid_signature"
    } else if msg.contains("revoked") || msg.contains("blocked") {
        "token_revoked"
    } else if msg.contains("format") || msg.contains("decode") || msg.contains("malformed") {
        "malformed_token"
    } else {
        "validation_error"
    }
}

/// Creates a `401 Unauthorized` response.
fn unauthorized_response(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "status": "error",
            "message": message,
            "code": "UNAUTHORIZED"
        })),
    )
        .into_response()
}

/// Creates a `503 Service Unavailable` response.
fn service_unavailable_response(message: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "status": "error",
            "message": message,
            "code": "SERVICE_UNAVAILABLE"
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn test_extract_bearer_token() {
        let req = Request::builder()
            .header("authorization", "Bearer valid-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("valid-token"));

        let req = Request::builder()
            .header("authorization", "Bearer  token-with-spaces  ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("token-with-spaces"));

        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        let req = Request::builder()
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        let req = Request::builder()
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        let req = Request::builder()
            .header("authorization", "Bearer")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);
    }

    #[test]
    fn test_classify_jwt_error() {
        let err = AuthServiceError::validation("token", "Token has expired");
        assert_eq!(classify_jwt_error(&err), "token_expired");

        let err = AuthServiceError::validation("token", "Invalid signature");
        assert_eq!(classify_jwt_error(&err), "invalid_signature");

        let err = AuthServiceError::validation("token", "Token revoked");
        assert_eq!(classify_jwt_error(&err), "token_revoked");

        let err = AuthServiceError::validation("token", "Malformed token");
        assert_eq!(classify_jwt_error(&err), "malformed_token");

        let err = AuthServiceError::validation("token", "Unknown error");
        assert_eq!(classify_jwt_error(&err), "validation_error");
    }
}