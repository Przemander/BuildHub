//! JWT Authentication Middleware
//!
//! Provides secure token validation for protected routes with Redis-backed
//! revocation support and comprehensive observability.

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn, span, Instrument, Level};

use crate::{
    app::AppState,
    metrics,
    utils::{errors::AuthServiceError, jwt},
};

/// JWT authentication middleware for protected routes.
///
/// # Security Features
/// - Token signature verification
/// - Expiration checking
/// - Redis-backed revocation list
/// - Fail-secure design (blocks when Redis unavailable)
///
/// # Usage
/// ```rust
/// router.route("/protected", get(handler))
///     .layer(from_fn_with_state(state, jwt_auth_middleware))
/// ```
pub async fn jwt_auth_middleware<B>(
    State(app_state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    
    // Create span for this middleware execution
    let span = span!(Level::INFO, "jwt_auth",
        path = %path,
        method = %method
    );
    
    async move {
        // Extract Bearer token
        let token = match extract_bearer_token(&req) {
            Some(token) => token,
            None => {
                warn!("Missing or invalid Authorization header");
                metrics::auth::jwt_validation_failure();
                return unauthorized_response("Missing or invalid Authorization header");
            }
        };

        // Check Redis availability (fail-secure for auth)
        let redis_client = match &app_state.redis_client {
            Some(redis) => redis,
            None => {
                warn!("Redis unavailable for authentication - failing secure");
                metrics::external::redis_failure("jwt_auth");
                return service_unavailable_response("Authentication service temporarily unavailable");
            }
        };

        // Validate token
        match jwt::validate_token(token, redis_client).await {
            Ok(claims) => {
                info!(
                    user_id = %claims.sub,
                    token_type = %claims.token_type,
                    "Authentication successful"
                );
                metrics::auth::jwt_validation_success();
                
                // Continue to the protected handler
                next.run(req).await
            }
            Err(err) => {
                let error_type = classify_jwt_error(&err);
                warn!(
                    error_type = %error_type,
                    error = %err,
                    "Authentication failed"
                );
                metrics::auth::jwt_validation_failure();
                
                let message = match error_type {
                    "token_expired" => "Token has expired",
                    "invalid_signature" => "Invalid token signature",
                    "token_revoked" => "Token has been revoked",
                    "malformed_token" => "Invalid token format",
                    _ => "Authentication failed",
                };
                
                unauthorized_response(message)
            }
        }
    }
    .instrument(span)
    .await
}

/// Extracts Bearer token from Authorization header.
fn extract_bearer_token<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| {
            auth.strip_prefix("Bearer ")
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
        })
}

/// Classifies JWT errors for better error messages.
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

/// Creates an unauthorized response.
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

/// Creates a service unavailable response.
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

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::Request,
        middleware::from_fn_with_state,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    use crate::utils::test_utils::state_with_redis;

    async fn protected_handler() -> &'static str {
        "Protected content"
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        metrics::init();
        let state = Arc::new(state_with_redis());
        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let response = app
            .oneshot(Request::builder().uri("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "error");
        assert!(json["message"].as_str().unwrap().contains("Missing"));
    }

    #[tokio::test]
    async fn test_invalid_bearer_format() {
        metrics::init();
        let state = Arc::new(state_with_redis());
        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_valid_token_success() {
        metrics::init();
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
        
        let state = Arc::new(state_with_redis());
        let token = generate_token("test-user", TOKEN_TYPE_ACCESS, None).unwrap();

        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"Protected content");
        
        std::env::remove_var("JWT_SECRET");
    }

    #[tokio::test]
    async fn test_redis_unavailable() {
        metrics::init();
        let mut state = state_with_redis();
        state.redis_client = None;
        let state = Arc::new(state);

        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["message"].as_str().unwrap().contains("temporarily unavailable"));
    }

    #[tokio::test]
    async fn test_invalid_token_signature() {
        metrics::init();
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");
        
        let state = Arc::new(state_with_redis());
        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Bearer invalid.jwt.token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        std::env::remove_var("JWT_SECRET");
    }

    #[test]
    fn test_extract_bearer_token() {
        // Valid token
        let req = Request::builder()
            .header("authorization", "Bearer valid-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("valid-token"));

        // Token with extra spaces
        let req = Request::builder()
            .header("authorization", "Bearer  token-with-spaces  ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("token-with-spaces"));

        // Missing header
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Wrong scheme
        let req = Request::builder()
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Empty token
        let req = Request::builder()
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Just "Bearer"
        let req = Request::builder()
            .header("authorization", "Bearer")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);
    }

    #[test]
    fn test_classify_jwt_error() {
        use crate::utils::errors::AuthServiceError;
        
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