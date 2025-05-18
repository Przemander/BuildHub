//! JWT authentication middleware for BuildHub.
//!
//! This middleware validates JWT tokens on protected routes using the shared JWT utility functions.
//! It checks for token presence, validity, and revocation (via Redis blocklist).
//! On failure, it returns a 401 Unauthorized response and logs the event.

use crate::app::AppState;
use crate::utils::errors::ApiError;
use crate::utils::jwt;
use crate::{log_error, log_info, log_warn};
use axum::{extract::State, http::Request, middleware::Next, response::IntoResponse};
use std::sync::Arc;

/// JWT authentication middleware for protected routes.
///
/// # Authentication Flow
/// 1. Extracts the `Authorization: Bearer <token>` header from the request
/// 2. Validates the JWT token's integrity and expiration
/// 3. Checks if the token has been revoked (using Redis blocklist)
/// 4. On success, passes the request to the next handler
/// 5. On failure, returns 401 Unauthorized with details and logs the event
///
/// # Security Features
/// - Proper JWT validation including signature verification
/// - Revocation checking for immediate token invalidation
/// - Comprehensive logging for security audit trails
/// - Graceful error handling with descriptive responses
///
/// # Example Usage
/// ```
/// let app = Router::new()
///     .route("/protected", get(protected_handler))
///     .layer(from_fn_with_state(app_state, jwt_auth_middleware));
/// ```
pub async fn jwt_auth_middleware<B>(
    State(app_state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    // Extract the Authorization header and validate Bearer token format
    let token = match extract_bearer_token(&req) {
        Some(token) => token,
        None => {
            log_warn!("JWTAuth", "Missing or invalid Authorization header", "unauthorized");
            return ApiError::unauthorized("Missing or invalid Authorization header")
                .into_response();
        }
    };

    // Get Redis client for token validation (required for blocklist check)
    let redis_client = match &app_state.redis_client {
        Some(redis) => redis,
        None => {
            log_error!("JWTAuth", "Redis unavailable for token validation", "system_error");
            return ApiError::internal("Redis unavailable for token validation").into_response();
        }
    };

    // Validate the token and handle authentication result
    match jwt::validate_token(token, redis_client).await {
        Ok(claims) => {
            log_info!("JWTAuth", &format!("Token valid for user {}", claims.sub), "success");
            next.run(req).await
        }
        Err(err) => {
            log_warn!(
                "JWTAuth",
                &format!("Invalid or expired token: {}", err),
                "unauthorized"
            );
            ApiError::unauthorized(&format!("Invalid or expired token: {}", err)).into_response()
        }
    }
}

/// Extracts a Bearer token from the Authorization header of a request.
///
/// Returns `None` if:
/// - The header is missing
/// - The header value isn't valid UTF-8
/// - The header doesn't begin with "Bearer "
///
/// Otherwise, returns `Some(token)` with the extracted token string.
fn extract_bearer_token<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|value| {
            if value.starts_with("Bearer ") {
                Some(value.trim_start_matches("Bearer ").trim())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::database::{init_pool, run_migrations};
    use crate::utils::jwt::{self, TOKEN_TYPE_ACCESS};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use chrono::Duration;
    use redis::Client;
    use std::env;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A dummy handler that returns "OK" for testing
    async fn ok_handler() -> &'static str {
        "OK"
    }

    /// Build AppState with optional Redis URL, using in-memory SQLite
    fn make_state(redis_url: Option<&str>) -> Arc<AppState> {
        // Configure test environment
        env::set_var("JWT_SECRET", "test-secret");
        env::set_var("DATABASE_URL", ":memory:");
        
        // Initialize database
        let pool = init_pool();
        run_migrations(&pool).expect("Failed to run migrations on in-memory DB");
        
        // Create AppState with optional Redis client
        let redis_client = redis_url.map(Client::open).transpose().unwrap();
        Arc::new(AppState {
            pool,
            redis_client,
            email_config: None,
        })
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_calls_next() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .unwrap();

        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act
        let req = Request::builder()
            .uri("/")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        
        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(resp.into_response().into_body())
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn malformed_auth_header_returns_401() {
        // Arrange
        let state = make_state(Some("redis://127.0.0.1/"));
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        // Act - Send a request with a malformed Authorization header (missing "Bearer" prefix)
        let req = Request::builder()
            .uri("/")
            .header("authorization", "invalid-format-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn extract_bearer_token_handles_edge_cases() {
        // Case 1: No Authorization header
        let req = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Case 2: Invalid format (not starting with "Bearer ")
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Token abc123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Case 3: Valid Bearer token
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Bearer abc123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("abc123"));

        // Case 4: Bearer token with extra whitespace
        let req = Request::builder()
            .uri("/")
            .header("authorization", "Bearer  abc123  ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("abc123"));
    }
}